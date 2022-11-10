/*
 * INET	      An implementation of the TCP/IP protocol suite for the LINUX
 *	      operating system.  INET is implemented using the  BSD Socket
 *	      interface as the means of communication with the user level.
 *
 *	      Definitions for PSP security
 *
 *	      This program is free software; you can redistribute it and/or
 *	      modify it under the terms of the GNU General Public License
 *	      as published by the Free Software Foundation; either version
 *	      2 of the License, or (at your option) any later version.
 */

#include <linux/inetdevice.h>
#include <linux/ipv6.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <net/addrconf.h>
#include <net/psp.h>
#include <net/transp_v6.h>

DEFINE_STATIC_KEY_FALSE(tcp_psp_needed);
EXPORT_SYMBOL(tcp_psp_needed);

/* Translates IP address into a device, for which a reference is taken.
 * Socket lock must be held by caller.
 */
static struct net_device *psp_get_device(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct ipv6_pinfo *np;
	struct net_device *dev;

	if (!sk_fullsock(sk))
		return NULL;

	if (sk->sk_family != AF_INET6)
		return NULL;

	if (sk->sk_bound_dev_if) /* link-local */
		return dev_get_by_index(net, sk->sk_bound_dev_if);

	/* inet_saddr is zero for all-zeros v6 address (IPV6_ADDR_ANY),
	 * and LOOPBACK4_IPV6 for specific address.
	 */
	if (inet->inet_saddr &&
	    inet->inet_saddr != LOOPBACK4_IPV6)
		return NULL;

	np = inet6_sk(sk);
	if (!np)
		return NULL;

	rcu_read_lock_bh();
	dev = ipv6_dev_find(net, &np->saddr, NULL);
	if (dev)
		dev_hold(dev);
	rcu_read_unlock_bh();
	return dev;
}

/* Translates IPv6 address into a device, for which a reference is taken.
 * Socket lock must be held by caller.
 */
static struct net_device *psp_get_device_v6(struct sock *sk,
					    struct in6_addr *saddr)
{
	struct net *net = sock_net(sk);
	struct net_device *dev = NULL;

	if (sk->sk_family != AF_INET6)
		return dev;

	rcu_read_lock_bh();
	dev = ipv6_dev_find(net, saddr, NULL);
	if (dev)
		dev_hold(dev);
	rcu_read_unlock_bh();

	return dev;
}

/* For a connected socket, returns the device used to reach the peer socket. */
static struct net_device *psp_get_peer_device(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	const struct dst_entry *dst;

	if (!inet->inet_dport ||
	    ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)))
		return NULL;

	dst = __sk_dst_get(sk);
	return dst ? dst->dev : NULL;
}

/* Simple sanity check on a device to ensure it exists and supports PSP. */
int psp_check_device(const struct net_device *dev)
{
	if (!dev)
		return -ENODEV;

	if (!(dev->features & NETIF_F_IP_PSP))
		return -EOPNOTSUPP;

	if (!dev->netdev_ops->ndo_get_spi_and_key)
		return -EOPNOTSUPP;

	return 0;
}
EXPORT_SYMBOL(psp_check_device);

/* The inverse of psp_get_device() */
static void psp_put_device(struct net_device *dev)
{
	if (dev)
		dev_put(dev);
}

/* Ensures socket is in a valid state to be issued encryption commands,
 * meaning it is either in TCP_CLOSE or already set to encrypt.
 * Socket lock must be held by caller.
 */
static int psp_check_socket(const struct sock *sk)
{
	/* anything goes while closed */
	if (sk->sk_state == TCP_CLOSE)
		return 0;

	/* The following states don't support credential changes:
	 *
	 * LISTEN:    socket options do not apply to them
	 * NEW_SYN_RECV:  applications lack an FD to use
	 * SYN_SENT:  their credentials could be updated but peer likely in
	 *            SYN_RECV
	 * TIME_WAIT: we don't keep Rx credentials and they are too short-lived
	 *            for credential changes to matter
	 */
	if (sk->sk_state == TCP_LISTEN)
		return -EPERM;

	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_NEW_SYN_RECV))
		return -ENOTCONN;

	if (sk->sk_state == TCP_TIME_WAIT)
		return -ESHUTDOWN;

	/* for remaining states only updates of existing credentials allowed */
	return tcp_uses_psp(tcp_sk(sk)) ? 0 : -EISCONN;
}

/* Lookup the real device that implements PSP.
 * Parse through ipvlan, bonding, etc, intermediate layers.
 */
int psp_get_device_path(struct sock *sk, char __user *optval,
			int __user *optlen)
{
	const char path_prefix[] = "/sys";
	const char path_suffix[] = "/psp";
	struct net_device *dev, *dev_held, *lower, *lnext;
	struct list_head *iter;
	struct kobject *kobj;
	char pathstr[200];
	int len, room, ret;
	int i, ulen, depth;

	lock_sock(sk);
	dev = psp_get_device(sk);
	release_sock(sk);
	if (!dev)
		return -ENODEV;

	dev_held = dev;
	ret = psp_check_device(dev);
	if (ret)
		goto err_dev;

	rcu_read_lock();

	depth = dev->lower_level - 1;	/* lowest level is 1 */
	for (i = 0; i < depth; i++) {
		iter = &dev->adj_list.lower;
		lower = netdev_next_lower_dev_rcu(dev, &iter);
		if (!lower) {
			ret = -ENXIO;
			goto err_rcu;
		}

		/* fail if multiple lower devices (e.g., link aggregation),
		 * unless they are ports on the same device
		 * (and thus share the psp master key).
		 */
		while ((lnext = netdev_next_lower_dev_rcu(dev, &iter))) {
			if (lnext->dev.parent != lower->dev.parent) {
				ret = -EXDEV;
				goto err_rcu;
			}
		}
		dev = lower;
	}

	/* move two levels up the path from /sys/../$device/net/ethN */
	kobj = &dev->dev.kobj;
	if (!kobj->parent || !kobj->parent->parent) {
		ret = -EIO;
		goto err_rcu;
	}
	kobj = kobj->parent->parent;

	/* prefix "/sys" */
	len = strscpy(pathstr, path_prefix, sizeof(pathstr));

	/* copy sysfs path to device */
	room = sizeof(pathstr) - len - sizeof(path_suffix);
	ret = kernfs_path(kobj->sd, pathstr + len, room);
	if (ret >= room) {
		ret = -ENOSPC;
		goto err_rcu;
	}
	len += ret;

	/* append "/psp" */
	ret = strscpy(pathstr + len, path_suffix, sizeof(pathstr) - len);
	if (ret != sizeof(path_suffix) - 1) {
		ret = -ENOSPC;
		goto err_rcu;
	}
	len += ret + 1;		/* include final \0 */

	rcu_read_unlock();

	dev_put(dev_held);

	/* copy path to optval */
	if (get_user(ulen, optlen))
		return -EFAULT;
	if (ulen < len)
		return -ENOMEM;
	if (copy_to_user(optval, pathstr, len))
		return -EFAULT;

	/* copy path length to optlen */
	if (put_user(len, optlen))
		return -EFAULT;

	return 0;

err_rcu:
	rcu_read_unlock();
err_dev:
	dev_put(dev_held);
	return ret;
}
EXPORT_SYMBOL_GPL(psp_get_device_path);

/* Fetches a fresh spi tuple from the driver (a potentially lengthy
 * operation). Socket lock must NOT be held by caller.
 */
static int psp_get_tuple(struct sock *sk, struct psp_spi_tuple *tuple,
			 struct net_device *held_dev)
{
	struct net_device *dev = NULL;
	int err;

	lock_sock(sk);

	dev = held_dev ? : psp_get_device(sk);

	err = psp_check_device(dev);

	release_sock(sk);

	if (!err) {
		err = dev->netdev_ops->ndo_get_spi_and_key(dev, tuple);
		if (err)
			err = -EIO;
		else
			static_branch_enable(&tcp_psp_needed);
	}

	if (!held_dev)
		psp_put_device(dev);

	return err;
}

int __psp_register_key(struct sock *sk, __be32 spi, const struct psp_key *key,
		       struct psp_key_idx *idx, u8 *cred_type,
		       struct net_device *held_dev)
{
	struct net_device *dev = NULL;
	int ret = 0;

	dev = held_dev ? : psp_get_device(sk);

	if (!dev)
		return -ENODEV;

	if (!(dev->features & NETIF_F_IP_PSP)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	*cred_type = KEY_128_RAW;

	if (dev->netdev_ops->ndo_psp_register_key) {
		ret = dev->netdev_ops->ndo_psp_register_key(dev, spi, key, idx);
		if (ret == 0)
			*cred_type = KEY_128_INDEX;
		/* skip psp_register_key if lower/phy dev does not support it */
		if (ret == -EOPNOTSUPP)
			ret = 0;
	}

out:
	if (!held_dev)
		dev_put(dev);

	return ret;
}
EXPORT_SYMBOL_GPL(__psp_register_key);

void __psp_unregister_key(struct sock *sk, struct psp_key_spi *p)
{
	struct net_device *dev = NULL;

	if (!PSP_CREDENTIAL_TYPE_INDEX(p->credential_type))
		return;

	rcu_read_lock();
	dev = dev_get_by_napi_id(p->key_idx.napi_id);
	if (dev)
		dev_hold(dev);
	rcu_read_unlock();
	p->key_idx.napi_id = 0;

	if (!dev) {
		net_warn_ratelimited("psp: unable to unregister key\n");
		return;
	}

	if ((dev->features & NETIF_F_IP_PSP) &&
	    dev->netdev_ops->ndo_psp_unregister_key)
		dev->netdev_ops->ndo_psp_unregister_key(dev, p->key_idx.idx);

	dev_put(dev);
}
EXPORT_SYMBOL_GPL(__psp_unregister_key);

/* Associates a new spi with a socket, remembering the previous spi.
 * Socket lock must be held by caller.
 */
static void psp_bump_spi(struct sock *sk, const struct psp_spi_tuple *tuple)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->psp.rx_prev = tp->psp.rx_curr;
	tp->psp.rx_curr.spi = htonl(tuple->spi);
	tp->psp.rx_curr.gen = tuple->key_generation;
}

/* Return true if the PSP-related sysctls have values that enable PSP in the
 * given namespace.
 */
static bool psp_sysctl_enabled(struct net *net)
{
	return net->ipv4.sysctl_psp_enable_conn;
}

/* Entry point for setsockopt(sockfd, SOL_TCP, TCP_PSP_TX_SPI_KEY, ...)
 * Sets the tx SPI/key in the sock struct. Fail if TCP_PSP_RX_SPI_KEY
 * hasn't been used yet.
 * Since this is a setsockopt(), the socket lock is already held by the caller.
 */
int psp_set_tx_spi_key(struct sock *sk, sockptr_t optval,
		       unsigned int optlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct psp_spi_tuple tuple;
	int err;

	if (optlen != sizeof(tuple))
		return -EINVAL;
	if (copy_from_sockptr(&tuple, optval, optlen))
		return -EFAULT;
	if (!tuple.spi)
		return -EINVAL;

	err = psp_check_socket(sk);
	if (err)
		return err;

	if (!tp->psp.rx_curr.spi)
		return -EINVAL;

	tp->psp.tx_info.key = tuple.key;
	tp->psp.tx_info.spi = htonl(tuple.spi);

	err = psp_register_key(sk, htonl(tuple.spi), &tuple.key,
			       &tp->psp.tx_info.key_idx,
			       &tp->psp.tx_info.credential_type, NULL);
	if (err) {
		memset(&tp->psp, 0, sizeof(tp->psp));
		return err;
	}

	return 0;
}

/* Entry point for getsockopt(sockfd, SOL_TCP, TCP_PSP_RX_SPI_KEY, ...)
 * Gets a fresh spi/key from the driver, stores them in the sock struct,
 * and passes them back to the caller.
 */
int psp_get_rx_spi_key(struct sock *sk, char __user *optval, int __user *optlen)
{
	struct psp_spi_tuple tuple;
	int err, len;

	if (unlikely(!psp_sysctl_enabled(sock_net(sk))))
		return -EINVAL;
	if (get_user(len, optlen))
		return -EFAULT;
	if (len != sizeof(tuple))
		return -EINVAL;

	err = psp_get_tuple(sk, &tuple, NULL);
	if (err)
		return err;

	lock_sock(sk);

	err = psp_check_socket(sk);
	if (err) {
		release_sock(sk);
		return err;
	}

	psp_bump_spi(sk, &tuple);

	release_sock(sk);

	if (copy_to_user(optval, &tuple, len))
		return -EFAULT;

	return 0;
}

/* Entry point for getsockopt(sockfd, SOL_TCP, TCP_PSP_LISTENER, ...)
 * Takes a client key/spi from the caller, gets a spi/key from the driver,
 * associates them with a listening socket, and returns them to the caller.
 * The socket must be in TCP_LISTEN state otherwise an error is returned.
 */
int psp_get_listener(struct sock *sk, char __user *optval, int __user *optlen)
{
	struct psp_spi_tuple rx_tuple;
	struct psp_spi_addr_tuple tx_tuple;
	int err, len;
	struct net_device *held_dev = NULL;

	if (unlikely(!psp_sysctl_enabled(sock_net(sk))))
		return -EINVAL;
	if (get_user(len, optlen))
		return -EFAULT;

	if (len != sizeof(tx_tuple) && len != sizeof(tx_tuple.tuple))
		return -EINVAL;

	if (copy_from_user(&tx_tuple, optval, len))
		return -EFAULT;

	if (!tx_tuple.tuple.spi)
		return -EINVAL;

	/* Get a fresh tuple from the driver; if present, use the user-supplied
	 * local address to help locate the correct driver, and hold it for the
	 * subsequent driver API calls.
	 */
	if (len == sizeof(tx_tuple)) {
		held_dev = psp_get_device_v6(sk, &tx_tuple.saddr);
		if (!held_dev)
			return -EINVAL;
	}

	err = psp_get_tuple(sk, &rx_tuple, held_dev);
	if (err)
		goto out;

	/* Optimistically pass the new tuple up to the caller. */
	if (copy_to_user(optval, &rx_tuple, sizeof(rx_tuple))) {
		err = -EFAULT;
		goto out;
	}

	lock_sock(sk);

	err = sk->sk_state == TCP_LISTEN ?
		psp_listen_add(sk, &tx_tuple.tuple, &rx_tuple, held_dev) :
		-EPERM;

	release_sock(sk);
out:
	if (held_dev)
		dev_put(held_dev);

	return err;
}

/* Entry point for setsockopt(sockfd, SOL_TCP, TCP_PSP_LISTENER, ...)
 * Takes a PSP tuple from the caller and attempts to disassociate it from a
 * listening socket by calling psp_lookup_listener() to remove it from the
 * table.
 * The socket must be in TCP_LISTEN state otherwise an error is returned.
 */
int psp_set_listener(struct sock *sk, sockptr_t optval, unsigned int optlen)
{
	struct psp_spi_tuple tuple;
	struct psp_listen_node *pln;

	if (optlen != sizeof(tuple))
		return -EINVAL;
	if (copy_from_sockptr(&tuple, optval, optlen))
		return -EFAULT;
	if (!tuple.spi)
		return -EINVAL;
	if (sk->sk_state != TCP_LISTEN)
		return -EPERM;

	pln = psp_lookup_listener(sk, htonl(tuple.spi), tuple.key_generation);
	if (!pln)
		return -ENOENT;

	psp_listen_unregister_key(sk, pln);
	kfree(pln);
	return 0;
}

/* Entry point for getsockopt(sockfd, SOL_TCP, TCP_PSP_SYN_SPI, ...)
 * Returns the spi and key generation from the locally received SYN packet.
 * The socket may be in any state other than TCP_LISTEN.
 */
int psp_get_syn_spi(struct sock *sk, char __user *optval, int __user *optlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct psp_spi_tuple tuple = {};
	int len;

	if (get_user(len, optlen))
		return -EFAULT;
	if (len != sizeof(tuple))
		return -EINVAL;

	lock_sock(sk);

	if (sk->sk_state == TCP_LISTEN) {
		release_sock(sk);
		return -EPERM;
	}

	if (sk->sk_state == TCP_SYN_SENT) {
		release_sock(sk);
		return -ENOTCONN;
	}

	tuple.spi = ntohl(tp->psp.rx_syn.spi);
	tuple.key_generation = tp->psp.rx_syn.gen;

	release_sock(sk);

	if (copy_to_user(optval, &tuple, len))
		return -EFAULT;

	return 0;
}

int psp_check_peer(struct sock *sk)
{
	struct net_device *dev;
	int val = 0;

	lock_sock(sk);

	dev = psp_get_peer_device(sk);
	if (psp_check_device(dev) == 0 && psp_sysctl_enabled(dev_net(dev)))
		val = 1;

	release_sock(sk);

	return val;
}
