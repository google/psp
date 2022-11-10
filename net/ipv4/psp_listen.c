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

#include <net/psp_defs.h>
#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/refcount.h>
#include <linux/tcp.h>
#include <linux/vmalloc.h>
#include <net/sock_reuseport.h>

#define PSP_HASH_BITS	16

/* Hash table linkage is protected by a single spinlock, as we can't depend on
 * the listener socket lock. If this turns into a bottleneck in practice, we can
 * break up this lock (one lock per bucket or one per 2^N buckets or some such).
 */

struct psp_listen_node {
	struct hlist_node  hash_node;
	struct hlist_node  list_node;
	struct sock       *sock;
	struct psp_key_spi tx_key_spi; /* key/SPI for SYN-ACKs */
	struct psp_spi_gen rx_cred;    /* expected SPI/gen for SYN */
};

struct psp_listen_hash {
	struct rcu_head rcu;
	spinlock_t slock;              /* guards access to hash table */
	refcount_t refcnt;             /* = #socks + #sock_reuseports */
	DECLARE_HASHTABLE(hash, PSP_HASH_BITS);
};

extern spinlock_t reuseport_lock;

/* Return the key/SPI pair of a request_sock or NULL if it doesn't use PSP */
const struct psp_key_spi *psp_reqsk_key_spi(const struct request_sock *req)
{
	const struct psp_listen_node *pln = tcp_rsk(req)->psp.listen_node;

	return pln ? &pln->tx_key_spi : NULL;
}

/* Returns true if an skb's SPI/gen do not match the expected credentials
 * in pln.
 */
bool psp_policy_failure_pln(const struct sk_buff *skb,
			    const struct psp_listen_node *pln)
{
	if (!pln)
		return true;

	return !psp_skb_gen_spi_ok(&skb->psp, &pln->rx_cred);
}

/* Initialize tcp_sock.psp after a passive open given its request_sock */
void psp_oreq_child_init(struct tcp_sock *tp,
			 const struct tcp_request_sock *treq)
{
	const struct psp_listen_node *pln = treq->psp.listen_node;

	memset(&tp->psp, 0, sizeof(tp->psp));
	if (pln) {
		tp->psp.tx_info = pln->tx_key_spi;
		tp->psp.rx_curr = pln->rx_cred;
		tp->psp.rx_syn = pln->rx_cred;
	}
}

/* psp_listen_node: constructor */
static struct psp_listen_node *psp_pln_init(struct sock *sk,
					    const struct psp_spi_tuple *tx,
					    const struct psp_spi_tuple *rx)
{
	struct psp_listen_node *pln;

	pln = kmalloc(sizeof(*pln), GFP_KERNEL);
	if (likely(pln)) {
		INIT_HLIST_NODE(&pln->hash_node);
		INIT_HLIST_NODE(&pln->list_node);
		pln->sock = sk;
		pln->tx_key_spi.key = tx->key;
		pln->tx_key_spi.spi = htonl(tx->spi);
		pln->rx_cred.spi = htonl(rx->spi);
		pln->rx_cred.gen = rx->key_generation;
	}
	return pln;
}

/* psp_listen_hash: constructor */
static struct psp_listen_hash *psp_plh_init(void)
{
	struct psp_listen_hash *plh;

	plh = vmalloc(sizeof(*plh));
	if (likely(plh)) {
		hash_init(plh->hash);
		spin_lock_init(&plh->slock);
		refcount_set(&plh->refcnt, 1);
	}
	return plh;
}

/* RCU callback to free a psp_listen_hash */
static void psp_plh_free_rcu(struct rcu_head *head)
{
	vfree(container_of(head, struct psp_listen_hash, rcu));
}

/* psp_listen_hash: inc the refcnt */
static void psp_listen_hash_hold(struct psp_listen_hash *plh)
{
	if (likely(plh))
		refcount_inc(&plh->refcnt);
}

/* psp_listen_hash: dec the refcnt, RCU-free if 0 */
static void psp_listen_hash_put(struct psp_listen_hash *plh)
{
	if (likely(plh) && refcount_dec_and_test(&plh->refcnt))
		call_rcu(&plh->rcu, psp_plh_free_rcu);
}

void psp_listen_unregister_key(struct sock *sk, struct psp_listen_node *pln)
{
	psp_unregister_key(sk, &pln->tx_key_spi);
}

/* Free outstanding PSP credentials registered with a listening socket.
 * Called with the socket locked but while there may be active credential
 * lookups.
 */
static void psp_listen_free_credentials(struct tcp_sock *tp,
					struct psp_listen_hash *plh)
{
	struct psp_listen_node *pln;
	struct hlist_node *tmp;

	if (!tp->psp.num_credentials)
		return;

	/* First phase: remove credentials from the hash table.
	 * There may be active hash lookups, the spin lock protects us.
	 */
	spin_lock_bh(&plh->slock);
	hlist_for_each_entry(pln, &tp->psp.list, list_node) {
		hash_del(&pln->hash_node);
	}
	spin_unlock_bh(&plh->slock);

	/* Second phase: the credential list is now isolated, iterate & free */
	hlist_for_each_entry_safe(pln, tmp, &tp->psp.list, list_node) {
		hlist_del(&pln->list_node);
		psp_listen_unregister_key((struct sock *)tp, pln);
		kfree(pln);
		cond_resched();
	}
	tp->psp.num_credentials = 0;
}

/* Free the PSP state of a closing TCP_LISTEN socket.
 * Called with the socket locked.
 */
void psp_listen_stop(struct sock *sk)
{
	struct psp_listen_hash *plh;
	struct tcp_sock *tp;

	/* We are called from INET code, sk need not be TCP. */
	if (sk->sk_type != SOCK_STREAM)
		return;

	tp = tcp_sk(sk);
	plh = rcu_dereference_protected(tp->psp.plh, lockdep_sock_is_held(sk));
	rcu_assign_pointer(tp->psp.plh, NULL);
	psp_listen_free_credentials(tp, plh);
	psp_listen_hash_put(plh);
}

/* Frees the PSP state of a reuseport group. Called from an RCU callback. */
void psp_reuseport_free(struct sock_reuseport *reuse)
{
	psp_listen_hash_put(rcu_access_pointer(reuse->psp.listen_hash));
}

/* Add the supplied PSP credential table to a reuse group if the group doesn't
 * already have one. The group's table after the potential addition is returned.
 * @plh may be NULL.
 */
static struct psp_listen_hash *
reuseport_attach_psp_cred_table(struct sock *sk, struct psp_listen_hash *plh)
{
	struct sock_reuseport *reuse;

	spin_lock_bh(&reuseport_lock);
	reuse = rcu_dereference_protected(sk->sk_reuseport_cb,
					  lockdep_is_held(&reuseport_lock));
	if (!rcu_access_pointer(reuse->psp.listen_hash))
		rcu_assign_pointer(reuse->psp.listen_hash, plh);
	plh = rcu_dereference_protected(reuse->psp.listen_hash,
					lockdep_is_held(&reuseport_lock));
	spin_unlock_bh(&reuseport_lock);
	return plh;
}

/* Obtain a psp_listen_hash for sk. It's either a newly allocated one or the
 * existing structure from sk's reuse group, if it has one.
 */
static struct psp_listen_hash *psp_plh_get(struct sock *sk)
{
	struct psp_listen_hash *plh, *reuse_plh;

	plh = psp_plh_init();  /* NULL OK */
	if (!rcu_access_pointer(sk->sk_reuseport_cb))
		return plh;

	reuse_plh = reuseport_attach_psp_cred_table(sk, plh);
	if (reuse_plh != plh)       /* use the reuse group's existing table */
		vfree(plh);
	psp_listen_hash_hold(reuse_plh);
	return reuse_plh;
}

/* Lookup a SPI/gen pair for a reuseport share group and return its sock.
 * The corresponding psp_listen_node is not removed from the hash table.
 * Called under RCU.
 */
struct sock *psp_lookup_reuseport(struct sock_reuseport *reuse,
				  const struct sk_buff *skb)
{
	struct psp_listen_hash *plh;
	struct psp_listen_node *pln;
	struct sock *sk = NULL;

	plh = rcu_dereference(reuse->psp.listen_hash);
	if (!plh)
		return NULL;

	spin_lock_bh(&plh->slock);
	hash_for_each_possible(plh->hash, pln, hash_node,
			       (__force u32) skb->psp.spi) {
		if (likely(psp_skb_gen_spi_ok(&skb->psp, &pln->rx_cred))) {
			sk = pln->sock;
			break;
		}
	}
	spin_unlock_bh(&plh->slock);
	return sk;
}

/* Lookup a SPI/gen pair for a single listening socket, remove it from the
 * hashtable, and return the corresponding psp_listen_node.
 */
struct psp_listen_node *psp_lookup_listener(struct sock *sk, __be32 spi,
					    u32 gen)
{
	struct psp_listen_node *pln = NULL;
	struct tcp_sock *tp = tcp_sk(sk);
	struct psp_listen_hash *plh;

	rcu_read_lock();

	plh = rcu_dereference(tp->psp.plh);
	if (!plh)
		goto done;

	spin_lock_bh(&plh->slock);

	hash_for_each_possible(plh->hash, pln, hash_node, (__force u32) spi) {
		if (unlikely(pln->rx_cred.spi != spi ||
			     gen - pln->rx_cred.gen > 1))
			continue;
		hash_del(&pln->hash_node);
		hlist_del(&pln->list_node);
		tp->psp.num_credentials--;
		break;
	}

	spin_unlock_bh(&plh->slock);
done:
	rcu_read_unlock();
	return pln;
}

/* Register client credentials with a listening socket.
 * Socket lock must be held by caller.
 */
int psp_listen_add(struct sock *sk, const struct psp_spi_tuple *tx,
		   const struct psp_spi_tuple *rx, struct net_device *dev)
{
	struct psp_listen_node *pln, *tmp;
	struct tcp_sock *tp = tcp_sk(sk);
	struct psp_listen_hash *plh;
	int err = -ENOMEM;

	/* Note that psp.num_credentials and psp.plh are always valid and
	 * 0-initialized.
	 */

	if (inet_csk_reqsk_queue_len(sk) + tp->psp.num_credentials >=
	    sk->sk_max_ack_backlog) {
		err = -ENOSPC;
		goto done;
	}

	plh = rcu_dereference_protected(tp->psp.plh, lockdep_sock_is_held(sk));
	if (unlikely(!plh)) {
		plh = psp_plh_get(sk);
		if (!plh)
			goto done;

		rcu_assign_pointer(tp->psp.plh, plh);
		INIT_HLIST_HEAD(&tp->psp.list);
	}

	pln = psp_pln_init(sk, tx, rx);
	if (unlikely(!pln))
		goto done;

	err = psp_register_key(sk, pln->tx_key_spi.spi, &tx->key,
			       &pln->tx_key_spi.key_idx,
			       &pln->tx_key_spi.credential_type, dev);
	if (err) {
		kfree(pln);
		goto done;
	}

	spin_lock_bh(&plh->slock);
	hash_for_each_possible(plh->hash, tmp, hash_node,
			       (__force u32) pln->rx_cred.spi) {
		if (unlikely(tmp->rx_cred.spi == pln->rx_cred.spi &&
			     tmp->rx_cred.gen == pln->rx_cred.gen)) {
			kfree(pln);
			err = -EEXIST;
			goto unlock;
		}
	}

	hash_add(plh->hash, &pln->hash_node, (__force u32) pln->rx_cred.spi);
	hlist_add_head(&pln->list_node, &tp->psp.list);
	tp->psp.num_credentials++;
unlock:
	spin_unlock_bh(&plh->slock);
done:
	return err;
}
