/*
 * INET	 An implementation of the TCP/IP protocol suite for the LINUX
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
#ifndef _NET_PSP_DEFS_H
#define _NET_PSP_DEFS_H

/* This header sits between the user space psp.h and the kernel space psp.h.
 * It contains PSP kernel definitions which do not depend upon any deeper parts
 * of the kernel, preventing the #include loops which would otherwise result
 * from having just a single PSP header.
 */

#ifdef CONFIG_INET_PSP
#include <uapi/linux/psp.h>
#endif
#include <linux/compiler.h>
#include <linux/netdev_features.h>
#include <linux/sockptr.h>
#include <linux/types.h>

#define PSP_ICV_LENGTH 16

/* The UDP dport used for PSP encapsulation. Note that in the case of PSP
 * offload HW may have a hardcoded value for this port.
 * Do not change this value.
 */
#define PSP_UDP_DPORT 1000
#define PSP_SRC_PORT_MIN 0
#define PSP_SRC_PORT_MAX 65535

struct net;
struct net_device;
struct net_offload;
struct psp_listen_hash;
struct psp_listen_node;
struct request_sock;
struct sk_buff;
struct sock;
struct sock_reuseport;
struct tcp_sock;
struct tcp_request_sock;

/* PSP fields needed by the sk_buff struct:
 *
 * @spi: used to indicate need for encryption of packet being transmitted, and
 *	 security index validated during reception of an encrypted packet.
 * @key: encryption key to be used when transmitting
 * @gen: on received packets, holds the most recent PSP key generation number
 *	 from the device.
 * @hdr_len: Total length of headers up to and including the inner L4 header.
 *           Set only for Rx packets.
 */
struct psp_skb {
#ifdef CONFIG_INET_PSP
	__be32 spi;
	union {
		struct psp_key key;              /* Tx only */
		u32 key_idx;
		struct {                         /* Rx only */
			psp_generation gen;
			unsigned int   hdr_len;
		};
	};
#endif
};

/* A special value assigned to psp_skb.spi to indicate the skb contains a
 * PSP-encapsulated packet. This value is used to determine the protocol value
 * for L3 headers. Note that 0x80000000 is not a valid SPI.
 */
#define PSP_SKB_SPI_SPECIAL htonl(0x80000000)

#ifdef CONFIG_INET_PSP
#define SKB_PSP_SPI(skb) ((skb)->psp.spi)
#else
#define SKB_PSP_SPI(skb) 0
#endif

/* PSP fields needed by the sock_reuseport struct:
 *
 * @listen_hash: All PSP credentials for this reuseport group.
 */
struct psp_reuseport {
#ifdef CONFIG_INET_PSP
	struct psp_listen_hash __rcu *listen_hash;
#endif
};

/* A key index for stateful devices: SADB index + napi_id to lookup dev */
struct psp_key_idx {
	u32 idx;
	u32 napi_id;
};

enum {
	KEY_128_RAW = 0,
	KEY_128_INDEX = 1,
};

#define PSP_CREDENTIAL_TYPE_INDEX(cred_type) (cred_type & 1)

/* A key/SPI pair, used to store the Tx key and SPI in the various TCP
 * socket structures.
 */
struct psp_key_spi {
#ifdef CONFIG_INET_PSP
	union {
		struct psp_key key;
		struct psp_key_idx key_idx;
	};
	__be32 spi;
	u8 credential_type;
	u8 __reserved24_0_7;
	u16 __reserved24_8_23;
#endif
};

/* A SPI/generation pair, used to store Rx SPIs and their generations. */
struct psp_spi_gen {
#ifdef CONFIG_INET_PSP
	__be32 spi;
	u32    gen;
#endif
};

/*  PSP Security Payload (PSP) Header
 *
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Next Header  |  Hdr Ext Len  |  Crypt Offset | R |Version|V|1|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Security Parameters Index (SPI)                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                  Initialization Vector (IV)                   +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Virtualization Key (VK) [Optional]             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  Pad to 8*N bytes [if needed]                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct psphdr {
	u8 nh;
	u8 extlen;
	u8 cryptoff;
	u8 flags;
	__be32 spi;
	u64 iv;			/* merged iv/sequence number */
};

/* total length of headers for PSP encapsulation (UDP + PSP) */
#define PSP_ENCAP_HLEN (sizeof(struct udphdr) + sizeof(struct psphdr))

#ifdef CONFIG_INET_PSP
/* Compare an skb's SPI and generation to a target and return true if the skb
 * credentials are acceptable. This is the case if the SPIs match and the skb
 * generation equals the target generation or exceeds it by 1.
 */
static inline bool psp_skb_gen_spi_ok(const struct psp_skb *psp_skb,
				      const struct psp_spi_gen *target)
{
	return psp_skb->spi == target->spi && psp_skb->gen - target->gen <= 1;
}

void psp_listen_stop(struct sock *sk);
void psp_reuseport_free(struct sock_reuseport *reuse);
struct sock *psp_lookup_reuseport(struct sock_reuseport *reuse,
				  const struct sk_buff *skb);
void psp_oreq_child_init(struct tcp_sock *tp,
			 const struct tcp_request_sock *treq);
int psp_listen_add(struct sock *sk, const struct psp_spi_tuple *tx,
		   const struct psp_spi_tuple *rx, struct net_device *held_dev);
struct psp_listen_node *psp_lookup_listener(struct sock *sk, __be32 spi,
					    u32 gen);
bool psp_policy_failure_pln(const struct sk_buff *skb,
			    const struct psp_listen_node *pln);
const struct psp_key_spi *psp_reqsk_key_spi(const struct request_sock *req);
void psp_encapsulate(struct net *net, struct sk_buff *skb, const struct psp_key_spi *key_spi);
int __psp_dev_encapsulate(struct sk_buff *skb);
void psp_finish_encap(struct net *net, struct sk_buff *skb,
		      const struct psp_key_spi *key_spi);
int psp_set_tx_spi_key(struct sock *sk, sockptr_t optval, unsigned int len);
int psp_get_rx_spi_key(struct sock *sk, char __user *optval, int __user *len);
int psp_get_listener(struct sock *sk, char __user *optval, int __user *len);
int psp_set_listener(struct sock *sk, sockptr_t optval, unsigned int len);
int psp_get_syn_spi(struct sock *sk, char __user *optval, int __user *len);
int psp_check_device(const struct net_device *dev);
int psp_check_peer(struct sock *sk);
int psp_get_device_path(struct sock *sk, char __user *optval, int __user *optlen);
struct sk_buff *psp_segment(struct sk_buff *skb, netdev_features_t features,
			    const struct net_offload __rcu **offloads);

int __psp_register_key(struct sock *sk, __be32 spi,
		       const struct psp_key *key, struct psp_key_idx *idx,
		       u8 *cred_type, struct net_device *held_dev);
void __psp_unregister_key(struct sock *sk, struct psp_key_spi *p);

static inline int psp_register_key(struct sock *sk, __be32 spi,
				   const struct psp_key *key,
				   struct psp_key_idx *idx,
				   u8 *cred_type,
				   struct net_device *held_dev)
{
	return __psp_register_key(sk, spi, key, idx, cred_type, held_dev);
}

static inline void psp_unregister_key(struct sock *sk, struct psp_key_spi *p)
{
	/* zero spi means psp is not active */
	if (!p->spi)
		return;

	__psp_unregister_key(sk, p);
	p->spi = 0;
}

/* helper because psp_listen_node is defined only within psp_listen.c */
void psp_listen_unregister_key(struct sock *sk, struct psp_listen_node *pln);

/* A key must only be unregistered once. Clear the reference after hand-off */
static inline void psp_handoff_key(struct psp_key_spi *p)
{
	p->spi = 0;
}

int __psp_dev_decapsulate(struct sk_buff *skb, u32 keygeneration, bool is_ipv4);

#else
static inline void psp_listen_stop(struct sock *sk)
{
}

static inline void psp_reuseport_free(struct sock_reuseport *reuse)
{
}

static inline void psp_oreq_child_init(struct tcp_sock *tp,
				       const struct tcp_request_sock *treq)
{
}

static inline struct sock *psp_lookup_reuseport(struct sock_reuseport *reuse,
						const struct sk_buff *skb)
{
	return NULL;
}

static inline const struct psp_key_spi *
psp_reqsk_key_spi(const struct request_sock *req)
{
	return NULL;
}

struct psp_key;
static inline int psp_register_key(struct sock *sk, __be32 spi,
				   const struct psp_key *key,
				   struct psp_key_idx *idx)
{
	return 0;
}

static inline void psp_unregister_key(struct tcp_sock *tp)
{
}

static inline void psp_handoff_key(struct tcp_sock *tp)
{
}

#endif  /* CONFIG_INET_PSP */

#endif  /* _NET_PSP_DEFS_H */
