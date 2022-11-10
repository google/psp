#ifndef _NET_PSP_H
#define _NET_PSP_H

#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/jump_label.h>
#include <net/ip.h>
#include <net/psp_defs.h>
#include <uapi/linux/udp.h>

extern struct static_key_false tcp_psp_needed;

/* Return whether a TCP socket uses PSP */
static inline bool tcp_uses_psp(const struct tcp_sock *tp)
{
#ifdef CONFIG_INET_PSP
	if (static_branch_unlikely(&tcp_psp_needed))
		return tp->psp.tx_info.spi != 0;
#endif
	return false;
}

static inline void psp_reuseport_init(struct psp_reuseport *reuse)
{
#ifdef CONFIG_INET_PSP
	RCU_INIT_POINTER(reuse->listen_hash, NULL);
#endif
}

static inline void psp_reqsk_init(struct tcp_request_sock *treq)
{
#ifdef CONFIG_INET_PSP
	treq->psp.listen_node = NULL;
#endif
}

static inline void psp_reqsk_destructor(struct request_sock *req)
{
#ifdef CONFIG_INET_PSP
	kfree(tcp_rsk(req)->psp.listen_node);
#endif
}

/* Initialize the PSP credentials associated with a TCP request sock.
 * Returns false if needed credentials aren't found.
 */
static inline bool psp_treq_init(struct sock *sk, struct tcp_request_sock *treq,
				 const struct sk_buff *skb)
{
#ifdef CONFIG_INET_PSP
	if (skb->psp.spi) {
		treq->psp.listen_node = psp_lookup_listener(sk, skb->psp.spi,
							    skb->psp.gen);
		return treq->psp.listen_node != NULL;
	}
	treq->psp.listen_node = NULL;
#endif
	return true;
}

/* Initialize TIME-WAIT PSP fields from the full socket. */
static inline void psp_twsk_init(struct tcp_timewait_sock *tcptw,
				 struct tcp_sock *tp)
{
#ifdef CONFIG_INET_PSP
	tcptw->tw_psp = tp->psp.tx_info;
	psp_handoff_key(&tp->psp.tx_info);
#endif
}

/* Capture the PSP credentials from a SYN/ACK. */
static inline void psp_rcv_synack(struct tcp_sock *tp,
				  const struct sk_buff *skb)
{
#ifdef CONFIG_INET_PSP
	tp->psp.rx_syn.spi = skb->psp.spi;
	tp->psp.rx_syn.gen = tp->psp.rx_curr.spi == skb->psp.spi ?
				tp->psp.rx_curr.gen : tp->psp.rx_prev.gen;
#endif
}

/* Return true if a socket has specified incomplete PSP credentials. Given
 * the sequencing of socket options needed to set up PSP this can happen if
 * a socket has only Rx PSP credentials.
 */
static inline bool psp_missing_cred(const struct tcp_sock *tp)
{
#ifdef CONFIG_INET_PSP
	return tp->psp.rx_curr.spi && !tp->psp.tx_info.spi;
#else
	return false;
#endif
}

/* Check if a packet matches a socket's PSP acceptance policy and return true
 * if it doesn't.
 */
static inline bool psp_policy_failure(const struct sock *sk,
				      const struct sk_buff *skb)
{
#ifdef CONFIG_INET_PSP
	const struct tcp_sock *tp = tcp_sk(sk);

	if (!static_branch_unlikely(&tcp_psp_needed))
		return false;

	/* Listening sockets accept both PSP and non-PSP SYNs.
	 * PSP SYNs are checked further later by psp_treq_init().
	 */
	if (sk->sk_state == TCP_LISTEN)
		return false;

	/* non-PSP packets require a non-PSP socket */
	if (!skb->psp.spi)
		return tcp_uses_psp(tp);

	/* PSP packets must match the socket's PSP credentials */
	return !psp_skb_gen_spi_ok(&skb->psp, &tp->psp.rx_curr) &&
	       !psp_skb_gen_spi_ok(&skb->psp, &tp->psp.rx_prev);
#else
	return false;
#endif
}

/* Similar to psp_policy_failure() but for TIME-WAIT sockets.
 * This performs only a simple "encrypted vs. nonencrypted" check as we don't
 * keep PSP Rx credentials for TIME-WAIT sockets.
 */
static inline bool psp_policy_tw_failure(const struct tcp_timewait_sock *tcptw,
					 const struct sk_buff *skb)
{
#ifdef CONFIG_INET_PSP
	return (skb->psp.spi == 0) != (tcptw->tw_psp.spi == 0);
#else
	return false;
#endif
}

/* Similar to psp_policy_failure() but for request sockets. */
static inline bool psp_policy_req_failure(const struct request_sock *req,
					  const struct sk_buff *skb)
{
#ifdef CONFIG_INET_PSP
	const struct psp_listen_node *pln = tcp_rsk(req)->psp.listen_node;

	if (!skb->psp.spi)
		return pln != NULL;

	return psp_policy_failure_pln(skb, pln);
#else
	return false;
#endif
}

/* Return overhead in bytes for UDP/PSP encapsulation. */
static inline unsigned int psp_encap_overhead(const struct tcp_sock *tp)
{
#ifdef CONFIG_INET_PSP
	if (tcp_uses_psp(tp))
		return PSP_ENCAP_HLEN + PSP_ICV_LENGTH;
#endif
	return 0;
}

/* Return the PSP Tx SPI/key pair for the given socket. Note a non-NULL return
 * value does not imply the socket uses PSP, that depends on the pair's values.
 */
static inline const struct psp_key_spi *psp_sk_key_spi(const struct sock *sk)
{
#ifdef CONFIG_INET_PSP
	if (sk) {
		if (likely(sk_fullsock_notlistener(sk)))
			return &tcp_sk(sk)->psp.tx_info;
		if (sk->sk_state == TCP_TIME_WAIT)
			return &tcp_twsk(sk)->tw_psp;
	}
#endif
	return NULL;
}

/* Set the PSP metadata in the skb */
static inline void psp_set_psp_skb(struct sk_buff *skb,
				   const struct psp_key_spi *key_spi)
{
#ifdef CONFIG_INET_PSP
	skb->psp.spi = key_spi->spi;
	skb->psp.key = key_spi->key;
#endif
}


/* If @key_spi provides usable PSP key & SPI encapsulate @skb with
 * transport-mode PSP.
 */
static inline void psp_encap(struct net *net, struct sk_buff *skb,
			     const struct psp_key_spi *key_spi)
{
#ifdef CONFIG_INET_PSP
	if (key_spi && key_spi->spi)
		psp_set_psp_skb(skb, key_spi);
#endif
}

/* Similar to psp_encap() but takes a TCP socket. */
static inline void psp_encapsulate_tcp(struct sk_buff *skb,
				       const struct sock *sk)
{
#ifdef CONFIG_INET_PSP
	const struct tcp_sock *tp = tcp_sk(sk);

	if (tcp_uses_psp(tp))
		psp_set_psp_skb(skb, &tp->psp.tx_info);
#endif
}

/* Another encapsulation variant for request sockets, used for SYN/ACKs. */
static inline void psp_encapsulate_synack(struct net *net,
					  struct sk_buff *skb,
					  const struct request_sock *req)
{
	psp_encap(net, skb, psp_reqsk_key_spi(req));
}

/* Prepare an ip_reply_arg for PSP encapsulation, if needed.  */
static inline void psp_fill_reply_arg(struct ip_reply_arg *arg,
				      const struct psp_key_spi *key_spi)
{
#ifdef CONFIG_INET_PSP
	if (key_spi && key_spi->spi) {
		arg->psp_key_spi = key_spi;
	}
#endif
}

/* If an skb generated from an ip_reply_arg needs PSP encapsulation fill out
 * the PSP/UDP headers and set the sk protocol to UDP, it is used to set the
 * protocol in the IP header. Otherwise set the sk to its native protocol.
 */
static inline void psp_encap_reply(struct net *net, struct sk_buff *skb,
				   const struct ip_reply_arg *arg)
{
#ifdef CONFIG_INET_PSP
	if (arg->psp_key_spi) {
		psp_set_psp_skb(skb, arg->psp_key_spi);
	}
#endif
}

/* Return the length of a PSP packet with offloaded crypto that should be
 * exposed to packet taps. We hide the inner packet payload as it is in
 * cleartext form at tap point.
 */
static inline unsigned int psp_len_for_taps(const struct sk_buff *skb)
{
#ifdef CONFIG_INET_PSP
	if (unlikely(!dev_net(skb->dev)->ipv4.sysctl_psp_hide_payload_from_taps))
		return skb->len;

	if (skb_transport_header_was_set(skb) &&
	    skb_mac_header_was_set(skb)) {
		/* Unencapped Tx skbs or Rx GRO skbs */
		const struct tcphdr *th = tcp_hdr(skb);

		return __tcp_hdrlen(th) + ((const u8 *)th - skb->data);
	}
	/* all Tx skbs */
	if (skb->encapsulation) {
		const struct tcphdr *th = inner_tcp_hdr(skb);

		return __tcp_hdrlen(th) + ((const u8 *)th - skb->data);
	}

	/* Rx skbs (device driver hints the full header length */
	return skb->psp.hdr_len - (skb->data - skb_mac_header(skb));
#else
	return 0;
#endif
}

/* Holds the original skb lengths around operations that hide and restore a PSP
 * packet's payload (see the following two functions).
 *
 * We do not store these in skb fields, e.g., in ->cb, to avoid potential
 * conflicts with upstream code.
 */
struct psp_skb_saved_lens {
	unsigned int len;
	unsigned int data_len_delta;
};

/* Shrink the length of a PSP skb to exclude the TCP payload.
 * Unlike pskb_trim this function does not allocate memory and does not remove
 * any fragments from skbs. OTOH after calling this function skb->data_len may
 * no longer equal the total fragment length of the skb. Caller is responsible
 * to use the resulting skb in ways that won't be confused by the discrepancy.
 * The original length and reduction to skb->data_len are returned so they can
 * be restored later.
 */
static inline void psp_trim_skb(struct sk_buff *skb,
				struct psp_skb_saved_lens *saved_lens)
{
	unsigned int snaplen, headlen, new_datalen;

	if (!SKB_PSP_SPI(skb)) {
		saved_lens->len = 0;
		return;
	}

	headlen = skb_headlen(skb);
	snaplen = psp_len_for_taps(skb);
	new_datalen = snaplen > headlen ? snaplen - headlen : 0;

	saved_lens->data_len_delta = skb->data_len - new_datalen;
	skb->data_len = new_datalen;

	saved_lens->len = skb->len;
	skb->len = snaplen;
}

/* Reverse the length changes of an earlier psp_trim_skb(). The values passed
 * to this function should be the ones returned by that call.
 */
static inline void psp_restore_skb(struct sk_buff *skb,
				   const struct psp_skb_saved_lens *saved_lens)
{
	if (saved_lens->len) {
		skb->len = saved_lens->len;
		skb->data_len += saved_lens->data_len_delta;
	}
}
#endif  /* _NET_PSP_H */
