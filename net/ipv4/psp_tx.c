/* Kernel PSP transmit path
 *
 */
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <net/protocol.h>
#include <net/psp_defs.h>
#include <net/psp.h>
#include <net/udp.h>

static void __psp_write_headers(struct net *net, struct sk_buff *skb,
				unsigned int udp_len, int port_min,
				int port_max)
{
	struct udphdr *uh = udp_hdr(skb);
	struct psphdr *psph = (struct psphdr *)(uh + 1);

	uh->dest = htons(PSP_UDP_DPORT);
	uh->source = udp_flow_src_port(net,
				       skb,
				       port_min,
				       port_max,
				       /*use_eth=*/ false);
	uh->check = 0;
	uh->len = htons(udp_len);

	psph->nh = IPPROTO_TCP;
	psph->extlen = 1;
	/* expose TCP ports but not the rest of the TCP header */
	psph->cryptoff = offsetof(struct tcphdr, seq) / sizeof(__be32);
	psph->flags = 1;        /* reserved 0, version 0, V = 0 */
	psph->spi = skb->psp.spi;
	memset(&psph->iv, 0, sizeof(psph->iv));

	skb_shinfo(skb)->gso_type |= SKB_GSO_PSP;
}

int __psp_dev_encapsulate(struct sk_buff *skb)
{
	u32 ip_payload_len;
	unsigned int udp_len;

	/* Only valid for PSP socket and packets without PSP encap yet */
	if (!SKB_PSP_SPI(skb))
		return 0;
	/* skb with PSP metadata but transport header was not set */
	if (unlikely(!skb_transport_header_was_set(skb))) {
		WARN_ON(1);
		return -1;
	}
	/* Ensure we have enough headroom to encapsulate */
	if (unlikely(skb_headroom(skb) < PSP_ENCAP_HLEN)) {
		WARN_ON(1);
		return -1;
	}
	/* Consume more headroom */
	skb_push(skb, PSP_ENCAP_HLEN);
	/* Shift headers to make room for PSP [MAC][IP][...][PSP][TCP] */
	memmove(skb->data,
		skb->data + PSP_ENCAP_HLEN,
		skb->transport_header - skb->mac_header);
	skb->transport_header -= PSP_ENCAP_HLEN;
	skb->network_header -= PSP_ENCAP_HLEN;
	skb->mac_header -= PSP_ENCAP_HLEN;
	/* Update inner transport header */
	skb_set_inner_ipproto(skb, IPPROTO_TCP);
	skb->inner_transport_header = skb->transport_header + PSP_ENCAP_HLEN;
	skb->encapsulation = 1;
	/* Fill in PSP header */
	udp_len = skb->len - skb_transport_offset(skb),
	__psp_write_headers(&init_net, skb, udp_len,
			    PSP_SRC_PORT_MIN, PSP_SRC_PORT_MAX);
	/* Update IP header and extension*/
	if (ip_hdr(skb)->version == 4) {
		ip_hdr(skb)->protocol = IPPROTO_UDP;
		ip_payload_len = ntohs(ip_hdr(skb)->tot_len);
		ip_payload_len += PSP_ENCAP_HLEN;
		ip_hdr(skb)->tot_len = htons(ip_payload_len);
	} else {
		ipv6_hdr(skb)->nexthdr = IPPROTO_UDP;
		ip_payload_len = ntohs(ipv6_hdr(skb)->payload_len);
		ip_payload_len += PSP_ENCAP_HLEN;
		ipv6_hdr(skb)->payload_len = htons(ip_payload_len);
	}
	/* Mark SKB_GSO_PSP */
	skb_shinfo(skb)->gso_type |= SKB_GSO_PSP;
	return 0;
}
EXPORT_SYMBOL(__psp_dev_encapsulate);
