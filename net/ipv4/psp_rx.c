#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sysctl.h>

#include <net/ip.h>
#include <net/netns/ipv4.h>
#include <net/psp_defs.h>

static struct ctl_table psp_table[] = {
	{
		.procname	= "psp_hide_payload_from_taps",
		.data		= &init_net.ipv4.sysctl_psp_hide_payload_from_taps,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "psp_enable_conn",
		.data		= &init_net.ipv4.sysctl_psp_enable_conn,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "psp_conntrack_support",
		.data		= &init_net.ipv4.sysctl_psp_conntrack_support,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra2		= SYSCTL_ONE,
	},
	{ }
};

static inline void psp_adjust_iplen(__be16 *len)
{
	*len = cpu_to_be16(be16_to_cpu(*len) -
			   (PSP_ENCAP_HLEN + PSP_ICV_LENGTH));
}

int __psp_dev_decapsulate(struct sk_buff *skb, u32 keygeneration, bool is_ipv4)
{
	/* We only enter here for packets encapsulated in PSP, and only accept
	 * TCP packets, which on the wire appear as follows:
	 *
	 *	|eth|ip+|udp|psp|tcp|payload|trailer|
	 *			[ encrypted ]
	 *	     ip+ has next-header UDP, length matching encap'ed packet
	 *
	 * These packets need the following transformations:
	 * 1. decryption, done on a pre-decrypt match in the HW, resulting in
	 *    the following data in the rx buffer (frame length from the NIC
	 *    excludes the psp trailer, but the ip header still includes it):
	 *
	 *	|eth|ip+|udp|psp|tcp|payload|
	 *			[ decrypted ]
	 *
	 * 2. adjustment of ip header fields (removal of PSP_ENCAP OVERHEAD
	 *    from ip length, replacement of protocol/nexhdr with TCP).
	 *    This may occur in a post-decrypt match if there is a suitable
	 *    header_info entry, or can be done in software below. We can tell
	 *    what needs to be done by looking at ip protocol/nexthdr. In case
	 *    of sw adjustment we also need to verify that ph->nh is tcp.
	 *    After this step we have the following in the buffer:
	 *
	 *	|eth|ip*|udp|psp|tcp|payload|
	 *			[ decrypted ]
	 *	     ip* has next-header TCP, length matching decap'ed packet
	 *
	 * 3. Extraction of the spi (which indicates the key used to protect
	 *    the packet on the wire) and removal of udp+psp header (pushing
	 *    forward eth+ip). This is done in software below, resulting in:
	 *
	 *	--------|eth|ip*|tcp|payload|
	 *			[ decrypted ]
	 */
	const struct psphdr *ph;
	unsigned int hdr_len;                       /* L2 + L3 header len */

	skb->psp.gen = keygeneration;

	if (is_ipv4) {
		struct iphdr *iph = (struct iphdr *)(skb->data + ETH_HLEN);

		if (unlikely(iph->protocol != IPPROTO_TCP)) {
			if (iph->protocol != IPPROTO_UDP)
				return -1;
			psp_adjust_iplen(&iph->tot_len);
			iph->protocol = IPPROTO_TCP;
			ip_send_check(iph);
		}
		hdr_len = ETH_HLEN + sizeof(*iph);
	} else {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(skb->data + ETH_HLEN);

		if (unlikely(ip6h->nexthdr != IPPROTO_TCP)) {
			if (ip6h->nexthdr != IPPROTO_UDP)
				return -1;
			psp_adjust_iplen(&ip6h->payload_len);
			ip6h->nexthdr = IPPROTO_TCP;
		}
		hdr_len = ETH_HLEN + sizeof(*ip6h);
	}

	/* make sure we have sufficient headers in the skb. */
	if (!pskb_may_pull(skb, hdr_len + PSP_ENCAP_HLEN +
			   sizeof(struct tcphdr)))
		return -1;

	ph = (struct psphdr *)(skb->data + hdr_len + sizeof(struct udphdr));
	if (ph->nh != IPPROTO_TCP)
		return -1;
	skb->psp.spi = ph->spi;
	skb->psp.hdr_len = hdr_len +
			   __tcp_hdrlen((const struct tcphdr *)(ph + 1));

	/* Frame should already be validated by the NIC HW */
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	/* remove PSP+UDP headers, adjust skb lengths */
	memmove(skb->data + PSP_ENCAP_HLEN, skb->data, hdr_len);
	__skb_pull(skb, PSP_ENCAP_HLEN);
	return 0;
}
EXPORT_SYMBOL(__psp_dev_decapsulate);

static void __net_exit psp_net_exit(struct net *net)
{
	struct ctl_table *table = net->ipv4.psp_hdr->ctl_table_arg;

	unregister_net_sysctl_table(net->ipv4.psp_hdr);
	if (table != psp_table)
		kfree(table);
}

static int __net_init psp_net_init(struct net *net)
{
	struct ctl_table *table = psp_table;

	if (!net_eq(net, &init_net)) {
		ptrdiff_t delta = (void *)net - (void *)&init_net;
		int i;

		table = kmemdup(table, sizeof(psp_table), GFP_KERNEL);
		if (!table)
			goto err_alloc;

		for (i = 0; i < ARRAY_SIZE(psp_table) - 1; i++)
			table[i].data += delta;
	}

	net->ipv4.sysctl_psp_enable_conn = 1;
	net->ipv4.sysctl_psp_hide_payload_from_taps = 1;
	net->ipv4.sysctl_psp_conntrack_support = 1;
	net->ipv4.psp_hdr = register_net_sysctl(net, "net/ipv4", table);
	if (!net->ipv4.psp_hdr)
		goto err_reg;

	return 0;

err_reg:
	if (table != psp_table)
		kfree(table);
err_alloc:
	return -ENOMEM;
}

static struct pernet_operations psp_net_ops __net_initdata = {
	.init  = psp_net_init,
	.exit  = psp_net_exit,
};

static int __init psp_rx_register(void)
{
	return register_pernet_subsys(&psp_net_ops);
}

module_init(psp_rx_register);
