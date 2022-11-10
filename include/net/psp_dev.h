#ifndef _NET_PSP_DEV_H
#define _NET_PSP_DEV_H
#include <linux/skbuff.h>


#ifdef CONFIG_INET_PSP
#include <net/psp_defs.h>
/*
 * A callback function for the device driver to perform PSP encapsulation.
 * Returns 0 if encapsulation is successful or unnecessary.
 * Returns -1 if error occurs during encapsulation.
 */
static inline int psp_dev_encapsulate(struct sk_buff *skb)
{
	return __psp_dev_encapsulate(skb);
}

static inline int psp_dev_decapsulate(struct sk_buff *skb, u32 keygeneration,
				      bool is_ipv4)
{
	return __psp_dev_decapsulate(skb, keygeneration, is_ipv4);
}

#else

static inline int psp_dev_encapsulate(struct sk_buff *skb)
{
	return 0;
}

static inline int psp_dev_decapsulate(struct sk_buff *skb, bool is_ipv4)
{
	return 0;
}
#endif  /* CONFIG_INET_PSP */

#endif  /* _NET_PSP_DEV_H */
