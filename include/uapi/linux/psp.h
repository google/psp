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
#ifndef _UAPI_LINUX_PSP_H
#define _UAPI_LINUX_PSP_H

#define PSP_V0_KEYSIZE 16	/* The size in bytes of a PSP V0 key */

#include <linux/types.h>
#include <linux/in6.h>

typedef __u32 psp_generation;
typedef __u32 psp_spi;

struct psp_key {
	__u8		k[PSP_V0_KEYSIZE];
};

struct psp_spi_tuple {
	struct psp_key	key;
	psp_generation	key_generation;
	psp_spi		spi;
};

struct psp_spi_addr_tuple {
	struct psp_spi_tuple tuple;
	struct in6_addr saddr;
};

#endif /* _UAPI_LINUX_PSP_H */
