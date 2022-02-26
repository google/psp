/*
 * Definitions of constants and structures used to
 * add PSP encapsulations when encrypting packets
 * and remove PSP encapsulations when decrypting packets
 *
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _PSP_H_
#define _PSP_H_

#define PACKED __attribute__((packed))

typedef enum { /* return codes */
  SUCCESS_RC,
  ERR_RC
} rc_t;

#define DEFAULT_CLEARTEXT_PCAP_FILE "cleartext.pcap"
#define DEFAULT_ENCRYPT_PCAP_FILE "psp_encrypt.pcap"
#define DEFAULT_DECRYPT_PCAP_FILE "psp_decrypt.pcap"
#define DEFAULT_ENCRYPT_CFG_FILE "psp_encrypt.cfg"
#define DEFAULT_DECRYPT_CFG_FILE "psp_decrypt.cfg"

#define MAX_PCAP_CAPTURE_OCTETS 65535

#define ETH_MIN_OCTETS 64
#define ETH_MAX_OCTETS 1514
#define ETH_JUMBO_MAX_OCTETS 9014

#define MAC_ADDR_OCTETS 6
#define IPV4_ETYPE 0x0800
#define IPV6_ETYPE 0x86DD

#define IPV4_VER_IHL 0x45
#define IPV4_IHL_MASK 0x0f
#define IPV4_IHL_UNITS 4 /* units of 4 octets */
#define IPV4_IHL_NO_OPTIONS 5
#define IPV4_HDR_OCTETS_NO_OPTIONS (IPV4_IHL_NO_OPTIONS * IPV4_IHL_UNITS)
#define IPV4_FLAGS_DF 0x4000
#define IPV4_FLAGS_MF 0x2000
#define IP_TTL_DEF 0x40

#define IPV6_VER 0x60000000
#define IPV6_ADDR_OCTETS 16

#define IP_PROTO_IPV4 0x04
#define IP_PROTO_IPV6 0x29
#define IP_PROTO_UDP 0x11
#define IP_PROTO_TCP 0x06

#define UDP_PORT_PSP 1000

#define TCP_DATA_OFFSET 0x5000 /* default */
#define TCP_FLAG_NS 0x0100
#define TCP_FLAG_CWR 0x0080
#define TCP_FLAG_ECE 0x0040
#define TCP_FLAG_URG 0x0020
#define TCP_FLAG_ACK 0x0010
#define TCP_FLAG_PSH 0x0008
#define TCP_FLAG_RST 0x0004
#define TCP_FLAG_SYN 0x0002
#define TCP_FLAG_FIN 0x0001

typedef enum { PSP_TRANSPORT, PSP_TUNNEL } psp_encap_t;

typedef enum { AES_GCM_128, AES_GCM_256 } crypto_alg_t;

#define PSP_HDR_EXT_LEN_UNITS 8 /* units of 8 octets */
#define PSP_HDR_EXT_LEN_MIN 1
#define PSP_HDR_EXT_LEN_WITH_VC 2
#define PSP_HDR_VC_OCTETS 8

/* values to expose L4 port numbers, units of 4 octets */
#define PSP_CRYPT_OFFSET_UNITS 4 /* units of 4 octets */
#define PSP_CRYPT_OFFSET_MASK 0x3f
#define PSP_CRYPT_OFFSET_MAX 64
#define PSP_CRYPT_OFFSET_RESERVED_BIT7 0x80
#define PSP_CRYPT_OFFSET_RESERVED_BIT6 0x40
#define PSP_CRYPT_OFFSET_V4_TUNNEL 6
#define PSP_CRYPT_OFFSET_V6_TUNNEL 11

typedef enum {
  PSP_VER0 = 0, /* AES-GCM-128 */
  PSP_VER1,     /* AES-GCM-256 */
  PSP_VER2,     /* AES-GMAC-128 */
  PSP_VER3      /* AES-GMAC-256 */
} psp_ver_t;

#define PSP_HDR_FLAG_S_SHIFT 7 /* sample bit */
#define PSP_HDR_FLAG_D_SHIFT 6 /* drop bit */
#define PSP_HDR_VER_SHIFT 2    /* version bits */
#define PSP_HDR_VER_MASK 0x0f
#define PSP_HDR_FLAG_V_SHIFT 1 /* virtualization-cookie-present bit */
#define PSP_HDR_FLAG_V (1 << PSP_HDR_FLAG_V_SHIFT)
#define PSP_HDR_ALWAYS_1 1

#define PSP_SPI_OCTETS 4
#define PSP_SPI_KEY_SELECTOR_BIT 0x80000000 /* for uint32_t compare */
#define PSP_SPI_MSB_KEY_SELECTOR_BIT 0x80   /* for uint8_t compare */

#define PSP_INITIAL_IV 1 /* starting value for psp initialization vector */
#define PSP_IV_OCTETS 8
#define AES_GCM_IV_OCTETS 12

#define AES_128_KEY_OCTETS 16
#define AES_256_KEY_OCTETS 32

#define PSP_MASTER_KEY_OCTETS AES_256_KEY_OCTETS
#define PSP_DERIVED_KEY_MAX_OCTETS AES_256_KEY_OCTETS
#define PSP_KEY_DERIVATION_BLOCK_OCTETS 16
#define PSP_ICV_OCTETS 16

struct eth_hdr {
  char dmac[MAC_ADDR_OCTETS];
  char smac[MAC_ADDR_OCTETS];
  uint16_t etype;
} PACKED;

struct ipv4_hdr {
  uint8_t ver_ihl;
  uint8_t tos;
  uint16_t len;
  uint16_t id;
  uint16_t flags_offset;
  uint8_t ttl;
  uint8_t proto;
  uint16_t csum;
  uint32_t sip;
  uint32_t dip;
};

struct ipv6_hdr {
  uint32_t ver_tc_flow;
  uint16_t plen;
  uint8_t proto;
  uint8_t ttl;
  uint8_t sip[IPV6_ADDR_OCTETS];
  uint8_t dip[IPV6_ADDR_OCTETS];
};

struct udp_hdr {
  uint16_t sport;
  uint16_t dport;
  uint16_t len;
  uint16_t csum;
};

struct tcp_hdr {
  uint16_t sport;
  uint16_t dport;
  uint32_t seq;
  uint32_t ack;
  uint16_t off_flags;
  uint16_t win;
  uint16_t csum;
  uint16_t urp;
};

struct psp_hdr {
  uint8_t next_hdr;
  uint8_t hdr_ext_len;
  uint8_t crypt_off;
  uint8_t s_d_ver_v_1;
  uint32_t spi;
  uint64_t iv;
};

struct psp_icv {
  uint8_t octets[PSP_ICV_OCTETS];
};

struct psp_trailer {
  struct psp_icv icv;
};

struct psp_v4_hdrs {
  struct eth_hdr eth;
  struct ipv4_hdr ipv4;
  struct udp_hdr udp;
  struct psp_hdr psp;
} PACKED;

struct psp_v6_hdrs {
  struct eth_hdr eth;
  struct ipv6_hdr ipv6;
  struct udp_hdr udp;
  struct psp_hdr psp;
} PACKED;

#define PSP_TRANSPORT_ENCAP_OCTETS \
  (sizeof(struct udp_hdr) + sizeof(struct psp_hdr) + sizeof(struct psp_trailer))

#define PSP_V4_TUNNEL_ENCAP_OCTETS \
  (PSP_TRANSPORT_ENCAP_OCTETS + sizeof(struct ipv4_hdr))

#define PSP_V6_TUNNEL_ENCAP_OCTETS \
  (PSP_TRANSPORT_ENCAP_OCTETS + sizeof(struct ipv6_hdr))

struct psp_master_key {
  uint8_t octets[PSP_MASTER_KEY_OCTETS];
};

struct psp_key_derivation_block {
  uint8_t octets[PSP_KEY_DERIVATION_BLOCK_OCTETS];
};

struct psp_derived_key {
  uint8_t octets[PSP_DERIVED_KEY_MAX_OCTETS];
};

struct aes_gcm_iv {
  uint8_t octets[AES_GCM_IV_OCTETS];
};

/* host-to-network and network-to-host for 64b */
#define HTONLL(x)                                                   \
  ((1 == htonl(1)) ? (x)                                            \
                   : ((((uint64_t)htonl((x)&0xFFFFFFFFUL)) << 32) | \
                      htonl((uint32_t)((x) >> 32))))
#define NTOHLL(x)                                                   \
  ((1 == ntohl(1)) ? (x)                                            \
                   : ((((uint64_t)ntohl((x)&0xFFFFFFFFUL)) << 32) | \
                      ntohl((uint32_t)((x) >> 32))))

/* compute IPv4 header checksum */
static inline uint16_t ipv4_hdr_csum(struct ipv4_hdr *h) {
  long sum = 0;
  uint16_t *p = (uint16_t *)h;
  int i, ihl_octets;

  ihl_octets = (h->ver_ihl & IPV4_IHL_MASK) * IPV4_IHL_UNITS;
  for (i = 0, sum = 0; i < (ihl_octets / 2); i++) sum += p[i];

  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);

  return ((uint16_t)~sum);
}

#endif /* _PSP_H_*/
