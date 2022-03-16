/*
 * Program to create a pcap file containing cleartext packets
 * for testing purposes
 *
 * The created packets are of the form Eth-IP-UDP-Payload with
 * a fixed size of 1434 octets (unless the -e option is specified)
 *
 * All of the created packets are for the same flow (i.e., they all have
 * the same MAC addresses, IP addresses, and UDP port numbers)
 *
 * Command Line Args:
 * 	[-n N] [-f file_name] [-i ver] [-e]
 *
 * 	N is the number of packets to create, defaults to 1
 *
 * 	file_name is the name of the pcap output file,
 * 	defaults to "cleartext.pcap"
 *
 * 	ver is 4 or 6, 4 indicates create ipv4 packets,
 * 	6 indicates create ipv6 packets, default is 4
 *
 * 	the -e option indicates that empty packets are to be
 * 	created, where empty means the size of the l4 payload is 0
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

#include <arpa/inet.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "psp.h"

#define IPV4 4
#define IPV6 6

#define DEFAULT_N 1
#define DEFAULT_IP_VER IPV4

struct ipv4_pkt_hdrs { /* hdrs of plaintext ipv4 packet */
  struct eth_hdr eth;
  struct ipv4_hdr ipv4;
  struct udp_hdr udp;
} PACKED;

struct ipv4_pkt { /* plaintext ipv4 packet */
  struct eth_hdr eth;
  struct ipv4_hdr ipv4;
  struct udp_hdr udp;
  uint8_t payload[0];
} PACKED;

/* size of payload for plaintext ipv4 packet */
#define IPV4_PAYLOAD_OCTETS                                                  \
  (ETH_MAX_OCTETS - (sizeof(struct ipv4_pkt_hdrs) + sizeof(struct psp_hdr) + \
                     sizeof(struct ipv6_hdr) + /* for tunnel mode */         \
                     sizeof(struct udp_hdr) +  /* for PSP encap */           \
                     sizeof(struct psp_trailer)))

/* size of plaintext ipv4 packet */
#define IPV4_PKT_OCTETS (sizeof(struct ipv4_pkt) + IPV4_PAYLOAD_OCTETS)

struct ipv6_pkt_hdrs { /* hdrs of plaintext ipv6 packet */
  struct eth_hdr eth;
  struct ipv6_hdr ipv6;
  struct udp_hdr udp;
} PACKED;

struct ipv6_pkt { /* plaintext ipv6 packet */
  struct eth_hdr eth;
  struct ipv6_hdr ipv6;
  struct udp_hdr udp;
  uint8_t payload[0];
} PACKED;

/* size of payload for plaintext ipv6 packet */
#define IPV6_PAYLOAD_OCTETS                                                  \
  (ETH_MAX_OCTETS - (sizeof(struct ipv6_pkt_hdrs) + sizeof(struct psp_hdr) + \
                     sizeof(struct ipv6_hdr) + /* for tunnel mode */         \
                     sizeof(struct udp_hdr) +  /* for PSP encap */           \
                     sizeof(struct psp_trailer)))

/* size of plaintext ipv6 packet */
#define IPV6_PKT_OCTETS (sizeof(struct ipv6_pkt) + IPV6_PAYLOAD_OCTETS)

struct pkt { /* plaintext packet */
  union {
    struct ipv4_pkt v4;
    struct ipv6_pkt v6;
  } PACKED;
} PACKED;

/* MAC addresses for packets */
char smac[MAC_ADDR_OCTETS] = {0x00, 0x22, 0x33, 0x44, 0x55, 0x00};
char dmac[MAC_ADDR_OCTETS] = {0x00, 0x88, 0x99, 0xAA, 0xBB, 0x00};

/* IPv4 addresses for packets */
uint32_t sip4 = ((10 << 24) + (0 << 16) + (0 << 8) + 1);
uint32_t dip4 = ((10 << 24) + (0 << 16) + (0 << 8) + 2);

/* IPv6 addresses for packets */
uint8_t sip6[IPV6_ADDR_OCTETS] = {10, 0, 0, 0, 0, 0, 0, 0,
                                  0,  0, 0, 0, 0, 0, 0, 1};
uint8_t dip6[IPV6_ADDR_OCTETS] = {10, 0, 0, 0, 0, 0, 0, 0,
                                  0,  0, 0, 0, 0, 0, 0, 2};

/* port numbers for packets */
uint16_t sport = 11111;
uint16_t dport = 22222;

/* empty packet flag */
bool empty = false;

/*
 * compute udp checksum for ipv4 packet
 *   - ipv4 header and udp header are in network byte order, and
 *     are initialized
 *   - udp payload follows udp header
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
static uint16_t ipv4_udp_csum(struct ipv4_pkt *pkt) {
  long sum = 0;
  uint16_t *p, len, odd_byte = 0, csum;
  int i;

  pkt->udp.csum = 0;
  p = (uint16_t *)(&pkt->udp);
  len = ntohs(pkt->udp.len);

  for (i = 0; i < (len / 2); i++) sum += p[i];

  if (len & 1) {
    *((uint8_t *)(&odd_byte)) = *((uint8_t *)(&p[i]));
    sum += odd_byte;
  }

  /* include pseudo header */
  p = (uint16_t *)(&pkt->ipv4.sip);
  sum += p[0];
  sum += p[1];
  sum += p[2];
  sum += p[3];

  sum += IP_PROTO_UDP << 8;
  sum += pkt->udp.len;

  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);

  csum = (uint16_t)~sum;
  if (csum == 0) csum = 0xffff;

  return csum;
}

/*
 * compute udp checksum for ipv6 packet
 *   - ipv6 header and udp header are in network byte order, and
 *     are initialized
 *   - udp payload follows udp header
 */
static uint16_t ipv6_udp_csum(struct ipv6_pkt *pkt) {
  long sum = 0;
  uint16_t *p, len, odd_byte = 0, csum;
  int i;

  pkt->udp.csum = 0;
  p = (uint16_t *)(&pkt->udp);
  len = ntohs(pkt->udp.len);

  for (i = 0; i < (len / 2); i++) sum += p[i];

  if (len & 1) {
    *((uint8_t *)(&odd_byte)) = *((uint8_t *)(&p[i]));
    sum += odd_byte;
  }

  /* include pseudo header */
  p = (uint16_t *)(pkt->ipv6.sip);
  for (i = 0; i < IPV6_ADDR_OCTETS; i++) sum += p[i];

  sum += IP_PROTO_UDP << 8;
  sum += pkt->udp.len;

  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);

  csum = (uint16_t)~sum;
  if (csum == 0) csum = 0xffff;

  return csum;
}

/* initialize packet headers */
static void init_ipv4_pkt_hdrs(struct ipv4_pkt *p) {
  uint16_t ip_len;

  memset(p, 0, sizeof(struct ipv4_pkt_hdrs));

  memcpy(p->eth.dmac, dmac, MAC_ADDR_OCTETS);
  memcpy(p->eth.smac, smac, MAC_ADDR_OCTETS);
  p->eth.etype = htons(IPV4_ETYPE);

  p->ipv4.ver_ihl = IPV4_VER_IHL;
  if (empty) {
    ip_len = sizeof(struct ipv4_pkt_hdrs) - sizeof(struct eth_hdr);
  } else {
    ip_len = IPV4_PKT_OCTETS - sizeof(struct eth_hdr);
  }
  p->ipv4.len = htons(ip_len);
  p->ipv4.flags_offset = htons(IPV4_FLAGS_DF);
  p->ipv4.ttl = IP_TTL_DEF;
  p->ipv4.proto = IP_PROTO_UDP;
  p->ipv4.sip = htonl(sip4);
  p->ipv4.dip = htonl(dip4);
  p->ipv4.csum = ipv4_hdr_csum(&p->ipv4);

  p->udp.sport = htons(sport);
  p->udp.dport = htons(dport);
  p->udp.len = htons(ip_len - sizeof(struct ipv4_hdr));
  p->udp.csum = 0;

  return;
}
#pragma GCC diagnostic pop

static void init_ipv6_pkt_hdrs(struct ipv6_pkt *p) {
  uint16_t ip_len;

  memset(p, 0, sizeof(struct ipv6_pkt_hdrs));

  memcpy(p->eth.dmac, dmac, MAC_ADDR_OCTETS);
  memcpy(p->eth.smac, smac, MAC_ADDR_OCTETS);
  p->eth.etype = htons(IPV6_ETYPE);

  p->ipv6.ver_tc_flow = htonl(IPV6_VER);
  if (empty)
    ip_len = sizeof(struct udp_hdr);
  else
    ip_len = IPV6_PKT_OCTETS - sizeof(struct eth_hdr) - sizeof(struct ipv6_hdr);
  p->ipv6.plen = htons(ip_len);
  p->ipv6.proto = IP_PROTO_UDP;
  p->ipv6.ttl = IP_TTL_DEF;
  memcpy(p->ipv6.sip, sip6, IPV6_ADDR_OCTETS);
  memcpy(p->ipv6.dip, dip6, IPV6_ADDR_OCTETS);

  p->udp.sport = htons(sport);
  p->udp.dport = htons(dport);
  p->udp.len = htons(ip_len);
  p->udp.csum = 0;

  return;
}

/* initialize packet payload */
static void init_pkt_payload(uint8_t *payload, int payload_octets,
                             int packet_id) {
  int i;
  uint8_t octet = (uint8_t)packet_id;

  for (i = 0; i < payload_octets; i++) payload[i] = octet++;

  return;
}

int main(int argc, char *argv[]) {
  int opt, i, n = DEFAULT_N, ip_ver = DEFAULT_IP_VER, rc = EXIT_SUCCESS;
  int pkt_octets, payload_octets;
  pcap_t *pd = NULL;
  pcap_dumper_t *pdumper = NULL;
  char *pcap_file = DEFAULT_CLEARTEXT_PCAP_FILE;
  uint8_t *payload;
  struct pkt *p = NULL;
  struct ipv4_pkt *v4_pkt;
  struct ipv6_pkt *v6_pkt;
  struct pcap_pkthdr pcap_pkt_hdr;

  while ((opt = getopt(argc, argv, "n:f:i:e")) != -1) {
    switch (opt) {
      case 'e':
        empty = true;
        break;
      case 'n':
        n = atoi(optarg);
        break;
      case 'f':
        pcap_file = optarg;
        break;
      case 'i':
        ip_ver = atoi(optarg);
        if ((ip_ver == IPV4) || (ip_ver == IPV6)) break;
        fprintf(stderr, "Invalid ip_ver\n");
        /* intentional fall-through */
      default:
        fprintf(stderr, "Usage: %s [-n N] [-f file_name] [-i ver] [-e]\n",
                argv[0]);
        goto err_exit;
        break;
    }
  }

  if (ip_ver == IPV4) {
    pkt_octets = IPV4_PKT_OCTETS;
  } else {
    pkt_octets = IPV6_PKT_OCTETS;
  }

  pd = pcap_open_dead(DLT_EN10MB, pkt_octets);
  if (pd == NULL) {
    fprintf(stderr, "pcap_open_dead() failed\n");
    goto err_exit;
  }

  pdumper = pcap_dump_open(pd, pcap_file);
  if (pdumper == NULL) {
    fprintf(stderr, "pcap_dump_open() failed\n");
    goto err_exit;
  }

  if (gettimeofday(&pcap_pkt_hdr.ts, NULL)) {
    fprintf(stderr, "gettimeofday() failed\n");
    goto err_exit;
  }

  p = malloc(pkt_octets);
  if (p == NULL) {
    fprintf(stderr, "malloc() failed\n");
    goto err_exit;
  }

  if (ip_ver == IPV4) {
    v4_pkt = (struct ipv4_pkt *)p;
    init_ipv4_pkt_hdrs(v4_pkt);
    payload = (uint8_t *)v4_pkt->payload;
    if (empty) {
      pcap_pkt_hdr.caplen = sizeof(struct ipv4_pkt_hdrs);
      pcap_pkt_hdr.len = pcap_pkt_hdr.caplen;
      payload_octets = 0;
    } else {
      pcap_pkt_hdr.caplen = pkt_octets;
      pcap_pkt_hdr.len = pkt_octets;
      payload_octets = IPV4_PAYLOAD_OCTETS;
    }
  } else {
    v6_pkt = (struct ipv6_pkt *)p;
    init_ipv6_pkt_hdrs(v6_pkt);
    payload = (uint8_t *)v6_pkt->payload;
    if (empty) {
      pcap_pkt_hdr.caplen = sizeof(struct ipv6_pkt_hdrs);
      pcap_pkt_hdr.len = pcap_pkt_hdr.caplen;
      payload_octets = 0;
    } else {
      pcap_pkt_hdr.caplen = pkt_octets;
      pcap_pkt_hdr.len = pkt_octets;
      payload_octets = IPV6_PAYLOAD_OCTETS;
    }
  }

  for (i = 0; i < n; i++) {
    init_pkt_payload(payload, payload_octets, i);
    if (ip_ver == IPV4)
      v4_pkt->udp.csum = ipv4_udp_csum(v4_pkt);
    else
      v6_pkt->udp.csum = ipv6_udp_csum(v6_pkt);
    pcap_dump((u_char *)pdumper, &pcap_pkt_hdr, (u_char *)p);
    pcap_pkt_hdr.ts.tv_usec++;
  }

  printf("created %d packets in %s\n", n, pcap_file);
  goto exit;

err_exit:
  fprintf(stderr, "pcap file creation failed\n");
  rc = EXIT_FAILURE;

exit:
  free(p);
  if (pdumper != NULL) pcap_dump_close(pdumper);
  if (pd != NULL) pcap_close(pd);

  exit(rc);
}
