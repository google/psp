/*
 * Program to perform PSP encryption
 *
 * Reads plaintext packets from a pcap input file
 *
 * Performs the following for each packet:
 *   - Adds appropriate PSP encapsulation
 *   - Computes ICV
 *   - Encrypts data
 *
 * Then writes each PSP-encrypted packet to a pcap output
 *
 * Command Line Args:
 * 	[-c psp_cfg_file_name] [-i in_file] [-o out_file] [-v] [-e]
 *
 * 	-v enables verbose mode
 *
 * 	-e forces a single bit error in each output packet,
 * 	   which will cause authentication to fail
 *
 *      Defaults:
 *      	psp_cfg_file: "psp_encrypt.cfg"
 *      	in_file:      "cleartext.pcap"
 *      	out_file:     "psp_encrypt.pcap"
 *
 * The format of the PSP encryption configuration file is:
 *   series of 32 hex bytes (e.g., 34 44 8a ...):            Master Key 0
 *   series of 32 hex bytes (e.g., 56 39 52 ...):            Master Key 1
 *   32b hex value (e.g., 9A345678), msb selects master key: SPI
 *   encap string (either "transport" or "tunnel"):          PSP Encap Mode
 *   crypro algorithm string
 *   (either "aes-gcm-128" or "aes-gcm-256"):                Crypto Algorithm
 *   non-negative integer with units of 4 bytes (e.g., 1):   Transport Mode
 *   							     Crypt Offset
 *   non-negative integer with units of 4 bytes (e.g., 6):   IPv4 Tunnel Mode
 *   							     Crypt Offset
 *   non-negative integer with units of 4 bytes (e.g., 11):  IPv6 Tunnel Mode
 *   							     Crypt Offset
 *   virtual cookie string (either "vc" or "no-vc")          Include VC in
 *							     PSP Header
 *
 * The program uses OpenSSL crypto libraries.
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
#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "psp.h"

typedef enum {                /* return codes for packet processsing */
               PKT_ENCRYPTED, /* success */
               PKT_SKIPPED,   /* packet not encrypted */
               PKT_ERR
} pkt_rc_t;

struct psp_encrypt_cfg { /* encryption config parms */
  struct psp_master_key master_key0;
  struct psp_master_key master_key1;
  uint32_t spi;
  psp_encap_t psp_encap;
  crypto_alg_t crypto_alg;
  /* crypt offset for transport mode, units = 4B */
  uint8_t transport_crypt_off;
  /* crypt offset for ipv4 packets in tunnel mode, units = 4B */
  uint8_t ipv4_tunnel_crypt_off;
  /* crypt offset for ipv6 packets in tunnel mode, units = 4B */
  uint8_t ipv6_tunnel_crypt_off;
  bool include_vc; /* include vc in psp header */
};

/*
 * context info associated with packet
 *
 * passed as parm to packet processing functions
 *
 * fields:
 *   max_pkt_octets: max packet size supported
 *   psp_cfg: psp encryption config parms
 *   key: derived psp encryption key
 *   next_iv: next psp initialization vector to use
 *   	      (since we don't have a picosecond resolution timer,
 *   	       we use a 64b counter instead)
 *   in_pcap_pkt_hdr: ptr to pcap_pkt_hdr for input packet
 *   in_pkt: ptr to input packet
 *   eth_hdr_len: length of ethernet header in octets
 *   out_pcap_pkt_hdr: pcap_pkt_hdr for output packet
 *   out_pkt: ptr to output packet
 *   scratch_buf: ptr to scratch packet buffer
 */
struct pkt_context {
  uint32_t max_pkt_octets;
  struct psp_encrypt_cfg psp_cfg;
  struct psp_derived_key key;
  uint64_t next_iv;
  struct pcap_pkthdr *in_pcap_pkt_hdr;
  uint8_t *in_pkt;
  uint32_t eth_hdr_len;
  struct pcap_pkthdr out_pcap_pkt_hdr;
  uint8_t *out_pkt;
  uint8_t *scratch_buf;
};

bool verbose = false, force_corruption = false;

/*
 * get psp configuration by:
 *   - reading from configuration file,
 *   - parsing the configuration data, and
 *   - saving the results in the packet context structure
 */
static rc_t get_psp_cfg(char *cfg_file, struct pkt_context *pkt_ctx) {
  int i;
  FILE *fp;
  char string[16];

  fp = fopen(cfg_file, "r");
  if (fp == NULL) {
    perror("fopen() failed for psp_cfg_file");
    goto err_exit;
  }

  for (i = 0; i < PSP_MASTER_KEY_OCTETS; i++) {
    if (fscanf(fp, "%hhx", &pkt_ctx->psp_cfg.master_key0.octets[i]) != 1) {
      fprintf(stderr, "read of master key 0 from psp_cfg_file failed\n");
      goto err_exit;
    }
  }

  if (verbose) {
    printf("Master Key 0:\n  ");
    for (i = 0; i < PSP_MASTER_KEY_OCTETS; i++)
      printf("%02hhx ", pkt_ctx->psp_cfg.master_key0.octets[i]);
    printf("\n");
    fflush(stdout);
  }

  for (i = 0; i < PSP_MASTER_KEY_OCTETS; i++) {
    if (fscanf(fp, "%hhx", &pkt_ctx->psp_cfg.master_key1.octets[i]) != 1) {
      fprintf(stderr, "read of master key 1 from psp_cfg_file failed\n");
      goto err_exit;
    }
  }

  if (verbose) {
    printf("Master Key 1:\n  ");
    for (i = 0; i < PSP_MASTER_KEY_OCTETS; i++)
      printf("%02hhx ", pkt_ctx->psp_cfg.master_key1.octets[i]);
    printf("\n");
    fflush(stdout);
  }

  if (fscanf(fp, "%x", &pkt_ctx->psp_cfg.spi) != 1) {
    fprintf(stderr, "read of spi from psp_cfg_file failed\n");
    goto err_exit;
  }

  if (verbose) {
    printf("SPI: %08x\n", pkt_ctx->psp_cfg.spi);
    fflush(stdout);
  }

  if (fscanf(fp, "%15s", string) != 1) {
    fprintf(stderr, "read of psp encap mode from psp_cfg_file failed\n");
    goto err_exit;
  }
  if (strcmp(string, "transport") == 0) {
    pkt_ctx->psp_cfg.psp_encap = PSP_TRANSPORT;
  } else if (strcmp(string, "tunnel") == 0) {
    pkt_ctx->psp_cfg.psp_encap = PSP_TUNNEL;
  } else {
    fprintf(stderr, "invalid psp encap mode in psp_cfg_file\n");
    goto err_exit;
  }

  if (verbose) {
    printf("Encap Mode: %s\n", string);
    fflush(stdout);
  }

  if (fscanf(fp, "%15s", string) != 1) {
    fprintf(stderr, "read of crypto algorithm from psp_cfg_file failed\n");
    goto err_exit;
  }
  if (strcmp(string, "aes-gcm-128") == 0) {
    pkt_ctx->psp_cfg.crypto_alg = AES_GCM_128;
  } else if (strcmp(string, "aes-gcm-256") == 0) {
    pkt_ctx->psp_cfg.crypto_alg = AES_GCM_256;
  } else {
    fprintf(stderr, "invalid crypto algotithm in psp_cfg_file\n");
    goto err_exit;
  }

  if (verbose) {
    printf("Crypto Alg: %s\n", string);
    fflush(stdout);
  }

  if (fscanf(fp, "%hhu", &pkt_ctx->psp_cfg.transport_crypt_off) != 1) {
    fprintf(stderr,
            "read of transport crypt offset from psp_cfg_file failed\n");
    goto err_exit;
  }
  if (pkt_ctx->psp_cfg.transport_crypt_off > PSP_CRYPT_OFFSET_MAX) {
    fprintf(stderr,
            "invalid transport crypt offset in psp_cfg_file: "
            "value = %hhu, max value = %d\n",
            pkt_ctx->psp_cfg.transport_crypt_off, PSP_CRYPT_OFFSET_MAX);
    goto err_exit;
  }

  if (verbose) {
    printf("Transport Mode Crypt Offset:   %hhu (%u bytes)\n",
           pkt_ctx->psp_cfg.transport_crypt_off,
           pkt_ctx->psp_cfg.transport_crypt_off * PSP_CRYPT_OFFSET_UNITS);
    fflush(stdout);
  }

  if (fscanf(fp, "%hhu", &pkt_ctx->psp_cfg.ipv4_tunnel_crypt_off) != 1) {
    fprintf(stderr,
            "read of ipv4 tunnel crypt offset from psp_cfg_file failed\n");
    goto err_exit;
  }
  if (pkt_ctx->psp_cfg.ipv4_tunnel_crypt_off > PSP_CRYPT_OFFSET_MAX) {
    fprintf(stderr,
            "invalid ipv4 tunnel crypt offset in psp_cfg_file: "
            "value = %hhu, max value = %d\n",
            pkt_ctx->psp_cfg.ipv4_tunnel_crypt_off, PSP_CRYPT_OFFSET_MAX);
    goto err_exit;
  }

  if (verbose) {
    printf("Tunnel Mode IPv4 Crypt Offset: %hhu (%u bytes)\n",
           pkt_ctx->psp_cfg.ipv4_tunnel_crypt_off,
           pkt_ctx->psp_cfg.ipv4_tunnel_crypt_off * PSP_CRYPT_OFFSET_UNITS);
    fflush(stdout);
  }

  if (fscanf(fp, "%hhu", &pkt_ctx->psp_cfg.ipv6_tunnel_crypt_off) != 1) {
    fprintf(stderr,
            "read of ipv6 tunnel crypt offset from psp_cfg_file failed\n");
    goto err_exit;
  }
  if (pkt_ctx->psp_cfg.ipv6_tunnel_crypt_off > PSP_CRYPT_OFFSET_MAX) {
    fprintf(stderr,
            "invalid ipv6 tunnel crypt offset in psp_cfg_file: "
            "value = %hhu, max value = %d\n",
            pkt_ctx->psp_cfg.ipv6_tunnel_crypt_off, PSP_CRYPT_OFFSET_MAX);
    goto err_exit;
  }

  if (verbose) {
    printf("Tunnel Mode IPv6 Crypt Offset: %hhu (%u bytes)\n",
           pkt_ctx->psp_cfg.ipv6_tunnel_crypt_off,
           pkt_ctx->psp_cfg.ipv6_tunnel_crypt_off * PSP_CRYPT_OFFSET_UNITS);
    fflush(stdout);
  }

  if (fscanf(fp, "%15s", string) != 1) {
    fprintf(stderr, "read of vc string from psp_cfg_file failed\n");
    goto err_exit;
  }
  if (strcmp(string, "vc") == 0) {
    pkt_ctx->psp_cfg.include_vc = true;
  } else if (strcmp(string, "no-vc") == 0) {
    pkt_ctx->psp_cfg.include_vc = false;
  } else {
    fprintf(stderr, "invalid vc string in psp_cfg_file\n");
    goto err_exit;
  }

  if (verbose) {
    printf("VC Mode: %s\n", string);
    fflush(stdout);
  }

  fclose(fp);
  return SUCCESS_RC;

err_exit:
  if (fp != NULL) fclose(fp);
  return ERR_RC;
}

/* get next psp initialization vector */
static inline uint64_t get_psp_iv(struct pkt_context *pkt_ctx) {
  uint64_t iv;

  iv = HTONLL(pkt_ctx->next_iv);
  pkt_ctx->next_iv++;
  return iv;
}

/*
 * derive 128b of psp encryption key
 *
 * parms:
 *   pkt_ctx: ptr to pcaket context struct
 *   counter: 1 => derive first 128b of key
 *            2 => derive second 128b of key
 *   derived_key: ptr to location where derived ket is returned
 *
 * returns:
 *   SUCCESS_RC: key derived successfully
 *   ERR_RC:     error deriving key
 */
static rc_t derive_psp_key_128(struct pkt_context *pkt_ctx, uint8_t counter,
                               uint8_t *derived_key) {
  CMAC_CTX *ctx = NULL;
  uint32_t spi;
  struct psp_key_derivation_block input_block;
  size_t key_len, input_block_len, final_len;
  const void *key;

  spi = pkt_ctx->psp_cfg.spi;
  input_block_len = (size_t)PSP_KEY_DERIVATION_BLOCK_OCTETS;
  input_block.octets[0] = 0x00;
  input_block.octets[1] = 0x00;
  input_block.octets[2] = 0x00;
  input_block.octets[3] = counter;
  input_block.octets[4] = 0x50;
  input_block.octets[5] = 0x76;
  if (pkt_ctx->psp_cfg.crypto_alg == AES_GCM_128) {
    input_block.octets[6] = 0x30;
    input_block.octets[14] = 0x00;
    input_block.octets[15] = 0x80;
  } else {
    input_block.octets[6] = 0x31;
    input_block.octets[14] = 0x01;
    input_block.octets[15] = 0x00;
  }
  input_block.octets[7] = 0x00;
  input_block.octets[8] = (spi >> 24) & 0xff;
  input_block.octets[9] = (spi >> 16) & 0xff;
  input_block.octets[10] = (spi >> 8) & 0xff;
  input_block.octets[11] = spi & 0xff;
  input_block.octets[12] = 0x00;
  input_block.octets[13] = 0x00;

  if (spi & PSP_SPI_KEY_SELECTOR_BIT)
    key = (const void *)pkt_ctx->psp_cfg.master_key1.octets;
  else
    key = (const void *)pkt_ctx->psp_cfg.master_key0.octets;
  key_len = (size_t)AES_256_KEY_OCTETS;

  ctx = CMAC_CTX_new();
  if (ctx == NULL) {
    fprintf(stderr, "CMAC_CTX_new() failed\n");
    goto err_exit;
  }

  if (!CMAC_Init(ctx, key, key_len, EVP_aes_256_cbc(), NULL)) {
    fprintf(stderr, "CMAC_Init() failed\n");
    goto err_exit;
  }

  if (!CMAC_Update(ctx, (const uint8_t *)input_block.octets, input_block_len)) {
    fprintf(stderr, "CMAC_Update() failed\n");
    goto err_exit;
  }

  if (!CMAC_Final(ctx, derived_key, &final_len)) {
    fprintf(stderr, "CMAC_Final() failed\n");
    goto err_exit;
  }

  CMAC_CTX_free(ctx);
  return SUCCESS_RC;

err_exit:
  if (ctx != NULL) CMAC_CTX_free(ctx);
  return ERR_RC;
}

/*
 * derive psp encryption key
 *
 * returns:
 *   SUCCESS_RC: derived key is returned in packet context structure
 *   ERR_RC:     error deriving key
 */
static rc_t derive_psp_key(struct pkt_context *pkt_ctx) {
  rc_t rc;

  rc = derive_psp_key_128(pkt_ctx, (uint8_t)1, pkt_ctx->key.octets);
  if ((rc != SUCCESS_RC) || (pkt_ctx->psp_cfg.crypto_alg == AES_GCM_128))
    return rc;
  return derive_psp_key_128(
      pkt_ctx, (uint8_t)2,
      &pkt_ctx->key.octets[PSP_KEY_DERIVATION_BLOCK_OCTETS]);
}

/*
 * perform psp encryption
 *
 * the code for this function is based off an example on the
 * OpenSSL website (see https://wiki.openssl.org/images/0/08/Evp-gcm-encrypt.c)
 *
 * parms:
 *   pkt_ctx: ptr to context info for packet
 *   psp: ptr to psp header of packet,
 *        aes_cgm iv is spi concatenated with psp iv,
 *        this is also start of additional authentication data
 *   cleartext_len: length of cleartext to be encrypted in octets
 *   cleartext: ptr to cleartext to encrypt
 *   aad_len: length of additional authentication data
 *   ciphertext: ptr to location where encrypted data is to be returned
 *   icv: ptr to location where integrity check value is to be returned
 *
 * returns:
 *   PKT_ENCRYPTED
 *   PKT_ERR
 * */
static pkt_rc_t psp_encrypt(struct pkt_context *pkt_ctx, struct psp_hdr *psp,
                            uint32_t cleartext_len, uint8_t *cleartext,
                            uint32_t aad_len, uint8_t *ciphertext,
                            struct psp_icv *icv) {
  int rc, len;
  uint8_t *aad = (uint8_t *)psp;
  struct aes_gcm_iv gcm_iv;
  EVP_CIPHER_CTX *ctx = NULL;

  memcpy(gcm_iv.octets, &psp->spi, PSP_SPI_OCTETS);
  memcpy(&gcm_iv.octets[PSP_SPI_OCTETS], &psp->iv, PSP_IV_OCTETS);

  /* create and initialize the cipher context */
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    fprintf(stderr, "EVP_CIPHER_CTX_new() failed\n");
    goto err_exit;
  }

  /* initialize the encryption operation */
  if (pkt_ctx->psp_cfg.crypto_alg == AES_GCM_128)
    rc = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
  else
    rc = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
  if (rc != 1) {
    fprintf(stderr, "EVP_EncryptInit_ex() failed\n");
    goto err_exit;
  }

  /* initialize key and iv */
  if (EVP_EncryptInit_ex(ctx, NULL, NULL, pkt_ctx->key.octets, gcm_iv.octets) !=
      1) {
    fprintf(stderr, "EVP_EncryptInit_ex() failed\n");
    goto err_exit;
  }

  /* provide additional authentication data */
  if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
    fprintf(stderr, "EVP_EncryptUpdate() failed\n");
    goto err_exit;
  }

  /* do encryption */
  if (EVP_EncryptUpdate(ctx, ciphertext, &len, cleartext, cleartext_len) != 1) {
    fprintf(stderr, "EVP_EncryptUpdate() failed\n");
    goto err_exit;
  }

  /* finalize encryption */
  if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
    fprintf(stderr, "EVP_EncryptFinal_ex() failed\n");
    goto err_exit;
  }

  /* get the icv */
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, PSP_ICV_OCTETS,
                          icv->octets) != 1) {
    fprintf(stderr, "EVP_CIPHER_CTX_ctrl() failed\n");
    goto err_exit;
  }

  EVP_CIPHER_CTX_free(ctx);
  return PKT_ENCRYPTED;

err_exit:
  if (ctx != NULL) EVP_CIPHER_CTX_free(ctx);
  return PKT_ERR;
}

/* perform transport mode psp encapsulation */
static pkt_rc_t transport_encap(struct pkt_context *pkt_ctx) {
  struct eth_hdr *eth;
  struct ipv4_hdr *ipv4, *out_ipv4;
  struct ipv6_hdr *ipv6, *out_ipv6;
  struct udp_hdr *psp_udp;
  struct psp_hdr *psp;
  struct psp_icv *out_icv;
  uint8_t *ip_proto, *in_pkt, *out_pkt, *out_l4, *buf, *in_encrypt,
      *out_encrypt, psp_ver;
  uint16_t etype, ip_len, *in_l4, sport, dport;
  uint32_t pkt_len, max_len, eth_hdr_len, ip_hdr_len, ip_payload_len,
      udp_hdr_len, vc_octets, psp_encap_octets, base_psp_hdr_len, psp_hdr_len,
      psp_payload_len, crypt_off, crypt_off_after_ext, encrypt_len, aad_len;
  uint64_t *vc;
  pkt_rc_t pkt_rc;

  in_pkt = pkt_ctx->in_pkt;
  eth = (struct eth_hdr *)in_pkt;
  eth_hdr_len = pkt_ctx->eth_hdr_len;
  pkt_len = pkt_ctx->in_pcap_pkt_hdr->len;
  max_len = pkt_ctx->max_pkt_octets - PSP_TRANSPORT_ENCAP_OCTETS;

  if (pkt_len > max_len) {
    fprintf(stderr, "invalid packet, too big, %u bytes\n", pkt_len);
    return PKT_ERR;
  }

  etype = ntohs(eth->etype);
  if (etype == IPV4_ETYPE) {
    ipv4 = (struct ipv4_hdr *)(in_pkt + eth_hdr_len);
    ip_proto = &ipv4->proto;
    ip_hdr_len = (ipv4->ver_ihl & IPV4_IHL_MASK) * IPV4_IHL_UNITS;
    psp_payload_len = pkt_len - (eth_hdr_len + ip_hdr_len);
  } else {
    ipv6 = (struct ipv6_hdr *)(in_pkt + eth_hdr_len);
    ip_proto = &ipv6->proto;
    switch (*ip_proto) {
      case IP_PROTO_UDP:
      case IP_PROTO_TCP:
        ip_hdr_len = sizeof(struct ipv6_hdr);
        psp_payload_len = pkt_len - (eth_hdr_len + ip_hdr_len);
        break;
      default:
        return PKT_SKIPPED;
    }
  }
  ip_payload_len = pkt_len - (eth_hdr_len + ip_hdr_len);

  crypt_off = pkt_ctx->psp_cfg.transport_crypt_off * PSP_CRYPT_OFFSET_UNITS;
  if (crypt_off > psp_payload_len) {
    fprintf(stderr, "skipping packet, crypt offset too big\n");
    return PKT_SKIPPED;
  }

  /*
   * build the psp-encapsulated packet
   *   - copy the eth and ip headers of input packet
   *   - insert the psp udp header
   *   - insert the psp header
   *   - copy crypt_off bytes from input packet starting at l4 header
   *   - compute icv and insert encrypted data
   *   - insert icv as psp trailer
   */
  out_pkt = pkt_ctx->out_pkt;
  memcpy(out_pkt, eth, eth_hdr_len + ip_hdr_len);

  if (pkt_ctx->psp_cfg.include_vc)
    vc_octets = PSP_HDR_VC_OCTETS;
  else
    vc_octets = 0;

  if (crypt_off > vc_octets)
    crypt_off_after_ext = crypt_off - vc_octets;
  else
    crypt_off_after_ext = 0;

  base_psp_hdr_len = sizeof(struct psp_hdr);
  psp_hdr_len = base_psp_hdr_len + vc_octets;
  psp_encap_octets = PSP_TRANSPORT_ENCAP_OCTETS + vc_octets;

  if (etype == IPV4_ETYPE) {
    ip_len = ntohs(ipv4->len);
    out_ipv4 = (struct ipv4_hdr *)(out_pkt + eth_hdr_len);
    out_ipv4->len = htons(ip_len + psp_encap_octets);
    out_ipv4->proto = IP_PROTO_UDP;
    out_ipv4->csum = 0;
    out_ipv4->csum = ipv4_hdr_csum(out_ipv4);
  } else {
    ip_len = ntohs(ipv6->plen);
    out_ipv6 = (struct ipv6_hdr *)(out_pkt + eth_hdr_len);
    out_ipv6->plen = htons(ip_len + psp_encap_octets);
    out_ipv6->proto = IP_PROTO_UDP;
  }

  psp_udp = (struct udp_hdr *)(out_pkt + eth_hdr_len + ip_hdr_len);
  in_l4 = (uint16_t *)(in_pkt + eth_hdr_len + ip_hdr_len);
  switch (*ip_proto) {
    case IP_PROTO_UDP:
    case IP_PROTO_TCP:
      /* set psp udp sport to simple hash of */
      /* port numbers from inner packet      */
      sport = ntohs(in_l4[0]);
      dport = ntohs(in_l4[1]);
      psp_udp->sport = htons(sport ^ dport);
      break;
    default:
      psp_udp->sport = htons(UDP_PORT_PSP);
      break;
  }
  psp_udp->dport = htons(UDP_PORT_PSP);
  psp_udp->len = htons(psp_payload_len + psp_encap_octets);
  psp_udp->csum = 0;
  udp_hdr_len = sizeof(struct udp_hdr);

  psp = (struct psp_hdr *)(((uint8_t *)psp_udp) + udp_hdr_len);
  psp->next_hdr = *ip_proto;
  if (pkt_ctx->psp_cfg.crypto_alg == AES_GCM_128)
    psp_ver = PSP_VER0;
  else
    psp_ver = PSP_VER1;
  if (pkt_ctx->psp_cfg.include_vc) {
    psp->hdr_ext_len = PSP_HDR_EXT_LEN_WITH_VC;
    psp->s_d_ver_v_1 =
        (psp_ver << PSP_HDR_VER_SHIFT) | PSP_HDR_FLAG_V | PSP_HDR_ALWAYS_1;
    vc = (uint64_t *)(((uint8_t *)psp) + base_psp_hdr_len);
    *vc = 0;
  } else {
    psp->hdr_ext_len = PSP_HDR_EXT_LEN_MIN;
    psp->s_d_ver_v_1 = (psp_ver << PSP_HDR_VER_SHIFT) | PSP_HDR_ALWAYS_1;
  }
  psp->crypt_off = pkt_ctx->psp_cfg.transport_crypt_off;
  psp->spi = htonl(pkt_ctx->psp_cfg.spi);
  psp->iv = get_psp_iv(pkt_ctx);

  out_l4 = ((uint8_t *)psp) + psp_hdr_len;
  memcpy(out_l4, in_l4, crypt_off_after_ext);

  /* build buffer for icv/encryption computation */
  buf = pkt_ctx->scratch_buf;
  memcpy(buf, psp, psp_hdr_len);
  memcpy(buf + psp_hdr_len, in_l4, ip_payload_len);

  /* compute icv and do encryption */
  in_encrypt = buf + base_psp_hdr_len + crypt_off;
  out_encrypt = ((uint8_t *)psp) + base_psp_hdr_len + crypt_off;
  encrypt_len = vc_octets + ip_payload_len - crypt_off;
  aad_len = base_psp_hdr_len + crypt_off;
  out_icv = (struct psp_icv *)(out_encrypt + encrypt_len);
  pkt_rc = psp_encrypt(pkt_ctx, psp, encrypt_len, in_encrypt, aad_len,
                       out_encrypt, out_icv);
  if (pkt_rc != PKT_ENCRYPTED) return pkt_rc;

  /* force corruption error if requested */
  if (force_corruption == true)
    psp->crypt_off |= PSP_CRYPT_OFFSET_RESERVED_BIT7;

  /* set pcap packet header fields for output packet */
  pkt_len += psp_encap_octets;
  pkt_ctx->out_pcap_pkt_hdr.caplen = pkt_len;
  pkt_ctx->out_pcap_pkt_hdr.len = pkt_len;
  pkt_ctx->out_pcap_pkt_hdr.ts = pkt_ctx->in_pcap_pkt_hdr->ts;

  return PKT_ENCRYPTED;
}

/* perform tunnel mode psp encapsulation */
static pkt_rc_t tunnel_encap(struct pkt_context *pkt_ctx) {
  struct eth_hdr *eth;
  struct ipv4_hdr *ipv4, *tunnel_ipv4;
  struct ipv6_hdr *ipv6, *tunnel_ipv6;
  struct udp_hdr *psp_udp;
  struct psp_hdr *psp;
  struct psp_icv *icv;
  uint8_t *ip_proto, *in_pkt, *out_pkt, *in_l3, *out_l3, *buf, *in_encrypt,
      *out_encrypt, psp_next_hdr, psp_ver;
  uint16_t etype, ip_len, *in_l4, sport, dport;
  uint32_t pkt_len, psp_encap_octets, max_len, eth_hdr_len, ip_hdr_len,
      udp_hdr_len, base_psp_hdr_len, vc_octets, psp_hdr_len, psp_payload_len,
      crypt_off, crypt_off_after_ext, encrypt_len, aad_len;
  uint64_t *vc;
  pkt_rc_t pkt_rc;

  in_pkt = pkt_ctx->in_pkt;
  eth = (struct eth_hdr *)in_pkt;
  eth_hdr_len = pkt_ctx->eth_hdr_len;
  etype = ntohs(eth->etype);
  pkt_len = pkt_ctx->in_pcap_pkt_hdr->len;
  psp_payload_len = pkt_len - eth_hdr_len;

  if (pkt_ctx->psp_cfg.include_vc)
    vc_octets = PSP_HDR_VC_OCTETS;
  else
    vc_octets = 0;

  if (etype == IPV4_ETYPE) {
    ipv4 = (struct ipv4_hdr *)(((uint8_t *)eth) + eth_hdr_len);
    ip_proto = &ipv4->proto;
    ip_hdr_len = (ipv4->ver_ihl & IPV4_IHL_MASK) * IPV4_IHL_UNITS;
    ip_len = ntohs(ipv4->len);
    psp_encap_octets = PSP_V4_TUNNEL_ENCAP_OCTETS + vc_octets;
    psp_next_hdr = IP_PROTO_IPV4;
    crypt_off = pkt_ctx->psp_cfg.ipv4_tunnel_crypt_off * PSP_CRYPT_OFFSET_UNITS;
  } else {
    ipv6 = (struct ipv6_hdr *)(((uint8_t *)eth) + eth_hdr_len);
    switch (ipv6->proto) {
      case IP_PROTO_UDP:
      case IP_PROTO_TCP:
        ip_proto = &ipv6->proto;
        ip_hdr_len = sizeof(struct ipv6_hdr);
        ip_len = ntohs(ipv6->plen);
        psp_encap_octets = PSP_V6_TUNNEL_ENCAP_OCTETS + vc_octets;
        psp_next_hdr = IP_PROTO_IPV6;
        crypt_off =
            pkt_ctx->psp_cfg.ipv6_tunnel_crypt_off * PSP_CRYPT_OFFSET_UNITS;
        break;
      default:
        fprintf(stderr,
                "skipping IPv6 packet, next proto not "
                "TCP or UDP, next proto = 0x%x\n",
                ipv6->proto);
        return PKT_SKIPPED;
    }
  }

  max_len = pkt_ctx->max_pkt_octets - psp_encap_octets;

  if (pkt_len > max_len) {
    fprintf(stderr, "invalid packet, too big, %u bytes\n", pkt_len);
    return PKT_ERR;
  }

  if (crypt_off > psp_payload_len) {
    fprintf(stderr, "skipping packet, crypt offset too big\n");
    return PKT_SKIPPED;
  }

  /*
   * build the psp-encapsulated packet
   *   - copy the eth header of input packet
   *   - insert ip header based on ip header of input packet
   *   - insert the psp udp header
   *   - insert the psp header
   *   - copy data from input packet starting at l3 header
   *   - compute icv and encrypt data
   *   - insert icv as the psp trailer
   */
  out_pkt = pkt_ctx->out_pkt;
  memcpy(out_pkt, eth, eth_hdr_len);

  if (crypt_off > vc_octets)
    crypt_off_after_ext = crypt_off - vc_octets;
  else
    crypt_off_after_ext = 0;

  base_psp_hdr_len = sizeof(struct psp_hdr);
  psp_hdr_len = base_psp_hdr_len + vc_octets;

  if (etype == IPV4_ETYPE) {
    tunnel_ipv4 = (struct ipv4_hdr *)(out_pkt + eth_hdr_len);
    memcpy(tunnel_ipv4, ipv4, sizeof(struct ipv4_hdr));
    tunnel_ipv4->ver_ihl = IPV4_VER_IHL;
    tunnel_ipv4->len = htons(ip_len + psp_encap_octets);
    tunnel_ipv4->proto = IP_PROTO_UDP;
    tunnel_ipv4->csum = 0;
    tunnel_ipv4->csum = ipv4_hdr_csum(tunnel_ipv4);
  } else {
    tunnel_ipv6 = (struct ipv6_hdr *)(out_pkt + eth_hdr_len);
    memcpy(tunnel_ipv6, ipv6, sizeof(struct ipv6_hdr));
    tunnel_ipv6->plen = htons(ip_len + psp_encap_octets);
    tunnel_ipv6->proto = IP_PROTO_UDP;
  }

  psp_udp = (struct udp_hdr *)(out_pkt + eth_hdr_len + ip_hdr_len);
  in_l4 = (uint16_t *)(in_pkt + eth_hdr_len + ip_hdr_len);
  switch (*ip_proto) {
    case IP_PROTO_UDP:
    case IP_PROTO_TCP:
      /* set psp udp sport to simple hash of */
      /* port numbers from inner packet      */
      sport = ntohs(in_l4[0]);
      dport = ntohs(in_l4[1]);
      psp_udp->sport = htons(sport ^ dport);
      break;
    default:
      psp_udp->sport = htons(UDP_PORT_PSP);
      break;
  }
  psp_udp->dport = htons(UDP_PORT_PSP);
  psp_udp->len =
      htons(psp_payload_len + PSP_TRANSPORT_ENCAP_OCTETS + vc_octets);
  psp_udp->csum = 0;
  udp_hdr_len = sizeof(struct udp_hdr);

  psp = (struct psp_hdr *)(((uint8_t *)psp_udp) + udp_hdr_len);
  psp->next_hdr = psp_next_hdr;
  if (pkt_ctx->psp_cfg.crypto_alg == AES_GCM_128)
    psp_ver = PSP_VER0;
  else
    psp_ver = PSP_VER1;
  if (pkt_ctx->psp_cfg.include_vc) {
    psp->hdr_ext_len = PSP_HDR_EXT_LEN_WITH_VC;
    psp->s_d_ver_v_1 =
        (psp_ver << PSP_HDR_VER_SHIFT) | PSP_HDR_FLAG_V | PSP_HDR_ALWAYS_1;
    vc = (uint64_t *)(((uint8_t *)psp) + base_psp_hdr_len);
    *vc = 0;
    psp_hdr_len = base_psp_hdr_len + PSP_HDR_VC_OCTETS;
  } else {
    psp->hdr_ext_len = PSP_HDR_EXT_LEN_MIN;
    psp->s_d_ver_v_1 = (psp_ver << PSP_HDR_VER_SHIFT) | PSP_HDR_ALWAYS_1;
    psp_hdr_len = base_psp_hdr_len;
  }
  psp->crypt_off = crypt_off / PSP_CRYPT_OFFSET_UNITS;
  psp->spi = htonl(pkt_ctx->psp_cfg.spi);
  psp->iv = get_psp_iv(pkt_ctx);

  in_l3 = (((uint8_t *)eth) + eth_hdr_len);
  out_l3 = ((uint8_t *)psp) + psp_hdr_len;
  memcpy(out_l3, in_l3, crypt_off_after_ext);

  /* build buffer for icv/encryption computation */
  buf = pkt_ctx->scratch_buf;
  memcpy(buf, psp, psp_hdr_len);
  memcpy(buf + psp_hdr_len, in_l3, psp_payload_len);

  /* compute icv and do encryption */
  in_encrypt = buf + base_psp_hdr_len + crypt_off;
  out_encrypt = ((uint8_t *)psp) + base_psp_hdr_len + crypt_off;
  encrypt_len = vc_octets + psp_payload_len - crypt_off;
  aad_len = base_psp_hdr_len + crypt_off;
  icv = (struct psp_icv *)(out_encrypt + encrypt_len);
  pkt_rc = psp_encrypt(pkt_ctx, psp, encrypt_len, in_encrypt, aad_len,
                       out_encrypt, icv);
  if (pkt_rc != PKT_ENCRYPTED) return pkt_rc;

  /* force corruption error if requested */
  if (force_corruption == true)
    psp->crypt_off |= PSP_CRYPT_OFFSET_RESERVED_BIT7;

  /* set pcap packet header fields for output packet */
  pkt_len += psp_encap_octets;
  pkt_ctx->out_pcap_pkt_hdr.caplen = pkt_len;
  pkt_ctx->out_pcap_pkt_hdr.len = pkt_len;
  pkt_ctx->out_pcap_pkt_hdr.ts = pkt_ctx->in_pcap_pkt_hdr->ts;

  return PKT_ENCRYPTED;
}

/* process packet read from input pcap file */
static pkt_rc_t process_in_pkt(struct pkt_context *pkt_ctx) {
  struct eth_hdr *eth;
  uint16_t etype;

  if (pkt_ctx->in_pcap_pkt_hdr->caplen != pkt_ctx->in_pcap_pkt_hdr->len) {
    fprintf(stderr, "partial packet captures not supported\n");
    return PKT_ERR;
  }

  eth = (struct eth_hdr *)pkt_ctx->in_pkt;
  etype = ntohs(eth->etype);
  switch (etype) {
    case IPV4_ETYPE:
    case IPV6_ETYPE:
      pkt_ctx->eth_hdr_len = sizeof(struct eth_hdr);
      break;
    default:
      fprintf(stderr, "skipping non-IP packet, etype = 0x%x\n", etype);
      return PKT_SKIPPED;
  }

  if (pkt_ctx->psp_cfg.psp_encap == PSP_TRANSPORT)
    return transport_encap(pkt_ctx);
  return tunnel_encap(pkt_ctx);
}

int main(int argc, char *argv[]) {
  int i, opt, n = 0, skipped = 0, rc = EXIT_SUCCESS, pcap_rc;
  pkt_rc_t pkt_rc;
  pcap_t *in_pd = NULL, *out_pd = NULL;
  pcap_dumper_t *pdumper = NULL;
  char *in_pcap_file = DEFAULT_CLEARTEXT_PCAP_FILE,
       *out_pcap_file = DEFAULT_ENCRYPT_PCAP_FILE,
       *cfg_file = DEFAULT_ENCRYPT_CFG_FILE;
  struct stat stat_buf;
  struct pkt_context pkt_ctx;

  pkt_ctx.max_pkt_octets = ETH_JUMBO_MAX_OCTETS;
  pkt_ctx.out_pkt = NULL;
  pkt_ctx.next_iv = PSP_INITIAL_IV;
  pkt_ctx.scratch_buf = NULL;

  /* handle command line args */
  while ((opt = getopt(argc, argv, "c:i:o:ve")) != -1) {
    switch (opt) {
      case 'c':
        cfg_file = optarg;
        break;
      case 'i':
        in_pcap_file = optarg;
        break;
      case 'o':
        out_pcap_file = optarg;
        break;
      case 'v':
        verbose = true;
        break;
      case 'e':
        force_corruption = true;
        break;
      default:
        fprintf(stderr,
                "Usage: %s [-c cfg_file] [-i in_file] "
                "[-o out_file] [-e]\n",
                argv[0]);
        goto err_exit;
        break;
    }
  }

  if (verbose) {
    printf("starting %s\n", argv[0]);
    fflush(stdout);
  }

  /* read psp config file */
  if (get_psp_cfg(cfg_file, &pkt_ctx) != SUCCESS_RC) goto err_exit;

  /* derive psp encryption key */
  if (derive_psp_key(&pkt_ctx) != SUCCESS_RC) goto err_exit;

  if (verbose) {
    printf("Derived Key:\n  ");
    for (i = 0; i < PSP_KEY_DERIVATION_BLOCK_OCTETS; i++)
      printf("%02hhx ", pkt_ctx.key.octets[i]);
    if (pkt_ctx.psp_cfg.crypto_alg == AES_GCM_256) {
      for (i = 0; i < PSP_KEY_DERIVATION_BLOCK_OCTETS; i++)
        printf("%02hhx ",
               pkt_ctx.key.octets[PSP_KEY_DERIVATION_BLOCK_OCTETS + i]);
    }
    printf("\n");
    fflush(stdout);
  }

  /* open output pcap file */
  out_pd = pcap_open_dead(DLT_EN10MB, pkt_ctx.max_pkt_octets);
  if (out_pd == NULL) {
    fprintf(stderr, "pcap_open_dead() failed\n");
    goto err_exit;
  }

  pdumper = pcap_dump_open(out_pd, out_pcap_file);
  if (pdumper == NULL) {
    fprintf(stderr, "pcap_dump_open() failed\n");
    goto err_exit;
  }

  /* open input pcap file */
  if (stat(in_pcap_file, &stat_buf) != 0) {
    fprintf(stderr, "stat() failed for %s\n", in_pcap_file);
    goto err_exit;
  }
  in_pd = pcap_open_offline(in_pcap_file, NULL);
  if (in_pd == NULL) {
    fprintf(stderr, "pcap_open_offline() failed\n");
    goto err_exit;
  }

  /* allocate packet buffers */
  pkt_ctx.out_pkt = calloc(1, pkt_ctx.max_pkt_octets);
  if (pkt_ctx.out_pkt == NULL) {
    fprintf(stderr, "calloc() failed\n");
    goto err_exit;
  }

  pkt_ctx.scratch_buf = calloc(1, pkt_ctx.max_pkt_octets);
  if (pkt_ctx.scratch_buf == NULL) {
    fprintf(stderr, "calloc() failed\n");
    goto err_exit;
  }

  /* process packets from input pcap file */
  while (1) {
    pcap_rc = pcap_next_ex(in_pd, &pkt_ctx.in_pcap_pkt_hdr,
                           (const u_char **)&pkt_ctx.in_pkt);
    if (pcap_rc == 1) {
      /* packet read without error from pcap file */
      pkt_rc = process_in_pkt(&pkt_ctx);
      if (pkt_rc == PKT_ERR) {
        goto err_exit;
      } else if (pkt_rc == PKT_SKIPPED) {
        skipped++;
      } else {
        /* write encrypted packet to output pcap file */
        pcap_dump((u_char *)pdumper, &pkt_ctx.out_pcap_pkt_hdr,
                  (u_char *)pkt_ctx.out_pkt);
        n++;
      }
    } else if (pcap_rc == PCAP_ERROR_BREAK) {
      /* no more packets to read */
      break;
    } else {
      pcap_perror(in_pd, "pcap_next_ex() failed");
      goto err_exit;
    }
  }

  printf("encrypted %d packets in %s, skipped %d packets\n", n, out_pcap_file,
         skipped);
  goto exit;

err_exit:
  fflush(stdout);
  fprintf(stderr, "psp encryption failed\n");
  fflush(stderr);
  rc = EXIT_FAILURE;

exit:
  free(pkt_ctx.scratch_buf);
  free(pkt_ctx.out_pkt);
  if (pdumper != NULL) pcap_dump_close(pdumper);
  if (out_pd != NULL) pcap_close(out_pd);
  if (in_pd != NULL) pcap_close(in_pd);

  exit(rc);
}
