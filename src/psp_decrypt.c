/*
 * Program to perform PSP decryption
 *
 * Reads PSP-encrypted packets from a pcap input file
 *
 * Performs the following for each packet:
 *   - Removes the PSP encapsulation (supports transport and tunnel encaps)
 *   - Checks that ICV is correct
 *   - Decrypts data
 *
 * Then writes each cleartext packet to a pcap output
 *
 * Command Line Args:
 * 	[-c psp_cfg_file_name] [-i input_file_name] [-o output_file_name] [-v]
 *
 *      -v enables verbose mode
 *
 *      Defaults:
 *      	psp_cfg_file:     "psp_decrypt.cfg"
 *      	input_file_name:  "psp_encrypt.pcap"
 *      	output_file_name: "psp_decrypt.pcap"
 *
 * The format of the PSP encryption configuration file is:
 *   series of 32 hex bytes (e.g., 34 44 8a ...):  Master Key 0
 *   series of 32 hex bytes (e.g., 56 39 52 ...):  Master Key 1
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
               PKT_DECRYPTED, /* success */
               PKT_SKIPPED,   /* packet not decrypted */
               PKT_ERR
} pkt_rc_t;

struct psp_decrypt_cfg { /* decryption config parms */
  struct psp_master_key master_key0;
  struct psp_master_key master_key1;
};

/*
 * context info associated with packet
 *
 * passed as parm to packet processing functions
 *
 * fields:
 *   max_pkt_octets: max packet size supported
 *   psp_cfg: psp decryption config parms
 *   crypto_alg: crypto algorithm to use
 *   derived: derived psp encryption key
 *   in_pcap_pkt_hdr: ptr to pcap_pkt_hdr for input packet
 *   in_pkt: ptr to input packet
 *   psp: ptr to psp header of input packet
 *   out_pcap_pkt_hdr: pcap_pkt_hdr for output packet
 *   out_pkt: ptr to output packet
 *   scratch_buf: ptr to scratch packet buffer
 */
struct pkt_context {
  uint32_t max_pkt_octets;
  struct psp_decrypt_cfg psp_cfg;
  crypto_alg_t crypto_alg;
  struct psp_derived_key key;
  struct pcap_pkthdr *in_pcap_pkt_hdr;
  uint8_t *in_pkt;
  struct psp_hdr *psp;
  struct pcap_pkthdr out_pcap_pkt_hdr;
  uint8_t *out_pkt;
  uint8_t *scratch_buf;
};

bool verbose = false;

/*
 * get psp configuration by:
 *   - reading from configuration file,
 *   - parsing the configuration data, and
 *   - saving the results in the packet context structure
 */
static rc_t get_psp_cfg(char *cfg_file, struct pkt_context *pkt_ctx) {
  int i;
  FILE *fp;

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

  fclose(fp);
  return SUCCESS_RC;

err_exit:
  if (fp != NULL) fclose(fp);
  return ERR_RC;
}

/*
 * derive 128b of psp encryption key
 *
 * parms:
 *   pkt_ctx: ptr to pcaket context struct
 *   counter: 1 => derive first 128b of key
 *            2 => derive second 128b of key
 *   derived_key: ptr to location where derived key is returned
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

  spi = ntohl(pkt_ctx->psp->spi);
  input_block_len = (size_t)PSP_KEY_DERIVATION_BLOCK_OCTETS;
  input_block.octets[0] = 0x00;
  input_block.octets[1] = 0x00;
  input_block.octets[2] = 0x00;
  input_block.octets[3] = counter;
  input_block.octets[4] = 0x50;
  input_block.octets[5] = 0x76;
  if (pkt_ctx->crypto_alg == AES_GCM_128) {
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
  if ((rc != SUCCESS_RC) || (pkt_ctx->crypto_alg == AES_GCM_128)) return rc;
  return derive_psp_key_128(
      pkt_ctx, (uint8_t)2,
      &pkt_ctx->key.octets[PSP_KEY_DERIVATION_BLOCK_OCTETS]);
}

/*
 * perform psp decryption
 *
 * the code for this function is based off an example on the
 * OpenSSL website (see https://wiki.openssl.org/images/0/08/Evp-gcm-encrypt.c)
 *
 * parms:
 *   pkt_ctx: ptr to context info for packet
 *   ciphertext_len: length of encrypted data to be decrypted in octets
 *   ciphertext: ptr to encrypted data to decrypt
 *   aad_len: length of additional data to be authenticated in octets
 *   aad: ptr to additional data to authenticate
 *   cleartext: ptr to location where decrypted data is to be returned
 *   expected_icv: ptr to expected integrity check value
 *
 *
 * returns:
 *   PKT_DECRYPTED
 *   PKT_ERR
 * */
static pkt_rc_t psp_decrypt(struct pkt_context *pkt_ctx,
                            uint32_t ciphertext_len, uint8_t *ciphertext,
                            uint32_t aad_len, uint8_t *aad, uint8_t *cleartext,
                            struct psp_icv *expected_icv) {
  int rc, len;
  uint8_t psp_ver;
  uint32_t *spi;
  uint64_t *psp_iv;
  struct aes_gcm_iv gcm_iv;
  EVP_CIPHER_CTX *ctx = NULL;

  if (ciphertext_len == 0) return PKT_DECRYPTED;

  /* form aes-gsm iv */
  spi = &pkt_ctx->psp->spi;
  psp_iv = &pkt_ctx->psp->iv;
  memcpy(gcm_iv.octets, spi, PSP_SPI_OCTETS);
  memcpy(&gcm_iv.octets[PSP_SPI_OCTETS], psp_iv, PSP_IV_OCTETS);

  /* derive the key */
  rc = derive_psp_key(pkt_ctx);
  if (rc != SUCCESS_RC) goto err_exit;

  if (verbose) {
    int i;

    printf("Derived Key:\n  ");
    for (i = 0; i < PSP_KEY_DERIVATION_BLOCK_OCTETS; i++)
      printf("%02hhx ", pkt_ctx->key.octets[i]);
    if (pkt_ctx->crypto_alg == AES_GCM_256) {
      for (i = 0; i < PSP_KEY_DERIVATION_BLOCK_OCTETS; i++)
        printf("%02hhx ",
               pkt_ctx->key.octets[PSP_KEY_DERIVATION_BLOCK_OCTETS + i]);
    }
    printf("\n");
    fflush(stdout);
  }

  /* create and initialize the cipher context */
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    fprintf(stderr, "EVP_CIPHER_CTX_new() failed\n");
    goto err_exit;
  }

  /* initialize the decryption operation */
  psp_ver = (pkt_ctx->psp->s_d_ver_v_1 >> PSP_HDR_VER_SHIFT) & PSP_HDR_VER_MASK;
  if (psp_ver == PSP_VER0)
    rc = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
  else
    rc = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
  if (rc != 1) {
    fprintf(stderr, "EVP_DecryptInit_ex() failed\n");
    goto err_exit;
  }

  /* initialize key and iv */
  if (EVP_DecryptInit_ex(ctx, NULL, NULL, pkt_ctx->key.octets, gcm_iv.octets) !=
      1) {
    fprintf(stderr, "EVP_DecryptInit_ex() failed\n");
    goto err_exit;
  }

  /* provide additional authentication data */
  if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
    fprintf(stderr, "EVP_DecryptUpdate() failed\n");
    goto err_exit;
  }

  /* do decryption */
  if (EVP_DecryptUpdate(ctx, cleartext, &len, ciphertext, ciphertext_len) !=
      1) {
    fprintf(stderr, "EVP_DecryptUpdate() failed\n");
    goto err_exit;
  }

  /* set the expected icv */
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, PSP_ICV_OCTETS,
                          expected_icv->octets) != 1) {
    fprintf(stderr, "EVP_CIPHER_CTX_ctrl() failed\n");
    goto err_exit;
  }

  /* finalize decryption */
  if (EVP_DecryptFinal_ex(ctx, cleartext + len, &len) < 1) {
    fprintf(stderr, "EVP_DecryptFinal_ex() failed\n");
    goto err_exit;
  }

  EVP_CIPHER_CTX_free(ctx);
  return PKT_DECRYPTED;

err_exit:
  if (ctx != NULL) EVP_CIPHER_CTX_free(ctx);
  return PKT_ERR;
}

/*
 * process packet read from input pcap file
 *   - parse the input packet and check for errors
 *   - decrypt and autheticate the packet
 *   - build cleartext packet without PSP encapsulation
 *
 * returns:
 *   PKT_DECRYPTED
 *   PKT_SKIPPED
 *   PKT_ERR
 */
static pkt_rc_t process_in_pkt(struct pkt_context *pkt_ctx) {
  struct eth_hdr *eth;
  struct ipv4_hdr *ipv4, *out_ipv4;
  struct ipv6_hdr *ipv6, *out_ipv6;
  struct udp_hdr *psp_udp;
  struct psp_hdr *psp;
  struct psp_icv *icv;
  uint8_t *ip_proto, *out_pkt, *after_base_psp_hdr, *after_ext_psp_hdr,
      *cipher_start, *aad, *out_cleartext;
  uint16_t etype, ip_len, strip_len, dport;
  uint32_t pkt_len, eth_hdr_len, ip_pkt_len, ip_hdr_len, udp_hdr_len,
      psp_hdr_len, hdr_ext_len, psp_trailer_len, psp_payload_len, psp_ver,
      crypt_off, crypt_off_after_ext, encrypted_ext_len, out_pkt_len,
      cipher_len, aad_len, cleartext_copy_len;
  crypto_alg_t crypto_alg;
  psp_encap_t psp_encap;
  pkt_rc_t pkt_rc;

  /* check input packet length */
  pkt_len = pkt_ctx->in_pcap_pkt_hdr->len;
  if (pkt_ctx->in_pcap_pkt_hdr->caplen != pkt_len) {
    fprintf(stderr, "partial packet captures not supported\n");
    return PKT_ERR;
  }

  if (pkt_len < ETH_MIN_OCTETS) {
    fprintf(stderr, "invalid packet, too small, %u bytes\n", pkt_len);
    return PKT_ERR;
  }

  if (pkt_len > pkt_ctx->max_pkt_octets) {
    fprintf(stderr, "invalid packet, too big, %u bytes\n", pkt_len);
    return PKT_ERR;
  }

  /* parse input packet */
  eth = (struct eth_hdr *)pkt_ctx->in_pkt;
  etype = ntohs(eth->etype);
  eth_hdr_len = sizeof(struct eth_hdr);
  ip_pkt_len = pkt_len - eth_hdr_len;
  switch (etype) {
    case IPV4_ETYPE:
      ipv4 = (struct ipv4_hdr *)(((uint8_t *)eth) + eth_hdr_len);
      ip_proto = &ipv4->proto;
      ip_hdr_len = (ipv4->ver_ihl & IPV4_IHL_MASK) * IPV4_IHL_UNITS;
      ip_len = ntohs(ipv4->len);
      if (ip_len != ip_pkt_len) {
        fprintf(stderr, "invalid packet, bad IP len\n");
        return PKT_ERR;
      }
      break;
    case IPV6_ETYPE:
      ipv6 = (struct ipv6_hdr *)(((uint8_t *)eth) + eth_hdr_len);
      ip_proto = &ipv6->proto;
      ip_hdr_len = sizeof(struct ipv6_hdr);
      ip_len = ntohs(ipv6->plen);
      if (((*ip_proto) == IP_PROTO_UDP) &&
          (ip_len != (ip_pkt_len - ip_hdr_len))) {
        fprintf(stderr, "invalid packet, bad IP len\n");
        return PKT_ERR;
      }
      break;
    default:
      fprintf(stderr, "skipping non-IP packet, etype = 0x%04x\n", etype);
      return PKT_SKIPPED;
  }

  if ((*ip_proto) != IP_PROTO_UDP) {
    fprintf(stderr, "skipping non-PSP packet, IP proto = 0x%02hhx\n",
            *ip_proto);
    return PKT_SKIPPED;
  }

  psp_udp = (struct udp_hdr *)(((uint8_t *)eth) + eth_hdr_len + ip_hdr_len);
  dport = ntohs(psp_udp->dport);
  if (dport != UDP_PORT_PSP) {
    fprintf(stderr, "skipping non-PSP packet, UDP dport = 0x%04hx\n", dport);
    return PKT_SKIPPED;
  }
  if (ntohs(psp_udp->len) != (pkt_len - (eth_hdr_len + ip_hdr_len))) {
    fprintf(stderr, "invalid packet, bad UDP len\n");
    return PKT_ERR;
  }
  udp_hdr_len = sizeof(struct udp_hdr);

  psp = (struct psp_hdr *)(((uint8_t *)psp_udp) + udp_hdr_len);
  pkt_ctx->psp = psp;
  psp_hdr_len = sizeof(struct psp_hdr);
  psp_trailer_len = sizeof(struct psp_trailer);
  /* including psp hdr ext in psp_payload_len */
  psp_payload_len = pkt_len - (eth_hdr_len + ip_hdr_len + udp_hdr_len +
                               psp_hdr_len + psp_trailer_len);
  hdr_ext_len =
      (psp->hdr_ext_len - PSP_HDR_EXT_LEN_MIN) * PSP_HDR_EXT_LEN_UNITS;
  if (hdr_ext_len > psp_payload_len) {
    fprintf(stderr, "invalid packet, hdr_ext_len exceeds packet size\n");
    return PKT_ERR;
  }

  crypt_off = (psp->crypt_off & PSP_CRYPT_OFFSET_MASK) * PSP_CRYPT_OFFSET_UNITS;
  if (crypt_off > psp_payload_len) {
    fprintf(stderr, "invalid packet, crypt offset too big, %u\n", crypt_off);
    return PKT_ERR;
  }

  psp_ver = (psp->s_d_ver_v_1 >> PSP_HDR_VER_SHIFT) & PSP_HDR_VER_MASK;
  switch (psp_ver) {
    case PSP_VER0:
      crypto_alg = AES_GCM_128;
      break;
    case PSP_VER1:
      crypto_alg = AES_GCM_256;
      break;
    default:
      fprintf(stderr, "invalid packet, unsupported PSP version, %u\n", psp_ver);
      return PKT_ERR;
  }
  pkt_ctx->crypto_alg = crypto_alg;

  if ((psp->s_d_ver_v_1 & PSP_HDR_ALWAYS_1) != PSP_HDR_ALWAYS_1) {
    fprintf(stderr,
            "invalid packet, invalid word 0 in PSP header, "
            "0x%08x\n",
            *((uint32_t *)psp));
    return PKT_ERR;
  }

  switch (psp->next_hdr) {
    case IP_PROTO_IPV4:
    case IP_PROTO_IPV6:
      psp_encap = PSP_TUNNEL;
      break;
    default:
      psp_encap = PSP_TRANSPORT;
      break;
  }

  /*
   * build the cleartext packet
   *   - copy the ethernet header of the input packet
   *   - if transport mode
   *   -   insert ip header based on ip header of input packet
   *   - copy data from input packet starting after psp header
   *   - check icv and decrypt data
   */
  out_pkt = pkt_ctx->out_pkt;
  memcpy(out_pkt, eth, eth_hdr_len);
  out_pkt += eth_hdr_len;

  if (psp_encap == PSP_TRANSPORT) {
    if (etype == IPV4_ETYPE) {
      memcpy(out_pkt, ipv4, ip_hdr_len);
      out_ipv4 = (struct ipv4_hdr *)out_pkt;
      strip_len = PSP_TRANSPORT_ENCAP_OCTETS + hdr_ext_len;
      out_ipv4->len = htons(ip_len - strip_len);
      out_ipv4->proto = psp->next_hdr;
      out_ipv4->csum = 0;
      out_ipv4->csum = ipv4_hdr_csum(out_ipv4);
    } else {
      memcpy(out_pkt, ipv6, ip_hdr_len);
      out_ipv6 = (struct ipv6_hdr *)out_pkt;
      strip_len = PSP_TRANSPORT_ENCAP_OCTETS + hdr_ext_len;
      out_ipv6->plen = htons(ip_len - strip_len);
      out_ipv6->proto = psp->next_hdr;
    }
    out_pkt += ip_hdr_len;
  }

  after_base_psp_hdr = ((uint8_t *)psp) + psp_hdr_len;
  after_ext_psp_hdr = after_base_psp_hdr + hdr_ext_len;
  if (crypt_off >= hdr_ext_len) {
    encrypted_ext_len = 0;
    crypt_off_after_ext = crypt_off - hdr_ext_len;
  } else {
    encrypted_ext_len = hdr_ext_len - crypt_off;
    crypt_off_after_ext = 0;
  }
  memcpy(out_pkt, after_ext_psp_hdr, crypt_off_after_ext);
  out_pkt += crypt_off_after_ext;

  cipher_start = after_base_psp_hdr + crypt_off;
  cipher_len = psp_payload_len - crypt_off;
  aad = (uint8_t *)psp;
  aad_len = psp_hdr_len + crypt_off;
  out_cleartext = pkt_ctx->scratch_buf;
  icv = (struct psp_icv *)(cipher_start + cipher_len);
  pkt_rc = psp_decrypt(pkt_ctx, cipher_len, cipher_start, aad_len, aad,
                       out_cleartext, icv);
  if (pkt_rc != PKT_DECRYPTED) return pkt_rc;
  cleartext_copy_len = cipher_len - encrypted_ext_len;
  memcpy(out_pkt, out_cleartext + encrypted_ext_len, cleartext_copy_len);
  out_pkt += cleartext_copy_len;

  /* set pcap packet header fields for output packet */
  out_pkt_len = out_pkt - pkt_ctx->out_pkt;
  pkt_ctx->out_pcap_pkt_hdr.caplen = out_pkt_len;
  pkt_ctx->out_pcap_pkt_hdr.len = out_pkt_len;
  pkt_ctx->out_pcap_pkt_hdr.ts = pkt_ctx->in_pcap_pkt_hdr->ts;

  return PKT_DECRYPTED;
}

int main(int argc, char *argv[]) {
  int opt, n = 0, skipped = 0, rc = EXIT_SUCCESS, pcap_rc;
  pkt_rc_t pkt_rc;
  pcap_t *in_pd = NULL, *out_pd = NULL;
  pcap_dumper_t *pdumper = NULL;
  char *in_pcap_file = DEFAULT_ENCRYPT_PCAP_FILE,
       *out_pcap_file = DEFAULT_DECRYPT_PCAP_FILE,
       *cfg_file = DEFAULT_DECRYPT_CFG_FILE;
  struct stat stat_buf;
  struct pkt_context pkt_ctx;

  pkt_ctx.max_pkt_octets = ETH_JUMBO_MAX_OCTETS;
  pkt_ctx.out_pkt = NULL;
  pkt_ctx.scratch_buf = NULL;

  /* handle command line args */
  while ((opt = getopt(argc, argv, "c:i:o:v")) != -1) {
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
      default:
        fprintf(stderr,
                "Usage: %s [-c cfg_file] [-i in_file] "
                "[-o out_file] [-v]\n",
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
        /* write decrypted packet to output pcap file */
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

  printf("decrypted %d packets in %s, skipped %d packets\n", n, out_pcap_file,
         skipped);
  goto exit;

err_exit:
  fflush(stdout);
  fprintf(stderr, "psp decryption failed\n");
  fflush(stderr);
  rc = EXIT_FAILURE;

exit:
  free(pkt_ctx.out_pkt);
  free(pkt_ctx.scratch_buf);
  if (pdumper != NULL) pcap_dump_close(pdumper);
  if (out_pd != NULL) pcap_close(out_pd);
  if (in_pd != NULL) pcap_close(in_pd);
  exit(rc);
}
