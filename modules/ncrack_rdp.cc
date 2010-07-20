
/***************************************************************************
 * ncrack_rdp.cc -- ncrack module for RDP                                  *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2010 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                *
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

#include "ncrack.h"
#include "nsock.h"
#include "NcrackOps.h"
#include "Service.h"
#include "modules.h"
#include "crypto.h"
#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <list>

#ifdef WIN32
#ifndef __attribute__
# define __attribute__(x)
#endif
# pragma pack(1)
#endif

#define RDP_TIMEOUT 20000
#define COOKIE_USERNAME "NCRACK_USER"


extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_connect_handler(nsock_pool nsp, nsock_event nse,
    void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

static int rdp_loop_read(nsock_pool nsp, Connection *con);
static void rdp_iso_connection_request(Connection *con);
static int rdp_iso_connection_confirm(Connection *con);
static void rdp_mcs_connect(Connection *con);
static int rdp_mcs_connect_response(Connection *con);
static int rdp_get_crypto(Connection *con, u_char *p);
static void rdp_mcs_erect_domain_request(Connection *con);
static void rdp_iso_data(Connection *con, uint16_t datalen);
static void rdp_mcs_attach_user_request(Connection *con);
static int rdp_mcs_attach_user_confirm(Connection *con);
static int rdp_iso_recv_data(Connection *con);
static void rdp_mcs_channel_join_request(Connection *con, uint16_t channel_id);
static int rdp_mcs_channel_join_confirm(Connection *con);
static void rdp_encrypt_data(Connection *con, uint8_t *data, uint32_t datalen);

/* ISO PDU codes */
enum ISO_PDU_CODE
{
  ISO_PDU_CR = 0xE0,  /* Connection Request */
  ISO_PDU_CC = 0xD0,  /* Connection Confirm */
  ISO_PDU_DR = 0x80,  /* Disconnect Request */
  ISO_PDU_DT = 0xF0,  /* Data */
  ISO_PDU_ER = 0x70   /* Error */
};

#define CS_CORE 0xC001;
#define CS_SECURITY 0xC002;
#define CS_NET 0xC003;
#define CS_CLUSTER 0xC004;

#define MCS_CONNECT_INITIAL 0x7f65
#define MCS_CONNECT_RESPONSE 0x7f66
#define MCS_GLOBAL_CHANNEL 1003
#define MCS_USERCHANNEL_BASE 1001

#define BER_TAG_BOOLEAN 1
#define BER_TAG_INTEGER 2
#define BER_TAG_OCTET_STRING 4
#define BER_TAG_RESULT 10
#define MCS_TAG_DOMAIN_PARAMS 0x30

/* Virtual channel options */
#define CHANNEL_OPTION_INITIALIZED 0x80000000
#define CHANNEL_OPTION_ENCRYPT_RDP 0x40000000
#define CHANNEL_OPTION_COMPRESS_RDP 0x00800000
#define CHANNEL_OPTION_SHOW_PROTOCOL 0x00200000

#define SEC_TAG_SRV_INFO 0x0c01
#define SEC_TAG_SRV_CRYPT 0x0c02
#define SEC_TAG_SRV_CHANNELS 0x0c03
#define SEC_TAG_PUBKEY 0x0006
#define SEC_TAG_KEYSIG 0x0008
#define SEC_RSA_MAGIC 0x31415352  /* RSA1 */

#define SEC_ENCRYPT 0x0008

enum states { RDP_INIT, RDP_CON, RDP_MCS_RESP, RDP_MCS_AURQ, RDP_MCS_AUCF, 
  RDP_MCS_CJ_USER, RDP_MCS_CJ_GLOBAL, RDP_FINI };

typedef struct rpd_state {

  uint8_t crypted_random[256];
  uint8_t sign_key[16];
  uint8_t encrypt_key[16];
  uint8_t decrypt_key[16];
  uint8_t encrypt_update_key[16];
  uint8_t decrypt_update_key[16];
  RC4_KEY rc4_encrypt_key;
  RC4_KEY rc4_decrypt_key;
  int rc4_keylen;
  int encrypt_use_count;

  uint16_t mcs_userid;

} rdp_state;


/* TPKT header */
typedef struct iso_tpkt {

  uint8_t version;  /* default version = 3 */
  uint8_t reserved;
  uint16_t length;  /* total packet length (including this header) - be */

} __attribute__((__packed__)) iso_tpkt;


/* ITU-T header */
typedef struct iso_itu_t {

  uint8_t hdrlen;   /* ITU-T header length */
  uint8_t code;     /* ISO_PDU_CODE */
  uint16_t dst_ref; /* 0 */
  uint16_t src_ref; /* 0 */
  uint8_t class_num;/* 0 */

} __attribute__((__packed__)) iso_itu_t;


/* ITU-T header - data case */
typedef struct iso_itu_t_data {

  uint8_t hdrlen;
  uint8_t code;
  uint8_t eot;

  iso_itu_t_data() { 
    hdrlen = 2;
    code = ISO_PDU_DT;
    eot = 0x80;
  }

} __attribute__((__packed__)) iso_itu_t_data;


/* 
 * Client MCS Erect Domain Request PDU 
 * http://msdn.microsoft.com/en-us/library/cc240523%28v=PROT.10%29.aspx
 */
typedef struct mcs_erect_domain_rq {

  uint8_t tag;
  uint16_t sub_height;
  uint16_t sub_interval;

  mcs_erect_domain_rq() {
    tag = 4;
    sub_height = htons(1);
    sub_interval = htons(1);
  }

} __attribute__((__packed__)) mcs_erect_domain_rq;


/*
 * Client MCS Attach User Request PDU
 * http://msdn.microsoft.com/en-us/library/cc240524%28v=PROT.10%29.aspx
 */
typedef struct mcs_attach_user_rq {

  uint8_t tag;
  mcs_attach_user_rq() {
    tag = 40;
  }

} mcs_attach_user_rq;


/* 
 * Server MCS Attach User Confirm PDU
 * http://msdn.microsoft.com/en-us/library/cc240525%28v=PROT.10%29.aspx
 */
typedef struct mcs_attach_user_confirm {

  uint8_t tag;    /* must be 44 */
  uint8_t result; /* must be 0 */
  uint16_t user_id;/* (be) */

} __attribute__((__packed__)) mcs_attach_user_confirm;

/* 
 * Client MCS Channel Join Request PDU
 * http://msdn.microsoft.com/en-us/library/cc240526%28v=PROT.10%29.aspx
 */
typedef struct mcs_channel_join_request {

  uint8_t tag;
  uint16_t user_id;
  uint16_t channel_id;
  mcs_channel_join_request() {
    tag = 56;
  }

} __attribute__((__packed__)) mcs_channel_join_request;

/* 
 * Server MCS Channel Join Confirm PDU
 * http://msdn.microsoft.com/en-us/library/cc240527%28v=PROT.10%29.aspx
 */
typedef struct mcs_channel_join_confirm {

  uint8_t tag;
  uint8_t result;
  uint16_t user_id;
  uint16_t req_channel_id;
  uint16_t channel_id;

} __attribute__((__packed__)) mcs_channel_join_confirm;


typedef struct mcs_data {

  uint8_t tag;
  uint16_t user_id; /* be */
  uint16_t channel; /* be */
  uint8_t flags;
  uint16_t length;  /* be */

  mcs_data() {
    tag = 100;
    channel = ntohs(MCS_GLOBAL_CHANNEL);
    flags = 0x70;
  }

} __attribute__((__packed__)) mcs_data;


typedef struct sec_header {

  uint32_t flags; /* normally SEC_ENCRYPT */
  uint8_t sig[8]; /* signature */

} __attribute__((__packed__)) sec_header;


/* Generic Conference Control (T.124) ConferenceCreateRequest 
 * T124 Section 8.7: http://www.itu.int/rec/T-REC-T.124-200701-I/en 
 */
typedef struct gcc_conference_create_request {
  /* be = big endian, le = little endian */
  // TODO: find the actual names of each var 

  /* be */
  uint16_t conf_num;  /* 5 */
  uint16_t word1;     /* 0x14 */
  uint8_t word2;      /* 0x7c */
  uint16_t word3;     /* 1 */
  uint16_t word4;     /* remaining length: length | 0x8000 */
  uint16_t word5;     /* 8, length? */
  uint16_t word6;     /* 16 */
  uint8_t word7;      /* 0 */
  uint16_t word8;     /* 0xc001 (le) */
  uint8_t word9;      /* 0 */
  uint32_t word10;    /* OEM ID: (le) */
  uint16_t word11;    /* remaining length: length - 14 | 0x8000 */

} __attribute__((__packed__)) gcc_ccr;



/* 
 * Client Core Data (TS_UD_CS_CORE)
 * http://msdn.microsoft.com/en-us/library/cc240510%28v=PROT.10%29.aspx
 */
typedef struct client_core_data {

  struct {
    uint16_t type;
    uint16_t length;
  } __attribute__((__packed__)) hdr;

  uint16_t version1;/* rdp version: 1 == RDP4, 4 == RD5 */
  uint16_t version2;/* always 8 */

  uint16_t width;   /* desktop width */
  uint16_t height;  /* desktop height */
  uint16_t depth;   /* color depth: 0xca00 = 4bits per pixel, 0xca01 8bpp */
  uint16_t sassequence;   /* always: RNS_UD_SAS_DEL (0xAA03) */
  uint32_t kb_layout;     /* 0x409: US keyboard layout */
  uint32_t client_build;  /* build number of client, 2600 */
  u_char client_name[32]; /* unicode name, padded to 32 bytes */
  uint32_t kb_type;     /* 0x4 for US kb type */
  uint32_t kb_subtype;  /* 0x0 for US kb subtype */
  uint32_t kb_fn;       /* 0xc for US kb function keys */
  uint8_t ime[64];      /* Input Method Editor file, 0 */
  uint16_t color_depth; /* 0xca01 */
  uint16_t client_id;   /* 1 */
  uint32_t serial_num;  /* 0 */
  uint8_t server_depth; /* 8 */
  uint16_t word1; /* 0x0700 */
  uint8_t word2;  /* 0 */
  uint32_t word3; /* 1 */
  uint8_t product_id[64]; /* all 0 */

} __attribute__((__packed__)) client_core_data;



/*
 * Client Security Data (TS_UD_CS_SEC)
 * http://msdn.microsoft.com/en-us/library/cc240511%28v=PROT.10%29.aspx
 */
typedef struct client_security_data {

  struct {
    uint16_t type;
    uint16_t length;/* 12 */
  } __attribute__((__packed__)) hdr;

  // TODO: rdesktop sets this field (enc_methods) to 0x3 for some reason
  // microsoft doesn't mention 3 as a possible value
  uint32_t enc_methods; /* 0 for no enc, 2 for 128-bit */
  uint32_t ext_enc; /* 0 for non-french locale clients */

} __attribute__((__packed__)) client_security_data;



/*
 * Client Network Data (TS_UD_CS_NET)
 * http://msdn.microsoft.com/en-us/library/cc240512%28v=PROT.10%29.aspx
 * This is only for 1 channel or else you need as many 
 * channel structs as the number of channels.
 */
typedef struct client_network_data {

  struct {
    uint16_t type;
    uint16_t length;
  } __attribute__((__packed__)) hdr;

  uint32_t channel_count;
  struct {
    char name[8];   /* null-terminated array of ANSI chars for channel id */
    uint32_t flags; /* channel option flags */
  } __attribute__((__packed__)) channel;

} __attribute__((__packed__)) client_network_data;



/*
 * Client Cluster Data (TS_UD_CS_CLUSTER)
 * http://msdn.microsoft.com/en-us/library/cc240514%28v=PROT.10%29.aspx
 */
typedef struct client_cluster_data {

  struct {
    uint16_t type;
    uint16_t length;
  } __attribute__((__packed__)) hdr;

  uint32_t redir_id;
  uint32_t pad; /* ? rdesktop seems to send another 32 zero bits */

} __attribute__((__packed__)) client_cluster_data;



typedef struct ber_integer {
  uint8_t tag;
  uint8_t length;
  uint16_t value;
  ber_integer() { 
    tag = BER_TAG_INTEGER;
    length = 2;
  }
} __attribute__((__packed__)) ber_integer;


typedef struct ber_string_small {
  uint8_t tag;
  uint8_t length;
  uint8_t value;
  ber_string_small() {
    tag = BER_TAG_OCTET_STRING;
    length = 1;
  }
} __attribute__((__packed__)) ber_string_small;


typedef struct ber_boolean {
  uint8_t tag;
  uint8_t length;
  uint8_t value;
  ber_boolean() {
    tag = BER_TAG_BOOLEAN;
    length = 1;
  }
} __attribute__((__packed__)) ber_boolean;



/* Each MCS Connect Initial struct is followed by 3 mcs_domain_params structs:
 * target_params, min_params and max_params. Then the mcs data follow.
 */
typedef struct mcs_domain_params {

  uint8_t tag;
  uint8_t length;
  ber_integer max_channels;
  ber_integer max_users;
  ber_integer max_tokens;
  ber_integer num_priorities;
  ber_integer min_throughput;
  ber_integer max_height;
  ber_integer max_pdusize;
  ber_integer ver_protocol;

  mcs_domain_params() {
    tag = MCS_TAG_DOMAIN_PARAMS;
    length = 32;
  }

} __attribute__((__packed__)) mcs_domain_params;



/* 
 * Variable-length Basic Encoding Rules encoded (BER-encoded)
 * MCS Connect Initial structure (using definite-length encoding)
 * as described in [T125] sections 10.1 and I.2 
 * (the ASN.1  structure definition is detailed in [T125] section 7, part 2).
 */
typedef struct mcs_connect_initial {

  uint16_t mcs_tag;
  uint8_t length_tag;
  uint16_t total_length;  /* total length (be) */

  ber_string_small calling_dom; /* calling domain */
  ber_string_small called_dom;  /* called domain */
  ber_boolean upward_flag;      /* upward flag */

  /* domain parameters */
  mcs_domain_params target;
  mcs_domain_params min;
  mcs_domain_params max;

  struct mcs_data {
    uint8_t tag;
    uint8_t length_tag;
    uint16_t datalength;

    mcs_data() { 
      tag = BER_TAG_OCTET_STRING;
      length_tag = 0x82;
    }
  } __attribute__((__packed__)) mcs_data;

  mcs_connect_initial() {
    mcs_tag = htons(MCS_CONNECT_INITIAL);
    length_tag = 0x82;
  }

} __attribute__((__packed__)) mcs_connect_initial;



/* 
 * Variable-length BER-encoded MCS Connect Response structure
 * (using definite-length encoding) as described in [T125] sections 10.2 and I.2
 * (the ASN.1  structure definition is detailed in [T125] section 7, part 2).
 * The userData field of the MCS Connect Response encapsulates the GCC
 * Conference Create Response data (contained in the gccCCrsp and
 * subsequent fields).
 */
typedef struct mcs_response { 

  uint16_t mcs_tag;
  uint8_t length_tag;
  uint16_t total_length;

  uint8_t result_tag;
  uint8_t result_len;
  uint8_t result_value;

  uint8_t connectid_tag;
  uint8_t connectid_len;
  uint8_t connectid_value;

}  __attribute__((__packed__)) mcs_response;


static uint8_t pad54[40] = {
  54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54,
  54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54,
  54, 54, 54, 54, 54, 54
};

static uint8_t pad92[48] = {
  92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92,
  92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92,
  92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92
};


static int
rdp_loop_read(nsock_pool nsp, Connection *con)
{
  uint16_t total_length;
  void *ioptr;

  /* Make sure we get at least 4 bytes: this is the TPKT header which
   * contains the total size of the message
   */
  if (con->inbuf == NULL || con->inbuf->get_len() < 4) {
    nsock_read(nsp, con->niod, ncrack_read_handler, RDP_TIMEOUT, con);
    return -1;
  }

  /* Get message length from TPKT header. It is in big-endian byte order */
  ioptr = con->inbuf->get_dataptr();
  memcpy(&total_length, ioptr, sizeof(total_length));

  total_length = ntohl(total_length); /* convert to host-byte order */

  /* If we haven't received all the bytes of the message, according to the
   * total length that we calculated, then try and get the rest */
  if (con->inbuf == NULL || con->inbuf->get_len() < total_length) {
    nsock_read(nsp, con->niod, ncrack_read_handler, RDP_TIMEOUT, con);
    return -1;
  }

  return 0;

}


static void
rdp_iso_connection_request(Connection *con)
{
  iso_tpkt tpkt;
  iso_itu_t itu_t;
  uint16_t length = 30 + strlen(COOKIE_USERNAME);

  tpkt.version = 3;
  tpkt.reserved = 0;
  tpkt.length = htons(length);

  itu_t.hdrlen = length - 5;
  itu_t.code = ISO_PDU_CR;
  itu_t.dst_ref = 0;
  itu_t.src_ref = 0;
  itu_t.class_num = 0;

  con->outbuf->append(&tpkt, sizeof(tpkt));
  con->outbuf->append(&itu_t, sizeof(iso_itu_t));

  /* It appears that we need to send a username cookie */
  con->outbuf->snprintf(strlen("Cookie: mstshash="), "%s",
      "Cookie: mstshash=");
  con->outbuf->snprintf(strlen(COOKIE_USERNAME), "%s", COOKIE_USERNAME);
  con->outbuf->snprintf(2, "%c%c", '\r', '\n');

}


static int
rdp_iso_connection_confirm(Connection *con)
{

  iso_tpkt *tpkt;
  iso_itu_t *itu_t;

  tpkt = (iso_tpkt *) ((const char *)con->inbuf->get_dataptr());
  itu_t = (iso_itu_t *) ((const char *)tpkt + sizeof(iso_tpkt));

  if (tpkt->version != 3)
    fatal("rdp_module: not supported version: %d\n", tpkt->version);

  if (itu_t->code != ISO_PDU_CC)
    return -1;

  return 0;
}


static void
rdp_iso_data(Connection *con, uint16_t datalen)
{

  iso_tpkt tpkt;
  iso_itu_t_data itu_t_data;

  tpkt.version = 3;
  tpkt.reserved = 0;
  tpkt.length = htons(sizeof(tpkt) + sizeof(itu_t_data) + datalen);

  con->outbuf->append(&tpkt, 4);
  con->outbuf->append(&itu_t_data, 3);

}

static void
rdp_mcs_data(Connection *con, uint16_t datalen)
{
  mcs_data mcs;
  rdp_state *info = (rdp_state *)con->misc_info;

  mcs.user_id = htons(info->mcs_userid);

  /* The length in the MCS header doesn't include the size of the header
   * itself, rather all the data following the header: the security header
   * and RDP data (if any) following it.
   */
  mcs.length = htons(datalen | 0x8000);

  printf("mcs-size %u \n", sizeof(mcs));
  con->outbuf->append(&mcs, sizeof(mcs));

}



static void
rdp_mcs_erect_domain_request(Connection *con)
{
  mcs_erect_domain_rq edrq;

  rdp_iso_data(con, sizeof(edrq));

  con->outbuf->append(&edrq, sizeof(edrq));
}


static void
rdp_mcs_attach_user_request(Connection *con)
{
  mcs_attach_user_rq aurq;

  rdp_iso_data(con, sizeof(aurq));

  con->outbuf->append(&aurq, sizeof(aurq));
}


static int
rdp_mcs_attach_user_confirm(Connection *con)
{
  mcs_attach_user_confirm *aucf;
  u_char *p;
  char error[64];
  rdp_state *info;

  /* rdp_state must have already been initialized! */
  info = (rdp_state *)con->misc_info;

  if (rdp_iso_recv_data(con) < 0)
    return -1;

  p = ((u_char *)con->inbuf->get_dataptr() + sizeof(iso_tpkt)
      + sizeof(iso_itu_t_data));

  aucf = (mcs_attach_user_confirm *)p;

  /* Check opcode */
  if ((aucf->tag >> 2) != 11) {
    snprintf(error, sizeof(error), "MCS attach user confirm opcode: %u\n",
        aucf->tag);
    goto mcs_aucf_error;
  }

  /* Check result parameter */
  if (aucf->result != 0) {
    snprintf(error, sizeof(error), "MCS attach user confirm result: %u\n",
        aucf->result);
    goto mcs_aucf_error;
  }

  if (aucf->tag & 2)
    info->mcs_userid = ntohs(aucf->user_id);

  return 0;

mcs_aucf_error:

  con->service->end.orly = true;
  con->service->end.reason = Strndup(error, strlen(error));
  return -1;

}


static void
rdp_mcs_channel_join_request(Connection *con, uint16_t channel_id)
{
  mcs_channel_join_request cjrq;
  rdp_state *info = (rdp_state *)con->misc_info;

  rdp_iso_data(con, sizeof(cjrq));

  cjrq.user_id = htons(info->mcs_userid);
  cjrq.channel_id = htons(channel_id);

  con->outbuf->append(&cjrq, sizeof(cjrq));
}


static int
rdp_mcs_channel_join_confirm(Connection *con)
{
  mcs_channel_join_confirm *cjcf;
  u_char *p;
  char error[64];

  if (rdp_iso_recv_data(con) < 0)
    return -1;

  p = ((u_char *)con->inbuf->get_dataptr() + sizeof(iso_tpkt)
      + sizeof(iso_itu_t_data));

  cjcf = (mcs_channel_join_confirm *)p;

  /* Check opcode */
  if ((cjcf->tag >> 2) != 15) {
    snprintf(error, sizeof(error), "MCS channel join confirm opcode: %u\n",
        cjcf->tag);
    goto mcs_cjcf_error;
  }

  /* Check result parameter */
  if (cjcf->result != 0) {
    snprintf(error, sizeof(error), "MCS channel join confirm result: %u\n",
        cjcf->result);
    goto mcs_cjcf_error;
  }

  return 0;

mcs_cjcf_error:

  con->service->end.orly = true;
  con->service->end.reason = Strndup(error, strlen(error));
  return -1;
}



/* 
 * Client MCS Connect Initial PDU with GCC Conference Create Request
 * Constructs the packet which is is described at:
 * http://msdn.microsoft.com/en-us/library/cc240508%28v=PROT.10%29.aspx
 */
static void
rdp_mcs_connect(Connection *con)
{
  /* TODO: consider instead of creating separate Bufs and merging them at the
   * end, to extend the Buf()'s class functions where you can push and pop data
   * out of it.
   */
  mcs_connect_initial mcs;

  gcc_ccr ccr;
  client_core_data ccd;
  client_security_data csd;
  client_cluster_data cluster;

  uint16_t datalen = 259;
  uint16_t total_length = datalen + 115;

#if 0
  printf("total_length: mcs=%d ccr=%d ccd=%d csd=%d cluster=%d total:%d \n",
      sizeof(mcs), sizeof(ccr), sizeof(ccd), sizeof(csd), sizeof(cluster), 
      sizeof(mcs) + sizeof(ccr) + sizeof(ccd) + sizeof(csd) + sizeof(cluster));
#endif

  rdp_iso_data(con, 379);

  /* 
   * MCS Connect Initial structure 
   */
  mcs.total_length = htons(total_length);
  mcs.calling_dom.value = 1;
  mcs.called_dom.value = 1;
  mcs.upward_flag.value = 0xff;

  /* target params */
  mcs.target.max_channels.value = htons(34);
  mcs.target.max_users.value = htons(2);
  mcs.target.max_tokens.value = 0;
  mcs.target.num_priorities.value = htons(1);
  mcs.target.min_throughput.value = htons(0);
  mcs.target.max_height.value = htons(1);
  mcs.target.max_pdusize.value = htons(0xffff);
  mcs.target.ver_protocol.value = htons(2);

  /* min params */
  mcs.min.max_channels.value = htons(1);
  mcs.min.max_users.value = htons(1);
  mcs.min.max_tokens.value = htons(1);
  mcs.min.num_priorities.value = htons(1);
  mcs.min.min_throughput.value = htons(0);
  mcs.min.max_height.value = htons(1);
  mcs.min.max_pdusize.value = htons(0x420);
  mcs.min.ver_protocol.value = htons(2);

  /* max params */
  mcs.max.max_channels.value = htons(0xffff);
  mcs.max.max_users.value = htons(0xfc17);
  mcs.max.max_tokens.value = htons(0xffff);
  mcs.max.num_priorities.value = htons(1);
  mcs.max.min_throughput.value = htons(0);
  mcs.max.max_height.value = htons(1);
  mcs.max.max_pdusize.value = htons(0xffff);
  mcs.max.ver_protocol.value = htons(2);

  /* MCS data */
  mcs.mcs_data.datalength = htons(datalen);


  /* first remaining length - it is on word4 so subtract the size of all the
   * previous words + the size of word4 (2+2+1+2+2 = 9). The rest is the size
   * of the whole remaining packet
   */
  int length = 250;


  /* Fill in the mcs_data:
   * This consists of a variable-length PER-encoded GCC Connect Data structure
   * which encapsulates a Connect GCC PDU that contains a GCC Conference Create
   * Request. The userData field of this struct contains a user data set
   * consisting of concatenated Client Data Blocks: clientCoreData,
   * clientSecurityData etc
   */

  /* Generic Conference Control (T.124) ConferenceCreateRequest 
   * T124 Section 8.7: http://www.itu.int/rec/T-REC-T.124-200701-I/en 
   */
  ccr.conf_num = htons(5);
  ccr.word1 = htons(0x14);
  ccr.word2 = 0x7c;
  ccr.word3 = htons(1);
  ccr.word4 = htons(length | 0x8000); /* remaining length */
  ccr.word5 = htons(8);
  ccr.word6 = htons(16);
  ccr.word7 = 0;
  ccr.word8 = 0xc001;
  ccr.word9 = 0;
  ccr.word10 = 0x61637544;  /* OEM ID: "Duca" TODO: change this */
  ccr.word11 = htons((length - 14) | 0x8000);


  /* Client Core Data (TS_UD_CS_CORE)
   * http://msdn.microsoft.com/en-us/library/cc240510%28v=PROT.10%29.aspx
   */
  ccd.hdr.type = CS_CORE;
  ccd.hdr.length = 212;
  ccd.version1 = 1;   /* RDP 5 by default */
  ccd.version2 = 8;
  ccd.width = 800;
  ccd.height = 600;
  ccd.depth = 0xca01;
  ccd.sassequence = 0xaa03;
  ccd.kb_layout = 0x409;
  ccd.client_build = 2600;
  u_char hostname[] = { 0x4E, 0x00, 0x43, 0x00, 0x52, 0x00, 0x41,
    0x00, 0x43, 0x00, 0x4B, 0x00 };
  memset(ccd.client_name, 0, 32);
  memcpy(ccd.client_name, hostname, sizeof(hostname));
  ccd.kb_type = 0x4;
  ccd.kb_subtype = 0x0;
  ccd.kb_fn = 0xc;
  memset(&ccd.ime, 0, 64);
  ccd.color_depth = 0xca01;
  ccd.client_id = 1;
  ccd.serial_num = 0;
  ccd.server_depth = 8;
  ccd.word1 = 0x0700;
  ccd.word2 = 0;
  ccd.word3 = 1;
  memset(&ccd.product_id, 0, 64);

  /* Client Cluster Data (TS_UD_CS_CLUSTER)
   * http://msdn.microsoft.com/en-us/library/cc240514%28v=PROT.10%29.aspx
   */
  cluster.hdr.type = CS_CLUSTER;
  cluster.hdr.length = 12;
  cluster.redir_id = 9;
  cluster.pad = 0;

  /* Client Security Data (TS_UD_CS_SEC)
   * http://msdn.microsoft.com/en-us/library/cc240511%28v=PROT.10%29.aspx
   */
  csd.hdr.type = CS_SECURITY;
  csd.hdr.length = 12;
  csd.enc_methods = 3;
  csd.ext_enc = 0;


#if 0
  /*
   * Client Network Data (TS_UD_CS_NET)
   * http://msdn.microsoft.com/en-us/library/cc240512%28v=PROT.10%29.aspx
   */
  cnd.hdr.length = 1 * 12 + 8;  /* only 1 channel */
  cnd.channel_count = 1;
  strncpy(cnd.channel.name, "rdpdr", sizeof("rdpdr"));
  cnd.channel.flags = CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_COMPRESS_RDP;
#endif


  con->outbuf->append(&mcs, 120);
  con->outbuf->append(&ccr, sizeof(ccr));
  con->outbuf->append(&ccd, sizeof(ccd));
  con->outbuf->append(&cluster, sizeof(cluster));
  con->outbuf->append(&csd, sizeof(csd));

}


static int
rdp_iso_recv_data(Connection *con)
{
  iso_tpkt *tpkt;
  iso_itu_t_data *itu_t;
  char error[64];

  tpkt = (iso_tpkt *) ((const char *)con->inbuf->get_dataptr());
  itu_t = (iso_itu_t_data *) ((const char *)tpkt + sizeof(iso_tpkt));

  if (tpkt->version != 3)
    fatal("rdp_module: not supported version: %d\n", tpkt->version);

  if (tpkt->length < 4) {
    con->service->end.orly = true;
    con->service->end.reason = Strndup("Bad tptk packet header.", 23);
    return -1;
  }

  if (itu_t->code != ISO_PDU_DT) {
    snprintf(error, sizeof(error), "Expected data packet, but got 0x%x.",
        itu_t->code);
    con->service->end.orly = true;
    con->service->end.reason = Strndup(error, strlen(error));
    return -1;
  }

  return 0;

}


/*
 * Parses and gets the Server Security Data (TS_UD_SC_SEC1) from MCS connect
 * response. Saves everything that will be needed later into rdp_state.
 * http://msdn.microsoft.com/en-us/library/cc240518%28v=PROT.10%29.aspx
 */
static int
rdp_get_crypto(Connection *con, u_char *p)
{
  uint8_t client_random[32];
  uint8_t mod[256];
  uint8_t exp[4];
  uint8_t *server_random = NULL;
  uint32_t server_random_len;
  uint32_t rc4_size;  
  uint32_t encryption_level;
  uint32_t rsa_len;
  uint32_t mod_len;
  char error[128];
  rdp_state *info;

  /* rdp_state must have already been initialized! */
  info = (rdp_state *)con->misc_info;

  memset(mod, 0, sizeof(mod));
  memset(exp, 0, sizeof(exp));

  /* Get encryption method: 
   * 0x00000000: None
   * 0x00000001: 40 bit
   * 0x00000002: 128 bit
   * 0x00000008: 56 bit 
   * 0x00000010: FIPS 140-1 compliant
   */
  rc4_size = *(uint32_t *)p;
  p += 4;

  /* Get encryption level:
   * 0x00000000: None
   * 0x00000001: low 
   * 0x00000002: client compatible
   * 0x00000003: high
   * 0x00000004: fips
   */
  encryption_level = *(uint32_t *)p;
  p += 4;

  if (encryption_level == 0)
    return -1;

  /* Now get the serverRandomLen */
  server_random_len = *(uint32_t *)p;
  p += 4;

  /* According to the specs, this field value MUST be 32 bytes, as long as both
   * the encryption method and level are not 0.
   */
  if (server_random_len != 32) {
    con->service->end.orly = true;
    snprintf(error, sizeof(error), "Server security data: "
        "server random len was %d but should be 32.", server_random_len);
    con->service->end.reason = Strndup(error, strlen(error));
    return -1;
  }

  /* Get rsa len */
  rsa_len = *(uint32_t *)p;
  p += 4;

  /* Store pointer for the serverRandom field and move it forward so far as
   * specified by the serverRandomLen field which we parsed earlier.
   */
  server_random = p;
  p += server_random_len;

  u_char *real_end = (u_char *)con->inbuf->get_dataptr() + con->inbuf->get_len();
  u_char *end = p + rsa_len;
  if (end > real_end) {
    con->service->end.orly = true;
    snprintf(error, sizeof(error), "Server security data: possibly corrupted "
        " packet. %d more bytes specified", end - real_end);
    con->service->end.reason = Strndup(error, strlen(error));
    return -1;
  }

  uint32_t flags = *(uint32_t *)p;
  /* RDP4 encryption */
  if (!(flags & 1))
    fatal("rdp_module: not supported rdp5 encryption\n");

  p += 8; /* skip 8 bytes */

  uint16_t tag, hdr_length;
  u_char *saved_p;
  uint32_t rsa_magic;
  while (p < end) {

    tag = *(uint16_t *)p;
    p += 2;
    hdr_length = *(uint16_t *)p;
    p += 2;

    saved_p = p + hdr_length;

    switch (tag)
    {
      case SEC_TAG_PUBKEY:

        rsa_magic = *(uint32_t *)p;
        p += 4;

        if (rsa_magic != SEC_RSA_MAGIC) {
          con->service->end.orly = true;
          snprintf(error, sizeof(error), "Server security data: Expected %d "
              "for RSA magic but got %d.", SEC_RSA_MAGIC, rsa_magic);
          con->service->end.reason = Strndup(error, strlen(error));
          return -1;
        }

        mod_len = *(uint32_t *)p;
        p += 4;

        /* subtract padding size 8 */
        mod_len -= 8;
        if (mod_len < 64 || mod_len > 256) {
          con->service->end.orly = true;
          snprintf(error, sizeof(error), "Server security data: Expected "
              "modulus size to be between 64 and 256 but was %d", mod_len);
          con->service->end.reason = Strndup(error, strlen(error));
          return -1;
        }
        p += 8; /* skip 8 bytes */
        memcpy(exp, p, 4);
        p += 4;
        memcpy(mod, p, mod_len);
        p += mod_len;
        p += 8; /* skip padding */

        break;

      case SEC_TAG_KEYSIG:
        //TODO: we don't check for signatures now, but perhaps we should to
        //detect MITM attacks
        break;

      default:
        break;

    }

    p = saved_p;
  }

  /* 
   * This is not strong randomness since it uses nbase's relatively weak algo
   * to get the 32 bytes needed.
   */
  get_random_bytes(client_random, sizeof(client_random));
  rsa_encrypt(client_random, info->crypted_random, 32, mod, mod_len, exp);

  uint8_t premaster_secret[48];
  uint8_t master_secret[48];
  uint8_t key[48];

  /* pre master secret */
  memcpy(premaster_secret, client_random, 24);
  memcpy(premaster_secret + 24, server_random, 24);

  /* master secret and key */
  hash48(master_secret, premaster_secret, 'A', client_random, server_random);
  hash48(key, master_secret, 'X', client_random, server_random);

  /* create key used for signing */
  memcpy(info->sign_key, key, 16);

  /* export keys */
  hash16(info->decrypt_key, &key[16], client_random, server_random);
  hash16(info->encrypt_key, &key[32], client_random, server_random);

  //TODO: check for case of 40bit enc 
  if (rc4_size == 1) {
    /* 40 bit enc */
    info->rc4_keylen = 8;
  } else 
    info->rc4_keylen = 16; /* 128 bit encryption */

  /* update keys */
  memcpy(info->encrypt_update_key, info->encrypt_key, 16);
  memcpy(info->decrypt_update_key, info->decrypt_key, 16);

  RC4_set_key(&info->rc4_encrypt_key, info->rc4_keylen, info->encrypt_key);
  RC4_set_key(&info->rc4_decrypt_key, info->rc4_keylen, info->decrypt_key);

  return 0;
}




static int
rdp_mcs_connect_response(Connection *con)
{
  mcs_response *mcs;
  u_char *p;
  char error[64];

  if (rdp_iso_recv_data(con) < 0)
    return -1;

  p = ((u_char *)con->inbuf->get_dataptr() + sizeof(iso_tpkt)
      + sizeof(iso_itu_t_data));

  mcs = (mcs_response *)p;

  /* Check result parameter */
  if (mcs->result_value != 0) {
    snprintf(error, sizeof(error), "MCS connect result: %x\n", mcs->result_value);
    con->service->end.orly = true;
    con->service->end.reason = Strndup(error, strlen(error));
    return -1;
  }

  /* Now parse MCS_TAG_DOMAIN_PARAMS header and ignore as many bytes as the
   * length of this header.
   */
  p += sizeof(mcs_response);
  if (*p != MCS_TAG_DOMAIN_PARAMS) {
    con->service->end.orly = true;
    con->service->end.reason = Strndup(
        "MCS connect no MCS_TAG_DOMAIN_PARAMS tag found where expected.", 62);
    return -1;
  }

  p++; /* now p should point to length of the header */
  uint8_t mcs_domain_len = *p;
  p += mcs_domain_len; /* ignore that many bytes */

  /* Now p points to the BER header of mcs_data - ignore header */
  p += 5;

  /* Ignore the 21 bytes of the T.124 ConferenceCreateResponse */
  p += 21;

  /* Now parse Server Data Blocks (serverCoreData, serverNetworkData,
   * serverSecurityData) 
   */
  uint8_t len = *++p;
  if (len & 0x80)
    len = *++p;

  uint16_t tag, hdr_length;
  u_char *saved_p;
  u_char *end = (u_char *)con->inbuf->get_dataptr() + con->inbuf->get_len();

  while (p < end) {

    tag = *(uint16_t *)p;
    p += 2;
    hdr_length = *(uint16_t *)p;
    p += 2;

    saved_p = p + hdr_length - 4;

    if (hdr_length <= 4) {
      return 0;
      //con->service->end.orly = true;
      //con->service->end.reason = Strndup("MCS response: corrupted packet.", 31);
      //return -1;
    }

    switch (tag)
    {
      case SEC_TAG_SRV_INFO:
        break;

      case SEC_TAG_SRV_CRYPT:
        if (rdp_get_crypto(con, p) < 0)
          return -1;
        break;

      default:
        break;
    }

    p = saved_p;
  } 

  return 0;
}


static void
rdp_encrypt_data(Connection *con, uint8_t *data, uint32_t datalen)
{
  rdp_state *info = (rdp_state *)con->misc_info;
  sec_header sec;

  sec.flags = SEC_ENCRYPT;

  /* Now sign the data */
  SHA_CTX sha1_ctx;
  uint8_t sha1_sig[20];
  MD5_CTX md5_ctx;
  uint8_t md5_sig[16];
  uint8_t len_header[4];

  SHA1_Init(&sha1_ctx);
  MD5_Init(&md5_ctx);

  len_header[0] = (datalen) & 0xFF;
  len_header[1] = (datalen >> 8) & 0xFF;
  len_header[2] = (datalen >> 16) & 0xFF;
  len_header[3] = (datalen >> 24) & 0xFF;

  SHA1_Update(&sha1_ctx, info->sign_key, info->rc4_keylen);
  SHA1_Update(&sha1_ctx, pad54, 40);
  SHA1_Update(&sha1_ctx, len_header, 4);
  SHA1_Update(&sha1_ctx, data, datalen);
  SHA1_Final(sha1_sig, &sha1_ctx);

  MD5_Update(&md5_ctx, info->sign_key, info->rc4_keylen);
  MD5_Update(&md5_ctx, pad92, 48);
  MD5_Update(&md5_ctx, sha1_sig, 20);
  MD5_Final(md5_sig, &md5_ctx);

  memcpy(sec.sig, md5_sig, sizeof(sec.sig));

  /* Encrypt the data */

  // UPDATE KEY
  if (info->encrypt_use_count == 4096) {
    info->encrypt_use_count = 0;

  }
  RC4(&info->rc4_encrypt_key, datalen, data, data);
  info->encrypt_use_count++;

  /* This is the security header, which is after the ISO and MCS headers */
  con->outbuf->append(&sec, sizeof(sec));
  /* Everything below the security header is the encrypted data. */
  con->outbuf->append(data, datalen);

}




void
ncrack_rdp(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  void *ioptr;
  rdp_state *info = NULL;

  if (con->misc_info)
    info = (rdp_state *) con->misc_info;

  switch (con->state)
  {
    case RDP_INIT:

      con->state = RDP_CON;

      con->outbuf = new Buf();
      rdp_iso_connection_request(con);

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;


    case RDP_CON:

      if (rdp_loop_read(nsp, con) < 0)
        break;

      con->state = RDP_MCS_RESP;

      if (rdp_iso_connection_confirm(con) < 0) {
        serv->end.orly = true;
        serv->end.reason = Strndup("TPKT Connection denied.", 23);
        return ncrack_module_end(nsp, con);
      }

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      rdp_mcs_connect(con);

      delete con->inbuf;
      con->inbuf = NULL;

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());

    case RDP_MCS_RESP:

      if (rdp_loop_read(nsp, con) < 0)
        break;

      con->state = RDP_MCS_AURQ;

      con->misc_info = (rdp_state *)safe_zalloc(sizeof(rdp_state));

      if (rdp_mcs_connect_response(con) < 0)
        return ncrack_module_end(nsp, con);

      /* Now send Erection Domain Request */
      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      rdp_mcs_erect_domain_request(con);

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case RDP_MCS_AURQ:

      con->state = RDP_MCS_AUCF;

      /* Now send Attach User Request */
      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      rdp_mcs_attach_user_request(con);

      delete con->inbuf;
      con->inbuf = NULL;

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case RDP_MCS_AUCF:

      if (rdp_loop_read(nsp, con) < 0)
        break;

      con->state = RDP_MCS_CJ_USER;

      if (rdp_mcs_attach_user_confirm(con) < 0)
        return ncrack_module_end(nsp, con);

      /* Now send User Channel Join request */
      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      rdp_mcs_channel_join_request(con, info->mcs_userid +
          MCS_USERCHANNEL_BASE);

      delete con->inbuf;
      con->inbuf = NULL;

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case RDP_MCS_CJ_USER:

      if (rdp_loop_read(nsp, con) < 0)
        break;

      con->state = RDP_MCS_CJ_GLOBAL;

      if (rdp_mcs_channel_join_confirm(con) < 0)
        return ncrack_module_end(nsp, con);

      /* Now send Global Channel Join request */
      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      rdp_mcs_channel_join_request(con, MCS_GLOBAL_CHANNEL);

      delete con->inbuf;
      con->inbuf = NULL;

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case RDP_MCS_CJ_GLOBAL:
      if (rdp_loop_read(nsp, con) < 0)
        break;

      con->state = RDP_FINI;

      if (rdp_mcs_channel_join_confirm(con) < 0)
        return ncrack_module_end(nsp, con);

      break;

    case RDP_FINI:

      printf("fini\n");
      exit(0);
      break;

  }


}

