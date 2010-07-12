
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
#include <list>

#ifdef WIN32
#ifndef __attribute__
# define __attribute__(x)
#endif
# pragma pack(1)
#endif

#define RDP_TIMEOUT 20000
#define COOKIE_USERNAME "NCRACK_USER"
#define FAKE_HOSTNAME "NCRACK"

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_connect_handler(nsock_pool nsp, nsock_event nse,
    void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

static int rdp_loop_read(nsock_pool nsp, Connection *con);
static void rdp_iso_connection_request(Connection *con);
static int rdp_iso_connection_confirm(Connection *con);
static int rdp_mcs_connect(Connection *con);


/* ISO PDU codes */
enum ISO_PDU_CODE
{
	ISO_PDU_CR = 0xE0,	/* Connection Request */
	ISO_PDU_CC = 0xD0,	/* Connection Confirm */
	ISO_PDU_DR = 0x80,	/* Disconnect Request */
	ISO_PDU_DT = 0xF0,	/* Data */
	ISO_PDU_ER = 0x70	  /* Error */
};

#define CS_CORE 0xC001;
#define CS_SECURITY 0xC002;
#define CS_NET 0xC003;

#define MCS_CONNECT_INITIAL	0x7f65
#define MCS_CONNECT_RESPONSE	0x7f66

#define BER_TAG_BOOLEAN		1
#define BER_TAG_INTEGER		2
#define BER_TAG_OCTET_STRING	4
#define BER_TAG_RESULT		10
#define MCS_TAG_DOMAIN_PARAMS	0x30

/* Virtual channel options */
#define CHANNEL_OPTION_INITIALIZED	0x80000000
#define CHANNEL_OPTION_ENCRYPT_RDP	0x40000000
#define CHANNEL_OPTION_COMPRESS_RDP	0x00800000
#define CHANNEL_OPTION_SHOW_PROTOCOL	0x00200000


enum states { RDP_INIT, RDP_CON, RDP_FINI };


/* TPKT header */
typedef struct iso_tpkt {

    uint8_t version;  /* default version = 3 */
    uint8_t reserved;
    uint16_t length;  /* total length in big endian */

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
  uint16_t word8;     /* 0xc001 */
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

  uint16_t version1;  /* rdp version: 1 == RDP4, 4 == RD5 */
  uint16_t version2;  /* always 8 */

  uint16_t width;   /* desktop width */
  uint16_t height;  /* desktop height */
  uint16_t depth;   /* color depth: 0xca00 = 4bits per pixel, 0xca01 8bpp */
  uint16_t sassequence; /* always: RNS_UD_SAS_DEL (0xAA03) */
  uint32_t kb_layout;   /* 0x409: US keyboard layout */
  uint32_t client_build;/* build number of client, 2600 */
  char client_name[32]; /* unicode name, padded to 32 bytes */
  uint32_t kb_type;     /* 0x4 for US kb type */
  uint32_t kb_subtype;  /* 0x0 for US kb subtype */
  uint32_t kb_fn;       /* 0xc for US kb function keys */
  uint64_t ime;         /* Input Method Editor file, 0 */

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
    mcs_tag = MCS_CONNECT_INITIAL;
    length_tag = 0x82;
  }

} __attribute__((__packed__)) mcs_connect_initial;
 




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

  printf("%x %x %x \n", tpkt.version, tpkt.reserved, tpkt.length);

  itu_t.hdrlen = length - 5;
  itu_t.code = ISO_PDU_CR;
  itu_t.dst_ref = 0;
  itu_t.src_ref = 0;
  itu_t.class_num = 0;

  con->outbuf->append(&tpkt, 4);

  char *shat = (char *)con->outbuf->get_dataptr();
  printf("SHAT: %x %x %x %x\n", *shat, *(shat + 1), *(shat +2), *(shat +3));


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

  printf("itu_t: %x \n", itu_t->code);

  if (tpkt->version != 3)
    fatal("rdp_module: not supported version: %d\n", tpkt->version);

  if (itu_t->code != ISO_PDU_CC)
    return -1;

  return 0;
}


static void
rdp_iso_data(Connection *con, uint16_t length)
{

  iso_tpkt tpkt;
  iso_itu_t_data itu_t_data;

  tpkt.version = 3;
  tpkt.length = htons(length);

  con->outbuf->append(&tpkt, 4);
  con->outbuf->append(&itu_t_data, 3);

}


/* 
 * Client MCS Connect Initial PDU with GCC Conference Create Request
 * Constructs the packet which is is described at:
 * http://msdn.microsoft.com/en-us/library/cc240508%28v=PROT.10%29.aspx
 */
static int
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

  uint16_t datalen = sizeof(ccr) + sizeof(ccd) + sizeof(csd);
  uint16_t total_length = datalen + sizeof(mcs);

  // sizeof(mcs) = 9 + 3 * 34 + 4 = 115
  printf("mcs_size=%d \n", sizeof(mcs));

  rdp_iso_data(con, total_length);

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
  int length = datalen - 9;
  printf("ccr=%d ccd=%d csd=%d\n", sizeof(ccr), sizeof(ccd), sizeof(csd));


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
  ccr.word8 = htons(0xc001);
  ccr.word9 = 0;
  ccr.word10 = 0x61637544;  /* OEM ID: "Duca" TODO: change this */
  ccr.word11 = htons((length - 14) | 0x8000);


  /* Client Core Data (TS_UD_CS_CORE)
   * http://msdn.microsoft.com/en-us/library/cc240510%28v=PROT.10%29.aspx
   */
  ccd.hdr.type = CS_CORE;
  ccd.hdr.length = sizeof(ccd);
  ccd.version1 = 4;   /* RDP 5 by default */
  ccd.version2 = 8;
  ccd.width = 800;
  ccd.height = 600;
  ccd.depth = 0xca01;
  ccd.sassequence = 0xaa03;
  ccd.kb_layout = 0x409;
  ccd.client_build = 2600;
  strncpy(ccd.client_name, FAKE_HOSTNAME, sizeof(FAKE_HOSTNAME));
  ccd.kb_type = 0x4;
  ccd.kb_fn = 0xc;
  ccd.ime = 0;

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


  con->outbuf->append(&mcs, sizeof(mcs));
  con->outbuf->append(&ccr, sizeof(ccr));
  con->outbuf->append(&ccd, sizeof(ccd));
  con->outbuf->append(&csd, sizeof(csd));


}




void
ncrack_rdp(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  void *ioptr;


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

      con->state = RDP_FINI;

      if (rdp_iso_connection_confirm(con) < 0) {
        serv->end.reason = Strndup("TPKT Connection denied.",
            sizeof("TPKT Connection denied." - 1));
        return ncrack_module_end(nsp, con);
      }

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      printf("rdp connect \n");

      rdp_mcs_connect(con);

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());


    case RDP_FINI:

      printf("fini\n");

      break;



  }




}



