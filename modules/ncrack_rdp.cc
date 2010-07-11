
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

enum states { RDP_INIT, RDP_CON, RDP_FINI };


typedef struct rdp_iso_pkt {

  /* TPKT header */
  struct {
    uint8_t version;  /* default version = 3 */
    uint8_t reserved; /* 0 */
    uint16_t length;  /* total length in big endian */
  } __attribute__((__packed__)) tpkt;

  /* ITU-T header */
  struct {
    uint8_t hdrlen;   /* ITU-T header length */
    uint8_t code;     /* ISO_PDU_CODE */
    uint16_t dst_ref; /* 0 */
    uint16_t src_ref; /* 0 */
    uint8_t class_num;    /* 0 */
  } __attribute__((__packed__)) itu_t;

} __attribute__((__packed__)) rdp_iso_pkt;


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
    uint16_t type;  /* CS_CORE (0xC001) */
    uint16_t length;/* 212 */
  } __attribute__((__packed__)) hdr;

  uint16_t version1;  /* rdp version: 1 == RDP4, 4 == RD5 */
  uint16_t version2;  /* always 8 */

  uint16_t width;   /* desktop width */
  uint16_t height;  /* desktop height */
  uint16_t depth;   /* color depth: 0xca00 = 4bits per pixel, 0xca01 8bpp */
  uint16_t sassequence; /* always: RNS_UD_SAS_DEL (0xAA03) */
  uint32_t kb_layout;   /* 0x409: US keyboard layout */
  uint32_t client_build;/* build number of client, 2600 */
  uint32_t client_name; /* unicode name, padded to 32 bytes */
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
    uint16_t type;  /* CS_SECURITY (0xC002) */
    uint16_t length;/* 12 */
  } __attribute__((__packed__)) hdr;

  // TODO: rdesktop sets this field (enc_methods) to 0x3 for some reason
  // microsoft doesn't mention 3 as a possible value
  uint32_t enc_methods; /* 0 for no enc, 2 for 128-bit */
  uint32_t ext_enc; /* 0 for non-french locale clients */
    
} __attribute__((__packed__)) client_security_data;



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

  rdp_iso_pkt iso;
  uint16_t length = 30 + strlen(COOKIE_USERNAME);

  iso.tpkt.version = 3;
  iso.tpkt.reserved = 0;
  iso.tpkt.length = htons(length);

  iso.itu_t.hdrlen = length - 5;
  iso.itu_t.code = ISO_PDU_CR;
  iso.itu_t.dst_ref = 0;
  iso.itu_t.src_ref = 0;
  iso.itu_t.class_num = 0;

  con->outbuf->append(&iso, sizeof(rdp_iso_pkt));

  /* It appears that we need to send a username cookie */
  con->outbuf->snprintf(strlen("Cookie: mstshash="), "%s",
      "Cookie: mstshash=");
  con->outbuf->snprintf(strlen(COOKIE_USERNAME), "%s", COOKIE_USERNAME);
  con->outbuf->snprintf(2, "%c%c", '\r', '\n');


}


static int
rdp_iso_connection_confirm(Connection *con)
{

  rdp_iso_pkt *iso;

  iso = (rdp_iso_pkt *) ((const char *)con->inbuf->get_dataptr());

  if (iso->tpkt.version != 3)
    fatal("rdp_module: not supported version: %d\n", iso->tpkt.version);

  if (iso->itu_t.code != ISO_PDU_CC)
    return -1;

  return 0;
}


/* 
 * Client MCS Connect Initial PDU with GCC Conference Create Request
 * Constructs the packet which is is described at:
 * http://msdn.microsoft.com/en-us/library/cc240508%28v=PROT.10%29.aspx
 */
static int
rdp_mcs_connect(Connection *con)
{
  Buf *iso = new Buf();
  Buf *mcs = new Buf(); 
  /* TODO: consider instead of creating separate Bufs and merging them at the
   * end, to extend the Buf()'s class functions where you can push and pop data
   * out of it.
   */
  gcc_ccr ccr;
  client_core_data ccd;
  client_security_data csd;
    
  int length = 158 + 76 + 12 + 4;
  unsigned int num_channels = 1;

  length += num_channels * 12 + 8;

  /* Fill in the mcs_data first:
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
  ccr.word4 = htons(length | 0x8000);
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
  ccd.hdr.length = 212;
  ccd.version1 = 1; //TODO: this is RD4 for now, change later
  ccd.version2 = 8;
  ccd.width = 800;
  ccd.height = 600;
  ccd.depth = 0xca01;
  ccd.sassequence = 0xaa03;
  ccd.kb_layout = 0x409;
  ccd.client_build = 2600;
  Strncpy(&ccd.client_name, FAKE_HOSTNAME, sizeof(FAKE_HOSTNAME));
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

      rdp_mcs_connect(con);

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());


    case RDP_FINI:

      printf("fini\n");

      break;



  }




}



