
/***************************************************************************
 * ncrack_rdp.cc -- ncrack module for RDP                                  *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
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
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
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
#include <map>

using namespace std;
bool rdp_discmap_initialized = false;
map <int, const char *> rdp_discmap;

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
extern void ncrack_module_end(nsock_pool nsp, void *mydata);


typedef struct rdp_state {

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
  int decrypt_use_count;
  uint32_t server_public_key_length;
  uint16_t mcs_userid;
  uint32_t shareid;

  u_char *rdp_packet;
  u_char *rdp_next_packet;
  u_char *rdp_packet_end;
  uint16_t packet_len;

  int login_result;

  uint8_t order_state_type;

  typedef struct order_memblt {
    uint8_t color_table;
    uint8_t cache_id;
    int16_t x;
    int16_t y;
    int16_t cx;
    int16_t cy;
    uint8_t opcode;
    int16_t srcx;
    int16_t srcy;
    uint16_t cache_idx;
  } order_memblt;

  bool win7_vista_fingerprint;

  order_memblt memblt;

} rdp_state;


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
static void rdp_encrypt_data(Connection *con, uint8_t *data, uint32_t datalen,
    uint32_t flags);
static void rdp_mcs_data(Connection *con, uint16_t datalen);
static void rdp_security_exchange(Connection *con);
static void rdp_client_info(Connection *con);
static u_char *rdp_mcs_recv_data(Connection *con, uint16_t *channel);
static u_char *rdp_secure_recv_data(Connection *con);
static u_char *rdp_recv_data(Connection *con, uint8_t *pdu_type);
static void rdp_data(Connection *con, Buf *data, uint8_t pdu_type);
static void rdp_synchronize(Connection *con);
static void rdp_control(Connection *con, uint16_t action);
static void rdp_confirm_active(Connection *con);
static void rdp_input_msg(Connection *con, uint32_t time, uint16_t message_type,
    uint16_t device_flags, uint16_t param1, uint16_t param2);
static void rdp_scancode_msg(Connection *con, uint32_t time, uint16_t flags,
    uint8_t scancode);
static void rdp_demand_active_confirm(Connection *con, u_char *p);
static int rdp_parse_rdpdata_pdu(Connection *con, u_char *p);
static char *rdp_disc_reason(uint32_t code);
static void rdp_fonts_send(Connection *con, uint16_t sequence);
static void rdp_disconnect(Connection *con);
static u_char *rdp_iso_recv_data_loop(Connection *con);
static void rdp_parse_update_pdu(Connection *con, u_char *p);
static void rdp_parse_orders(Connection *con, u_char *p, uint16_t num);
static void rdp_parse_second_order(u_char *p);
static u_char *rdp_parse_destblt(u_char *p, uint32_t params, bool delta);
static u_char *rdp_coord(u_char *p, bool delta, int16_t *coord = NULL);
static u_char *rdp_parse_brush(u_char *p, uint32_t params);
static u_char *rdp_parse_patblt(u_char *p, uint32_t params, bool delta);
static u_char *rdp_parse_screenblt(u_char *p, uint32_t params, bool delta);
static u_char *rdp_parse_line(u_char *p, uint32_t params, bool delta);
static u_char *rdp_parse_pen(u_char *p, uint32_t params);
static u_char *rdp_color(u_char *p);
static u_char *rdp_parse_rect(u_char *p, uint32_t params, bool delta);
static u_char *rdp_parse_desksave(u_char *p, uint32_t params, bool delta);
static u_char *rdp_parse_memblt(u_char *p, uint32_t params, bool delta, rdp_state *info);
static u_char *rdp_parse_triblt(u_char *p, uint32_t params, bool delta);
static u_char *rdp_parse_polygon(u_char *p, uint32_t params, bool delta);
static u_char *rdp_parse_polygon2(u_char *p, uint32_t params, bool delta);
static u_char *rdp_parse_ellipse(u_char *p, uint32_t params, bool delta);
static u_char *rdp_parse_ellipse2(u_char *p, uint32_t params, bool delta);
static u_char *rdp_parse_text2(Connection *con, u_char *p, uint32_t params, bool delta);
static u_char *rdp_parse_ber(u_char *p, int tag, int *length);


/* RDP PDU codes */
enum RDP_PDU_TYPE
{
  RDP_PDU_DEMAND_ACTIVE = 1,
	RDP_PDU_CONFIRM_ACTIVE = 3,
	RDP_PDU_REDIRECT = 4,	/* Standard Server Redirect */
	RDP_PDU_DEACTIVATE = 6,
	RDP_PDU_DATA = 7,
	RDP_PDU_ENHANCED_REDIRECT = 10	/* Enhanced Server Redirect */  
};


enum RDP_DATA_PDU_TYPE
{
 	RDP_DATA_PDU_UPDATE = 2,
	RDP_DATA_PDU_CONTROL = 20,
	RDP_DATA_PDU_POINTER = 27,
	RDP_DATA_PDU_INPUT = 28,
	RDP_DATA_PDU_SYNCHRONISE = 31,
	RDP_DATA_PDU_BELL = 34,
	RDP_DATA_PDU_CLIENT_WINDOW_STATUS = 35,
	RDP_DATA_PDU_LOGON = 38,	/* PDUTYPE2_SAVE_SESSION_INFO */
	RDP_DATA_PDU_FONT2 = 39,
	RDP_DATA_PDU_KEYBOARD_INDICATORS = 41,
	RDP_DATA_PDU_DISCONNECT = 47,
	RDP_DATA_PDU_AUTORECONNECT_STATUS = 50
};

enum RDP_UPDATE_PDU_TYPE
{
  RDP_UPDATE_ORDERS = 0,
  RDP_UPDATE_BITMAP = 1,
  RDP_UPDATE_PALETTE = 2,
  RDP_UPDATE_SYNCHRONISE = 3
};


#define RDP_ORDER_STANDARD   0x01
#define RDP_ORDER_SECONDARY  0x02
#define RDP_ORDER_BOUNDS     0x04
#define RDP_ORDER_CHANGE     0x08
#define RDP_ORDER_DELTA      0x10
#define RDP_ORDER_LASTBOUNDS 0x20
#define RDP_ORDER_SMALL      0x40
#define RDP_ORDER_TINY       0x80

enum RDP_ORDER_TYPE
{
  RDP_ORDER_DESTBLT = 0,
  RDP_ORDER_PATBLT = 1,
  RDP_ORDER_SCREENBLT = 2,
  RDP_ORDER_LINE = 9,
  RDP_ORDER_RECT = 10,
  RDP_ORDER_DESKSAVE = 11,
  RDP_ORDER_MEMBLT = 13,
  RDP_ORDER_TRIBLT = 14,
  RDP_ORDER_POLYGON = 20,
  RDP_ORDER_POLYGON2 = 21,
  RDP_ORDER_POLYLINE = 22,
  RDP_ORDER_ELLIPSE = 25,
  RDP_ORDER_ELLIPSE2 = 26,
  RDP_ORDER_TEXT2 = 27
};


/* ISO PDU codes */
enum ISO_PDU_CODE
{
  ISO_PDU_CR = 0xE0,  /* Connection Request */
  ISO_PDU_CC = 0xD0,  /* Connection Confirm */
  ISO_PDU_DR = 0x80,  /* Disconnect Request */
  ISO_PDU_DT = 0xF0,  /* Data */
  ISO_PDU_ER = 0x70   /* Error */
};

enum RDP_INPUT_DEVICE
{
  RDP_INPUT_SYNCHRONIZE = 0,
  RDP_INPUT_CODEPOINT = 1,
  RDP_INPUT_VIRTKEY = 2,
  RDP_INPUT_SCANCODE = 4,
  RDP_INPUT_MOUSE = 0x8001
};


enum RDP_CONTROL_PDU_TYPE
{
  RDP_CTL_REQUEST_CONTROL = 1,
  RDP_CTL_GRANT_CONTROL = 2,
  RDP_CTL_DETACH = 3,
  RDP_CTL_COOPERATE = 4
};

#define RDP_KEYPRESS 0

#define CS_CORE 0xC001;
#define CS_SECURITY 0xC002;
#define CS_NET 0xC003;
#define CS_CLUSTER 0xC004;

#define MCS_CONNECT_INITIAL 0x7f65
#define MCS_CONNECT_RESPONSE 0x7f66
#define MCS_GLOBAL_CHANNEL 1003
#define MCS_USERCHANNEL_BASE 1001
#define MCS_SDIN 26 /* Send Data Indication */
#define MCS_DPUM 8 /* Disconnect Provider Ultimatum */

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
#define SEC_CLIENT_RANDOM 0x0001
#define SEC_ENCRYPT 0x0008
#define SEC_LOGON_INFO 0x0040
#define SEC_LICENCE_NEG 0x0080

#define RDP_LOGON_AUTO 0x0008
#define RDP_LOGON_NORMAL 0x0033


enum states { RDP_INIT, RDP_CON, RDP_MCS_RESP, RDP_MCS_AURQ, RDP_MCS_AUCF,
  RDP_MCS_CJ_USER, RDP_SEC_EXCHANGE, RDP_CLIENT_INFO,
  RDP_DEMAND_ACTIVE, RDP_DEMAND_ACTIVE_SYNC, RDP_DEMAND_ACTIVE_INPUT_SYNC,
  RDP_DEMAND_ACTIVE_FONTS, RDP_LOOP };


enum login_results { LOGIN_INIT, LOGIN_FAIL, LOGIN_ERROR, LOGIN_SUCCESS };



/* RDP header */
typedef struct rdp_hdr_data {

  uint16_t length;
  uint16_t code;
  uint16_t mcs_userid;
  uint32_t shareid;
  uint8_t pad;
  uint8_t streamid;
  uint16_t remaining_length;
  uint8_t type;
  uint8_t compress_type;
  uint16_t compress_len;

  rdp_hdr_data() {
    code = RDP_PDU_DATA | 0x10;
    pad = 0;
    streamid = 1;
    compress_type = 0;
    compress_len = 0;
  }

} __attribute__((__packed__)) rdp_hdr_data;


typedef struct rdp_input_event {

  uint16_t num_events;
  uint16_t pad;
  uint32_t time;
  uint16_t message_type;
  uint16_t device_flags;
  uint16_t param1;
  uint16_t param2;

  rdp_input_event() {
    num_events = 1;
    pad = 0;
  }

} __attribute__((__packed__)) rdp_input_event;


typedef struct rdp_fonts {

  uint16_t num_fonts;
  uint16_t pad;
  uint16_t seq;
  uint16_t entry_size;

  rdp_fonts() {
    num_fonts = 0;
    pad = 0;
    entry_size = 0x32;
  }

} __attribute__((__packed__)) rdp_fonts;


typedef struct rdp_sync {

  uint16_t type;
  uint16_t type2;

  rdp_sync() {
    type = 1;
    type2 = 1002;
  }
} __attribute__((__packed__)) rdp_sync;


typedef struct rdp_ctrl {

  uint16_t action;
  uint16_t user_id;
  uint32_t control_id;

  rdp_ctrl() {
    user_id = 0;
    control_id = 0;
  }
} __attribute__((__packed__)) rdp_ctrl;


/* 
 * Client Confirm Active PDU
 * http://msdn.microsoft.com/en-us/library/cc240487%28v=PROT.10%29.aspx
 */
#define RDP_SOURCE "MSTSC"
typedef struct rdp_confirm_active_pdu {

  uint16_t length;
  uint16_t type;
  uint16_t mcs_userid;
  uint32_t shareid;
  uint16_t userid;
  uint16_t source_len;
  uint16_t caplen;
  u_char source[sizeof(RDP_SOURCE)];
  uint16_t num_caps;
  uint8_t pad[2];

  rdp_confirm_active_pdu() {

    type = RDP_PDU_CONFIRM_ACTIVE | 0x10;
    userid = 0x3ea;
    source_len = sizeof(RDP_SOURCE);
    memcpy(source, RDP_SOURCE, sizeof(RDP_SOURCE));
    num_caps = 0xd;
    memset(&pad, 0, sizeof(pad));
  } 

} __attribute__((__packed__)) rdp_confirm_active_pdu;


/* RDP capabilities */
#define RDP_CAPSET_GENERAL 1  /* generalCapabilitySet in T.128 p.138 */
#define RDP_CAPLEN_GENERAL 0x18
typedef struct rdp_general_caps {

  uint16_t type;
  uint16_t len;

  uint16_t os_major;
  uint16_t os_minor;
  uint16_t protocol_version;
  uint16_t pad;
  uint16_t compression_type;
  uint16_t pad2; /* careful with this, might trigger rdp5 */
  uint16_t update_cap;
  uint16_t remote_unshare_cap;
  uint16_t compression_level;
  uint16_t pad3;

  rdp_general_caps() {

    type = RDP_CAPSET_GENERAL;
    len = RDP_CAPLEN_GENERAL;
    os_major = 1;
    os_minor = 3;
    protocol_version = 0x200;
    pad = 0;
    compression_type = 0;
    pad2 = 0;
    update_cap = 0;
    remote_unshare_cap = 0;
    compression_level = 0;
    pad3 = 0;
  }

} __attribute__((__packed__)) rdp_general_caps;


#define RDP_CAPSET_BITMAP 2
#define RDP_CAPLEN_BITMAP 0x1C
typedef struct rdp_bitmap_caps { 

  uint16_t type;
  uint16_t len;
  uint16_t bpp;
  uint16_t bpp1;
  uint16_t bpp2;
  uint16_t bpp3;
  uint16_t width;
  uint16_t height;
  uint16_t pad;
  uint16_t allow_resize;
  uint16_t compression;
  uint16_t unknown1;
  uint16_t unknown2;
  uint16_t pad2;

  rdp_bitmap_caps() {
    type = RDP_CAPSET_BITMAP;
    len = RDP_CAPLEN_BITMAP;
    bpp = 8;
    bpp1 = 1;
    bpp2 = 1;
    bpp3 = 1;
    width = 800;
    height = 600;
    pad = 0;
    allow_resize = 1;
    compression = 1;
    unknown1 = 0;
    unknown2 = 1;
    pad2 = 0;
  } 

} __attribute__((__packed__)) rdp_bitmap_caps;


#define RDP_CAPSET_ORDER 3
#define RDP_CAPLEN_ORDER 0x58
typedef struct rdp_order_caps {

  uint16_t type;
  uint16_t len;
  uint8_t term_desc[20];
  uint16_t cache_x;
  uint16_t cache_y;
  uint16_t pad;
  uint16_t max_order;
  uint16_t num_fonts;
  uint16_t cap_flags;

  struct order {

    uint8_t dest_blt;
    uint8_t pat_blt;
    uint8_t screen_blt;
    uint8_t mem_blt;
    uint8_t tri_blt;
    uint8_t pad[3];
    uint8_t line1;
    uint8_t line2;
    uint8_t rect;
    uint8_t desksave;
    uint8_t pad2;
    uint8_t mem_blt2;
    uint8_t tri_blt2;
    uint8_t pad3[5];
    uint8_t polygon1;
    uint8_t polygon2;
    uint8_t polyline;
    uint8_t pad4[2];
    uint8_t ellipse1;
    uint8_t ellipse2;
    uint8_t text2;
    uint8_t pad5[4];
    
    order() {
      dest_blt = 1;
      pat_blt = 1;
      screen_blt = 1;
      mem_blt = 1;
      tri_blt = 0;
      memset(&pad, 0, sizeof(pad));
      line1 = 1;
      line2 = 1;
      rect = 1;
      desksave = 1;
      pad2 = 0;
      mem_blt2 = 1;
      tri_blt2 = 1;
      memset(&pad3, 0, sizeof(pad3));
      polygon1 = 1;
      polygon2 = 1;
      polyline = 1;
      memset(&pad4, 0, sizeof(pad4));
      ellipse1 = 1;
      ellipse2 = 1;
      text2 = 1;
      memset(&pad5, 0, sizeof(pad5));
    }

  } __attribute__((__packed__)) order;
  
  uint16_t text_cap_flags;
  uint8_t pad2[6];
  uint32_t desk_cache_size;
  uint32_t unknown1;
  uint32_t unknown2;

  rdp_order_caps() {
    type = RDP_CAPSET_ORDER;
    len = RDP_CAPLEN_ORDER;
    memset(&term_desc, 0, sizeof(term_desc));
    cache_x = 1;
    cache_y = 20;
    pad = 0;
    max_order = 1;
    num_fonts = 0x147;
    cap_flags = 0x2a;
    order;
    text_cap_flags = 0x6a1;
    memset(&pad2, 0, sizeof(pad2));
    desk_cache_size = 0x38400;
    unknown1 = 0;
    unknown2 = 0x4e4;
  }

} __attribute__((__packed__)) rdp_order_caps;


#define RDP_CAPSET_BMPCACHE 4
#define RDP_CAPLEN_BMPCACHE 0x28
typedef struct rdp_bmpcache_caps {

  uint16_t type;
  uint16_t len;
  uint8_t unused[24];
  uint16_t entries1;
  uint16_t max_cell_size1;
  uint16_t entries2;
  uint16_t max_cell_size2;
  uint16_t entries3;
  uint16_t max_cell_size3;

  rdp_bmpcache_caps() {
    type = RDP_CAPSET_BMPCACHE;
    len = RDP_CAPLEN_BMPCACHE;
    memset(&unused, 0, sizeof(unused));
    entries1 = 0x258;
    max_cell_size1 = 0x100 * ((8 + 7) / 8);
    entries2 = 0x12c;
    max_cell_size2 = 0x400 * ((8 + 7) / 8);
    entries3 = 0x106;
    max_cell_size3 = 0x1000 * ((8 + 7) / 8);
  }

} __attribute__((__packed__)) rdp_bmpcache_caps;


#define RDP_CAPSET_COLCACHE 10
#define RDP_CAPLEN_COLCACHE 0x08
typedef struct rdp_colcache_caps {

  uint16_t type;
  uint16_t len;
  uint16_t cache_size;
  uint16_t pad;

  rdp_colcache_caps() {
    type = RDP_CAPSET_COLCACHE;
    len = RDP_CAPLEN_COLCACHE;
    cache_size = 6;
    pad = 0;
  }

} __attribute__((__packed__)) rdp_colcache_caps;


#define RDP_CAPSET_ACTIVATE 7
#define RDP_CAPLEN_ACTIVATE 0x0C
typedef struct rdp_activate_caps { 

  uint16_t type;
  uint16_t len;
  uint16_t help_key;
  uint16_t help_index_key;
  uint16_t extended_help_key;
  uint16_t windows_activate;

  rdp_activate_caps() {
    type = RDP_CAPSET_ACTIVATE;
    len = RDP_CAPLEN_ACTIVATE;
    help_key = 0;
    help_index_key = 0;
    extended_help_key = 0;
    windows_activate = 0;
  }

} __attribute__((__packed__)) rdp_activate_caps;


#define RDP_CAPSET_CONTROL 5
#define RDP_CAPLEN_CONTROL 0x0C
typedef struct rdp_control_caps {

  uint16_t type;
  uint16_t len;
  uint16_t control_caps;
  uint16_t remote_detach;
  uint16_t control_interest;
  uint16_t detach_interest;

  rdp_control_caps() {
    type = RDP_CAPSET_CONTROL;
    len = RDP_CAPLEN_CONTROL;
    control_caps = 0;
    remote_detach = 0;
    control_interest = 2;
    detach_interest = 2;
  }

} __attribute__((__packed__)) rdp_control_caps;


#define RDP_CAPSET_POINTER 8
#define RDP_CAPLEN_POINTER 0x08
typedef struct rdp_pointer_caps {
  
  uint16_t type;
  uint16_t len;
  uint16_t color_ptr;
  uint16_t cache_size;

  rdp_pointer_caps() {
    type = RDP_CAPSET_POINTER;
    len = RDP_CAPLEN_POINTER;
    color_ptr = 0;
    cache_size = 20;
  }

} __attribute__((__packed__)) rdp_pointer_caps;


#define RDP_CAPSET_SHARE 9
#define RDP_CAPLEN_SHARE 0x08
typedef struct rdp_share_caps { 

  uint16_t type;
  uint16_t len;
  uint16_t userid;
  uint16_t pad;

  rdp_share_caps() {
    type = RDP_CAPSET_SHARE;
    len = RDP_CAPLEN_SHARE;
    userid = 0;
    pad = 0;
  } 

} __attribute__((__packed__)) rdp_share_caps;


static uint8_t caps_0x0d_array[] = {
  0x01, 0x00, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00,
  0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

typedef struct rdp_caps_0x0d {
  uint16_t id;
  uint16_t length;
  uint8_t caps[sizeof(caps_0x0d_array)];

  rdp_caps_0x0d() {
    id = 0x0d;
    length = 0x58;
    memcpy(caps, caps_0x0d_array, sizeof(caps_0x0d_array));
  }

} __attribute__((__packed__)) rdp_caps_0x0d;


static uint8_t caps_0x0c_array[] = { 0x01, 0x00, 0x00, 0x00 };

typedef struct rdp_caps_0x0c {
  uint16_t id;
  uint16_t length;
  uint8_t caps[sizeof(caps_0x0c_array)];

  rdp_caps_0x0c() {
    id = 0x0c;
    length = 0x08;
    memcpy(caps, caps_0x0c_array, sizeof(caps_0x0c_array));
  }

} __attribute__((__packed__)) rdp_caps_0x0c;


static uint8_t caps_0x0e_array[] = { 0x01, 0x00, 0x00, 0x00 };

typedef struct rdp_caps_0x0e {
  uint16_t id;
  uint16_t length;
  uint8_t caps[sizeof(caps_0x0e_array)];

  rdp_caps_0x0e() {
    id = 0x0e;
    length = 0x08;
    memcpy(caps, caps_0x0e_array, sizeof(caps_0x0e_array));
  }

} __attribute__((__packed__)) rdp_caps_0x0e;


static uint8_t caps_0x10_array[] = {
  0xFE, 0x00, 0x04, 0x00, 0xFE, 0x00, 0x04, 0x00,
  0xFE, 0x00, 0x08, 0x00, 0xFE, 0x00, 0x08, 0x00,
  0xFE, 0x00, 0x10, 0x00, 0xFE, 0x00, 0x20, 0x00,
  0xFE, 0x00, 0x40, 0x00, 0xFE, 0x00, 0x80, 0x00,
  0xFE, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x08,
  0x00, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00
};

typedef struct rdp_caps_0x10 {
  uint16_t id;
  uint16_t length;
  uint8_t caps[sizeof(caps_0x10_array)];

  rdp_caps_0x10() {
    id = 0x10;
    length = 0x34;
    memcpy(caps, caps_0x10_array, sizeof(caps_0x10_array));
  }

} __attribute__((__packed__)) rdp_caps_0x10;


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

  uint32_t flags; /* normally SEC_ENCRYPT etc */
  uint8_t sig[8]; /* signature */

} __attribute__((__packed__)) sec_header;


/* Generic Conference Control (T.124) ConferenceCreateRequest 
 * T124 Section 8.7: http://www.itu.int/rec/T-REC-T.124-200701-I/en 
 */
typedef struct gcc_conference_create_request {
  /* be = big endian, le = little endian */
  /* The above document is a bit fuzzy in which names correspond to which
   * variables, thus no particular names were given to them */

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

  /* Rdesktop sets this field (enc_methods) to 0x3 for some reason
   * microsoft doesn't mention 3 as a possible value */
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

static uint8_t pad0[8] = {
  0, 0, 0, 0, 0, 0, 0, 0
};

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
  u_char *ioptr;

  /* Make sure we get at least 4 bytes: this is the TPKT header which
   * contains the total size of the message
   */
  if (con->inbuf == NULL || con->inbuf->get_len() < 4) {
    nsock_read(nsp, con->niod, ncrack_read_handler, RDP_TIMEOUT, con);
    return -1;
  }

  /* Get message length from TPKT header. It is in big-endian byte order */
  ioptr = (u_char *)con->inbuf->get_dataptr() + 2;
  memcpy(&total_length, ioptr, sizeof(total_length));

  total_length = ntohs(total_length); /* convert to host-byte order */

  /* If we haven't received all the bytes of the message, according to the
   * total length that we calculated, then try and get the rest */
  if (con->inbuf == NULL || con->inbuf->get_len() < total_length) {
    nsock_read(nsp, con->niod, ncrack_read_handler, RDP_TIMEOUT, con);
    return -1;
  }

  return 0;

}


static u_char *
rdp_parse_ber(u_char *p, int tag, int *length)
{
  int len;

  if (tag > 0xFF)
    p += 2;
  else 
    p += 1;
  
  len = *(uint8_t *)p;
  p += 1;

  if (len & 0x80) {
    len &= ~0x80;
    *length = 0;
    while (len--) {
      *length = (*length << 8) + *(p++);
    }
  } else 
    *length = len;

  return p;
}



/*****************************************************************************
 * Prepares a Disconnect packet, which only consists of an ISO message with the
 * appropriate code (ISO_PDU_DR). The resulting headers are placed in Ncrack's
 * 'outbuf' buffer.
 */
static void
rdp_disconnect(Connection *con)
{
  iso_tpkt tpkt;
  iso_itu_t itu_t;

  tpkt.version = 3;
  tpkt.reserved = 0;
  tpkt.length = htons(11);

  itu_t.hdrlen = 6;
  itu_t.code = ISO_PDU_DR;
  itu_t.dst_ref = 0;
  itu_t.src_ref = 0;
  itu_t.class_num = 0;

  con->outbuf->append(&tpkt, sizeof(tpkt));
  con->outbuf->append(&itu_t, sizeof(iso_itu_t));

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

  if (itu_t->code != ISO_PDU_CC) {
    con->service->end.orly = true;
    con->service->end.reason = Strndup("TPKT Connection denied.", 23);
    return -1;
  }

  return 0;
}


/* 
 * Prepares an ISO header (TPKT and ITU_T) 
 * the 'datalen' is the number of bytes following this header.
 * This usually means the size of the MCS header + the size of the
 * security header (if it exists) + the size of any additional data
 * (rdp_data)
 */
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
  ccr.word10 = 0x61637544;  /* OEM ID: "Duca" */
  ccr.word11 = htons((length - 14) | 0x8000);


  /* Client Core Data (TS_UD_CS_CORE)
   * http://msdn.microsoft.com/en-us/library/cc240510%28v=PROT.10%29.aspx
   */
  ccd.hdr.type = CS_CORE;
  ccd.hdr.length = 212;
  ccd.version1 = 1;   /* RDP 4 by default */
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


static void
rdp_demand_active_confirm(Connection *con, u_char *p)
{
  
  rdp_state *info = (rdp_state *)con->misc_info;

  /* Store the shareid and ingore the rest of the data in this packet */
  info->shareid = *(uint32_t *)p;

  /* Now prepare the confirm active egress data */
  rdp_confirm_active(con);
}



/*****************************************************************************
 * Maps disconnection error codes to human readable text. Upon first
 * invocation, it initializes an STL map accordingly. It then performs a lookup
 * based on the 32bit 'code' that gets as input. The message string is
 * dynamically allocated here, so the caller is responsible for freeing it
 * later.
 */
static char *
rdp_disc_reason(uint32_t code)
{
  char *ret;

  if (rdp_discmap_initialized == false) {
    rdp_discmap_initialized = true;

    rdp_discmap.insert(make_pair<int, const char*>(0x0000, "No information available"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0001, "Server initiated disconnect"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0002, "Server initiated logoff"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0003, "Server idle timeout reached"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0004, "Server logon timeout reached"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0005, "The session was replaced"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0006, "The server is out of memory"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0007, "The server denied the connection"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0008,
          "The server denied the connection for security reason"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0100, "Internal licensing error"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0101, "No license server available"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0102, "No valid license available"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0103, "Invalid licensing message"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0104,
          "Hardware id doesn't match software license"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0105, "Client license error"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0106,
          "Network error during licensing protocol"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0107,
          "Licensing protocol was not completed"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0108,
          "Incorrect client license enryption"));
    rdp_discmap.insert(make_pair<int, const char*>(0x0109, "Can't upgrade license"));
    rdp_discmap.insert(make_pair<int, const char*>(0x010a,
          "The server is not licensed to accept remote connections"));
    rdp_discmap.insert(make_pair<int, const char*>(-1,
          "Internal protocol error / Unknown reason"));
  }

  map<int, const char*>::iterator mi = rdp_discmap.end();
  mi = rdp_discmap.find(code);
  if (mi == rdp_discmap.end()) {
    /* fallback to key -1 */
    mi = rdp_discmap.find(-1);
  }
  ret = Strndup(mi->second, strlen(mi->second));

  return ret;
}



static u_char *
rdp_parse_brush(u_char *p, uint32_t params)
{

  if (params & 1)
    p += 1;
  if (params & 2)
    p += 1;
  if (params & 4)
    p += 1;
  if (params & 8)
    p += 1;
  if (params & 16)
    p += 7;

  return p;
}



static u_char *
rdp_parse_pen(u_char *p, uint32_t params)
{
  if (params & 1)
    p += 1;
  if (params & 2)
    p += 1;
  if (params & 4)
    p = rdp_color(p);

  return p;
}


/* The following are currently extracted from the rdesktop bruteforcing
 * patches.
 */

/* This appears to indicate that our attempt has failed in some way */
#define LOGON_AUTH_FAILED "\xfe\x00\x00"

/* The system could not log you on. Make sure your User name and domain are correct [FAILED] */
#define LOGON_MESSAGE_FAILED_XP  "\x17\x00\x18\x06\x10\x06\x1a\x09\x1b\x05\x1a\x06\x1c\x05\x10\x04\x1d\x06"
#define LOGON_MESSAGE_FAILED_2K3 "\x11\x00\x12\x06\x13\x06\x15\x09\x16\x05\x15\x06\x17\x05\x13\x04\x18\x06"

/* The system can log you on but you do not have the allow log on using
 * terminal services right (not in remote desktop group) [SUCCESS]*/
#define LOGON_MESSAGE_NOT_IN_RDESKTOP_GROUP "\x11\x00\x12\x06\x14\x09\x12\x02\x15\x06\x12\x09\x16\x06\x17\x09\x12\x04"

/* The local policy of this system does not permit you to logon interactively. [SUCCESS] */
#define LOGON_MESSAGE_NO_INTERACTIVE_XP "\x17\x00\x18\x06\x10\x06\x11\x09\x1a\x02\x0f\x06\x0d\x05\x11\x06\x1b\x05"
#define LOGON_MESSAGE_NO_INTERACTIVE_2K3 "\x11\x00\x12\x06\x13\x06\x15\x09\x16\x02\x17\x06\x18\x05\x15\x06\x19\x05"

/* Unable to log you on because your account has been locked out */
#define LOGON_MESSAGE_LOCKED_XP  "\x17\x00\x0e\x07\x0d\x06\x18\x06\x11\x06\x10\x02\x1a\x09\x1b\x04\x11\x09"
#define LOGON_MESSAGE_LOCKED_2K3 "\x11\x00\x12\x07\x13\x06\x14\x06\x15\x06\x16\x02\x18\x09\x19\x04\x15\x09"

/* Your account has been disabled. Please see your system administrator. [ERROR] */
/* Your account has expired. Please see your system administrator. [ERROR] */
#define LOGON_MESSAGE_DISABLED_XP  "\x17\x00\x18\x06\x19\x06\x1a\x06\x0d\x07\x0f\x06\x0f\x05\x18\x05\x19\x06"
#define LOGON_MESSAGE_DISABLED_2K3 "\x11\x00\x12\x06\x13\x06\x14\x06\x16\x07\x17\x06\x17\x05\x12\x05\x13\x06"

/* Your password has expired and must be changed. [SUCCESS] */
#define LOGON_MESSAGE_EXPIRED_XP  "\x17\x00\x18\x06\x19\x06\x0d\x09\x1b\x06\x10\x04\x1b\x09\x10\x04\x1c\x06"
#define LOGON_MESSAGE_EXPIRED_2K3 "\x11\x00\x12\x06\x13\x06\x14\x06\x16\x07\x17\x06\x18\x06\x18\x05\x19\x05"

/* You are required to change your password at first logon. [SUCCESS] */
#define LOGON_MESSAGE_MUST_CHANGE_XP  "\x17\x00\x18\x06\x19\x06\x0d\x09\x1b\x06\x10\x04\x1b\x09\x10\x04\x1c\x06"
#define LOGON_MESSAGE_MUST_CHANGE_2K3 "\x11\x00\x12\x06\x13\x06\x15\x09\x16\x06\x17\x04\x16\x09\x17\x04\x18\x06"

/* The terminal server has exceeded the maximum number of allowed connections. [SUCCESS] */
#define LOGON_MESSAGE_MSTS_MAX_2K3 "\x00\x00\x01\x06\x02\x07\x01\x07\x05\x07\x24\x0a\x25\x0a\x0b\x07\x0b\x06\x26"

/* The user MACHINE_NAME\USER is currently logged on to this computer. [SUCCESS] */
#define LOGON_MESSAGE_CURRENT_USER_XP "\x12\x00\x13\x07\x10\x05\x14\x06\x0e\x07\x0d\x06\x16\x06\x10\x08\x17\x06"


static u_char *
rdp_parse_text2(Connection *con, u_char *p, uint32_t params, bool delta)
{
  uint8_t length;
  u_char text[256];
  rdp_state *info = (rdp_state *)con->misc_info;
  const char *hostinfo = con->service->HostInfo();

  if (params & 0x000001)
    p += 1;
  if (params & 0x000002)
    p += 1;
  if (params & 0x000004)
    p += 1;
  if (params & 0x000008)
    p += 1;
  if (params & 0x000010)
    p = rdp_color(p);
  if (params & 0x000020)
    p = rdp_color(p);
  if (params & 0x000040)
    p += 2;
  if (params & 0x000080)
    p += 2;
  if (params & 0x000100)
    p += 2;
  if (params & 0x000200)
    p += 2;
  if (params & 0x000400)
    p += 2;
  if (params & 0x000800)
    p += 2;
  if (params & 0x001000)
    p += 2;
  if (params & 0x002000)
    p += 2;

  p = rdp_parse_brush(p, params >> 14);

  if (params & 0x080000)
    p += 2;
  if (params & 0x100000)
    p += 2;

  if (params & 0x200000) {
    length = *(uint8_t *)p;
    p += 1;
    if (length <= sizeof(text))
      memcpy(text, p, length);
    p += length;
    if (length > sizeof(text)) {
      if (o.debugging > 2)
        fprintf(stderr, "Text message too long!\n");
      return p;
    }
  }

  if (!memcmp(text, LOGON_AUTH_FAILED, 3))
    if (o.debugging > 8)
      fprintf(stderr, "Retrieved connection termination packet.\n");

  if ((!memcmp(text, LOGON_MESSAGE_FAILED_XP, 18))
      || (!memcmp(text, LOGON_MESSAGE_FAILED_2K3, 18))) {
    info->login_result = LOGIN_FAIL;
    if (o.debugging > 8)
      log_write(LOG_PLAIN, "%s Account credentials are NOT valid.\n", hostinfo);

  } else if ((!memcmp(text, LOGON_MESSAGE_NOT_IN_RDESKTOP_GROUP, 18))) {
    info->login_result = LOGIN_SUCCESS;
    if (o.verbose)
      log_write(LOG_PLAIN, "%s Account credentials are valid, however, the "
        "account does not have the log on through terminal services right "
        "(not in remote desktop users group).\n", hostinfo);

  } else if ((!memcmp(text, LOGON_MESSAGE_NO_INTERACTIVE_XP, 18))
      || (!memcmp(text, LOGON_MESSAGE_NO_INTERACTIVE_2K3, 18))) {
    info->login_result = LOGIN_SUCCESS;
    if (o.verbose)
      log_write(LOG_PLAIN, "%s Account credentials are valid, however,"
          "the account is denied interactive logon.\n", hostinfo);

  } else if ((!memcmp(text, LOGON_MESSAGE_LOCKED_XP, 18)) 
      || (!memcmp(text, LOGON_MESSAGE_LOCKED_2K3, 18))) {
    info->login_result = LOGIN_ERROR;
    if (o.verbose)
      log_write(LOG_PLAIN, "%s Account is currently locked out.\n", hostinfo);

  } else if ((!memcmp(text, LOGON_MESSAGE_DISABLED_XP, 18)) 
      || (!memcmp(text, LOGON_MESSAGE_DISABLED_2K3, 18))) {
    info->login_result = LOGIN_ERROR;
    if (o.verbose)
      log_write(LOG_PLAIN, "%s Account is currently disabled or expired. "
        "XP appears to report that an account is disabled only for valid "
        "credentials.\n", hostinfo);

  } else if ((!memcmp(text, LOGON_MESSAGE_EXPIRED_XP, 18))
      || (!memcmp(text, LOGON_MESSAGE_EXPIRED_2K3, 18))) {
    info->login_result = LOGIN_SUCCESS;
    if (o.verbose) 
      log_write(LOG_PLAIN, "%s Account credentials are valid, however, the "
          "password has expired and must be changed.\n", hostinfo);

  } else if ((!memcmp(text, LOGON_MESSAGE_MUST_CHANGE_XP, 18)) 
      || (!memcmp(text, LOGON_MESSAGE_MUST_CHANGE_2K3, 18))) {
    info->login_result = LOGIN_SUCCESS;
    if (o.verbose)
      log_write(LOG_PLAIN, "%s Account credentials are valid, however, the "
          "password must be changed at first logon.\n", hostinfo);

  } else if (!memcmp(text, LOGON_MESSAGE_MSTS_MAX_2K3, 18)) {
    info->login_result = LOGIN_SUCCESS;
    if (o.verbose)
      log_write(LOG_PLAIN, "%s Account credentials are valid, however, the "
          "maximum number of terminal services connections has been "
          "reached.\n", hostinfo);

  } else if (!memcmp(text, LOGON_MESSAGE_CURRENT_USER_XP, 18)) {
    info->login_result = LOGIN_SUCCESS;
    if (o.verbose)
      log_write(LOG_PLAIN, "%s Valid credentials, however, another user is "
          "currently logged on.\n", hostinfo);

  } else {
    if (o.debugging > 8)
      fprintf(stderr, "Text: irrelevant message\n");

  }


  return p;
}



static u_char *
rdp_parse_ellipse(u_char *p, uint32_t params, bool delta)
{

  if (params & 0x01)
    p = rdp_coord(p, delta);
  if (params & 0x02)
    p = rdp_coord(p, delta);
  if (params & 0x04)
    p = rdp_coord(p, delta);
  if (params & 0x08)
    p = rdp_coord(p, delta);
  if (params & 0x10)
    p += 1;
  if (params & 0x20)
    p += 1;
  if (params & 0x40)
    p = rdp_color(p);

  return p;
}



static u_char *
rdp_parse_ellipse2(u_char *p, uint32_t params, bool delta)
{

  if (params & 0x0001)
    p = rdp_coord(p, delta);
  if (params & 0x0002)
    p = rdp_coord(p, delta);
  if (params & 0x0004)
    p = rdp_coord(p, delta);
  if (params & 0x0008)
    p = rdp_coord(p, delta);
  if (params & 0x0010)
    p += 1;
  if (params & 0x0020)
    p += 1;
  if (params & 0x0040)
    p = rdp_color(p);
  if (params & 0x0080)
    p = rdp_color(p);

  p = rdp_parse_brush(p, params >> 8);

  return p;
}



static u_char *
rdp_parse_polyline(u_char *p, uint32_t params, bool delta)
{
  uint8_t datasize;

  if (params & 0x01)
    p = rdp_coord(p, delta);
  if (params & 0x02)
    p = rdp_coord(p, delta);
  if (params & 0x04)
    p += 1;
  if (params & 0x10)
    p = rdp_color(p);
  if (params & 0x20)
    p += 1;
  if (params & 0x40) {
    datasize = *(uint8_t *)p;
    p += 1;
    p += datasize;
  }

  return p;
}


static u_char *
rdp_parse_polygon(u_char *p, uint32_t params, bool delta)
{
  uint8_t datasize;

  if (params & 0x01)
    p = rdp_coord(p, delta);
  if (params & 0x02)
    p = rdp_coord(p, delta);
  if (params & 0x04)
    p += 1;
  if (params & 0x08)
    p += 1;
  if (params & 0x10)
    p = rdp_color(p);
  if (params & 0x20)
    p += 1;
  if (params & 0x40) {
    datasize = *(uint8_t *)p;
    p += 1;
    p += datasize;
  }

  return p;
}


static u_char *
rdp_parse_polygon2(u_char *p, uint32_t params, bool delta)
{
  uint8_t datasize;

  if (params & 0x0001)
    p = rdp_coord(p, delta);
  if (params & 0x0002)
    p = rdp_coord(p, delta);
  if (params & 0x0004)
    p += 1;
  if (params & 0x0008)
    p += 1;
  if (params & 0x0010)
    p = rdp_color(p);
  if (params & 0x0020)
    p = rdp_color(p);

  p = rdp_parse_brush(p, params >> 6);

  if (params & 0x0800)
    p += 1;
  if (params & 0x1000) {
    datasize = *(uint8_t *)p;
    p += 1;
    p += datasize;
  }

  return p;
}



static u_char *
rdp_parse_triblt(u_char *p, uint32_t params, bool delta)
{

  if (params & 0x000001)
    p += 2;
  if (params & 0x000002)
    p = rdp_coord(p, delta);
  if (params & 0x000004)
    p = rdp_coord(p, delta);
  if (params & 0x000008)
    p = rdp_coord(p, delta);
  if (params & 0x000010)
    p = rdp_coord(p, delta);
  if (params & 0x000020)
    p += 1;
  if (params & 0x000040)
    p = rdp_coord(p, delta);
  if (params & 0x000080)
    p = rdp_coord(p, delta);
  if (params & 0x000100)
    p = rdp_color(p);
  if (params & 0x000200)
    p = rdp_color(p);

  p = rdp_parse_brush(p, params >> 10);

  if (params & 0x008000)
    p += 2;
  if (params & 0x010000)
    p += 2;

  return p;
}


static u_char *
rdp_parse_memblt(u_char *p, uint32_t params, bool delta, rdp_state *info)
{

  if (params & 0x0001) {
    info->memblt.cache_id = *(uint8_t *)p;
    p += 1;
    info->memblt.color_table = *(uint8_t *)p;
    p += 1;
  }

  if (params & 0x0002)
    p = rdp_coord(p, delta, &info->memblt.x);

  if (params & 0x0004)
    p = rdp_coord(p, delta, &info->memblt.y);

  if (params & 0x0008)
    p = rdp_coord(p, delta, &info->memblt.cx);

  if (params & 0x0010)
    p = rdp_coord(p, delta, &info->memblt.cy);

  if (params & 0x0020) {
    info->memblt.opcode = *(uint8_t *)p;
    p += 1;
  }

  if (params & 0x0040)
    p = rdp_coord(p, delta, &info->memblt.srcx);

  if (params & 0x0080)
    p = rdp_coord(p, delta, &info->memblt.srcy);

  if (params & 0x0100) {
    info->memblt.cache_idx = *(uint16_t *)p;
    p += 2;
  }

  /* This is a fingerprint for Windows 7, Windows Vista, Windows Server
   * 2008. These specific values for the memblt always appear when your
   * credentials fail to authenticate. The Microsoft RDP server from Windows
   * Vista and above doesn't send any text message -> inside a text order <-
   * unlike what happens in Windows XP etc. Consequently, we needed to
   * inspect the RDP packets deeper and search for patterns that always
   * appear whenever we fail to authenticate. This specific pattern has to
   * do (most probably) with the coordinates of the 'OK' button that appears
   * at the bottom of the screen when Windows tells us that our credentials
   * weren't correct.
   */
  if (info->memblt.opcode == 0xcc &&
      info->memblt.x == 740 &&
      info->memblt.y == 448 &&
      info->memblt.cx == 60 &&
      info->memblt.cy == 56 &&
      info->memblt.cache_id == 2) {
    if (o.debugging > 8)
      printf(" ======================= WIN_7 FAIL ==============\n");
    info->login_result = LOGIN_FAIL;
    info->win7_vista_fingerprint = true;
  }

  if (o.debugging > 8)
    printf("MEMBLT(op=0x%x,x=%d,y=%d,cx=%d,cy=%d,id=%d,idx=%d)\n",
         info->memblt.opcode, info->memblt.x, info->memblt.y, info->memblt.cx,
         info->memblt.cy, info->memblt.cache_id, info->memblt.cache_idx);

  return p;
}



static u_char *
rdp_parse_desksave(u_char *p, uint32_t params, bool delta)
{
  if (params & 0x01)
    p += 4;
  if (params & 0x02)
    p = rdp_coord(p, delta);
  if (params & 0x04)
    p = rdp_coord(p, delta);
  if (params & 0x08)
    p = rdp_coord(p, delta);
  if (params & 0x10)
    p = rdp_coord(p, delta);
  if (params & 0x20)
    p += 1;

  return p;
} 




static u_char *
rdp_parse_rect(u_char *p, uint32_t params, bool delta)
{
  if (params & 0x01)
    p = rdp_coord(p, delta);
  if (params & 0x02)
    p = rdp_coord(p, delta);
  if (params & 0x04)
    p = rdp_coord(p, delta);
  if (params & 0x08)
    p = rdp_coord(p, delta);
  if (params & 0x10)
    p += 1;
  if (params & 0x20)
    p += 1;
  if (params & 0x40)
    p += 1;

  return p;
}




static u_char *
rdp_parse_line(u_char *p, uint32_t params, bool delta)
{
  if (params & 0x0001)
    p += 2;
  if (params & 0x0002)
    p = rdp_coord(p, delta);
  if (params & 0x0004)
    p = rdp_coord(p, delta);
  if (params & 0x0008)
    p = rdp_coord(p, delta);
  if (params & 0x0010)
    p = rdp_coord(p, delta);
  if (params & 0x0020)
    p = rdp_color(p);
  if (params & 0x0040)
    p += 1;

  p = rdp_parse_pen(p, params >> 7);

  return p;
}



static u_char *
rdp_parse_screenblt(u_char *p, uint32_t params, bool delta)
{
  if (params & 0x0001)
    p = rdp_coord(p, delta);
  if (params & 0x0002)
    p = rdp_coord(p, delta);
  if (params & 0x0004)
    p = rdp_coord(p, delta);
  if (params & 0x0008)
    p = rdp_coord(p, delta);
  if (params & 0x0010)
    p += 1;
  if (params & 0x0020)
    p = rdp_coord(p, delta);
  if (params & 0x0040)
    p = rdp_coord(p, delta);

  return p;
}



static u_char *
rdp_parse_patblt(u_char *p, uint32_t params, bool delta)
{
  if (params & 0x0001)
    p = rdp_coord(p, delta);
  if (params & 0x0002)
    p = rdp_coord(p, delta);
  if (params & 0x0004)
    p = rdp_coord(p, delta);
  if (params & 0x0008)
    p = rdp_coord(p, delta);
  if (params & 0x0010)
    p += 1;
  if (params & 0x0020)
    p = rdp_color(p);
  if (params & 0x0040)
    p = rdp_color(p);

  p = rdp_parse_brush(p, params >> 7);

  return p;
}


static u_char *
rdp_parse_destblt(u_char *p, uint32_t params, bool delta)
{

  if (params & 0x01)
    p = rdp_coord(p, delta);
  if (params & 0x02)
    p = rdp_coord(p, delta);
  if (params & 0x04)
    p = rdp_coord(p, delta);
  if (params & 0x08)
    p = rdp_coord(p, delta);
  if (params & 0x10)
    p += 1;

  return p;
}


static u_char *
rdp_color(u_char *p)
{
  p += 3;
  return p;
}


static u_char *
rdp_coord(u_char *p, bool delta, int16_t *coord)
{
  int8_t change;

  if (delta) {
    if (coord) {
      change = *(uint8_t *)p;
      *coord += change;
    }
    p += 1;
  } else {
    if (coord) {
      *coord = *(uint16_t *)p;
    }
    p += 2;
  }

  return p;
}



static void
rdp_parse_orders(Connection *con, u_char *p, uint16_t num)
{
  uint16_t parsed = 0;
  uint8_t flags;
  int size, temp_size;
  uint32_t params;
  bool delta;
  rdp_state *info = (rdp_state *)con->misc_info;

  while (parsed < num) {

    flags = *(uint8_t *)p;
    p += 1;

    if ((!flags & RDP_ORDER_STANDARD)) {
      if (o.debugging > 8)
        printf("%s error parsing orders\n", __func__);
      break;
    }

    if (flags & RDP_ORDER_SECONDARY) {

      /* parse secondary order: we just ignore everything here after we parse
       * the length field to know how many bytes to skip to move on to the next
       * order
       */
      uint16_t second_length = *(uint16_t *)p; 
      p += 2;
      /* skip secondary flags */
      p += 2;
      /* skip type */
      p += 1;
      /* now add length and ignore that many bytes */
      p += (int16_t) second_length + 7;

    }

    else {

      if (flags & RDP_ORDER_CHANGE) {
        info->order_state_type = *(uint8_t *)p;
        p += 1;

      }

      switch (info->order_state_type) {
        case RDP_ORDER_TRIBLT:
        case RDP_ORDER_TEXT2:
          size = 3;
          break;

        case RDP_ORDER_PATBLT:
        case RDP_ORDER_MEMBLT:
        case RDP_ORDER_LINE:
        case RDP_ORDER_POLYGON2:
        case RDP_ORDER_ELLIPSE2:
          size = 2;
          break;

        default:
          size = 1;
      }

      /* Check parameters present */
      temp_size = size;

      if (flags & RDP_ORDER_SMALL)
        temp_size--;

      if (flags & RDP_ORDER_TINY) {
        if (temp_size < 2)
          temp_size = 0;
        else
          temp_size -= 2;
      }

      params = 0;
      uint8_t bits;
      for (int i = 0; i < temp_size; i++) {
        bits = *(uint8_t *)p;
        p += 1;
        params |= bits << (i * 8);
      }

      if (flags & RDP_ORDER_BOUNDS) {
        if (!(flags & RDP_ORDER_LASTBOUNDS)) {

          uint8_t bounds = *(uint8_t *)p;
          p += 1;

          if (bounds & 1)
            p += 2;
          else if (bounds & 16)
            p += 1;

          if (bounds & 2)
            p += 2;
          else if (bounds & 32)
            p += 1;

          if (bounds & 4)
            p += 2;
          else if (bounds & 64)
            p += 1;

          if (bounds & 8)
            p += 2;
          else if (bounds & 128)
            p += 1;

        } 
      }

      delta = flags & RDP_ORDER_DELTA;
     
      switch (info->order_state_type) {

        case RDP_ORDER_DESTBLT:
          if (o.debugging > 9)
            printf(" ORDER DESTBLT \n");
          p = rdp_parse_destblt(p, params, delta);
          break;

        case RDP_ORDER_PATBLT:
          if (o.debugging > 9)
            printf(" ORDER PATBLT\n");
          p = rdp_parse_patblt(p, params, delta);
          break;

        case RDP_ORDER_SCREENBLT:
          if (o.debugging > 9)
            printf(" ORDER SCREENBLT\n");
          p = rdp_parse_screenblt(p, params, delta);
          break;

        case RDP_ORDER_LINE:
          if (o.debugging > 9)
            printf(" ORDER LINE\n");
          p = rdp_parse_line(p, params, delta);
          break;

        case RDP_ORDER_RECT:
          if (o.debugging > 9)
            printf(" ORDER RECT\n");
          p = rdp_parse_rect(p, params, delta);
          break;

        case RDP_ORDER_DESKSAVE:
          if (o.debugging > 9)
            printf(" ORDER DESKSAVE\n");
          p = rdp_parse_desksave(p, params, delta);
          break;

        case RDP_ORDER_MEMBLT:
          if (o.debugging > 9)
            printf(" ORDER MEMBLT\n");
          p = rdp_parse_memblt(p, params, delta, info);
          break;

        case RDP_ORDER_TRIBLT:
          if (o.debugging > 9)
            printf(" ORDER TRIBLT\n");
          p = rdp_parse_triblt(p, params, delta);
          break;

        case RDP_ORDER_POLYGON:
          if (o.debugging > 9)
            printf(" ORDER POLYGON\n");
          p = rdp_parse_polygon(p, params, delta);
          break;

        case RDP_ORDER_POLYGON2:
          if (o.debugging > 9)
            printf(" ORDER POLYGON 2 \n");
          p = rdp_parse_polygon2(p, params, delta);
          break;

        case RDP_ORDER_POLYLINE:
          if (o.debugging > 9)
            printf(" ORDER  POLYLINE \n");
          p = rdp_parse_polyline(p, params, delta);
          break;

        case RDP_ORDER_ELLIPSE:
          if (o.debugging > 9)
            printf(" ORDER ELLIPSE\n");
          p = rdp_parse_ellipse(p, params, delta);
          break;

        case RDP_ORDER_ELLIPSE2:
          if (o.debugging > 9)
            printf(" ORDER ELLIPSE 2 \n");
          p = rdp_parse_ellipse2(p, params, delta);
          break;

        case RDP_ORDER_TEXT2:
          if (o.debugging > 9)
            printf("------> PARSE TEXT <------- \n");
          p = rdp_parse_text2(con, p, params, delta);
          break;

        default:
          if (o.debugging > 9)
            printf("Unimplemented order %u\n", info->order_state_type);
          return;

      }

    }

    parsed++;
  }

}




static void
rdp_parse_update_pdu(Connection *con, u_char *p)
{

  uint16_t type;
  uint16_t num_orders;

  type = *(uint16_t *)p;
  p += 2;

  switch (type) {

    case RDP_UPDATE_ORDERS:

      if (o.debugging > 8)
        printf(" -----> UPDATE ORDERs\n");
      p += 2; /* padding */
      num_orders = *(uint16_t *)p;
      p += 2;
      p += 2; /* more padding */
      rdp_parse_orders(con, p, num_orders);

      break;

    case RDP_UPDATE_BITMAP:
      break;

    case RDP_UPDATE_PALETTE:
      break;

    case RDP_UPDATE_SYNCHRONISE:
      break;

    default:
      if (o.debugging > 8)
        printf("Update PDU unimplemented: %u\n", type);
  }

}




/*****************************************************************************
 * Parses an RDP data PDU. A disconnection PDU is one example and is useful for
 * realizing why the RDP server decided to choke on us and close the
 * connection.
 */
static int
rdp_parse_rdpdata_pdu(Connection *con, u_char *p)
{
  rdp_state *info = (rdp_state *)con->misc_info;
  uint8_t pdu_type;
  uint32_t disc_reason;
  char *disc_msg;

  /* Skip shareid, padding and streamid */
  p += 6;

  /* Skip len */
  p += 2;

  /* Get pdu type */
  pdu_type = *(uint8_t *)p;
  p += 1;

  /* Skip compression type and compression len */
  p += 1;
  p += 2;


  switch (pdu_type) {

    case RDP_DATA_PDU_UPDATE:
      if (o.debugging > 8)
        printf(" -- DATA PDU UPDATE\n");
      rdp_parse_update_pdu(con, p);
      break;

    case RDP_DATA_PDU_CONTROL:
      if (o.debugging > 8)
        printf(" -- DATA PDU CONTROL\n");
      break;

    case RDP_DATA_PDU_SYNCHRONISE:
      if (o.debugging > 8)
        printf(" -- DATA PDU SYNC\n");
      break;

    case RDP_DATA_PDU_POINTER:
      if (o.debugging > 8)
        printf(" -- DATA PDU POINTER\n");
      break;

    case RDP_DATA_PDU_BELL:
      break;

    case RDP_DATA_PDU_DISCONNECT:
      disc_reason = *(uint32_t *)p;
      p += 4;
      disc_msg = rdp_disc_reason(disc_reason);
      if (o.debugging > 8)
        log_write(LOG_PLAIN, "RDP: Disconnected: %s\n", disc_msg);
      free(disc_msg);
      /* Don't disconnect because Windows Vista and Windows 7 always send a
       * disconnect PDU, when you authenticate correctly, with reason 0 */
      //return -1;
      break;

    case RDP_DATA_PDU_LOGON:
      if (o.debugging > 8) {
        printf("=========LOGIN SUCCESSFUL=======\n");
        printf("user: %s pass %s\n", con->user, con->pass);
      }
      return 1;
      break;

    default:
      if (o.debugging > 8)
        printf("PDU data unimplemented %u\n", pdu_type);
      break;
  }

  return 0;

}


enum { LOOP_WRITE, LOOP_DISC, LOOP_NOTH, LOOP_AUTH };
static int
rdp_process_loop(Connection *con)
{
  bool loop = true;
  bool disc = false;
  uint8_t pdu_type = 0;
  rdp_state *info = (rdp_state *)con->misc_info;
  u_char *p;
  int pdudata_ret;

  if (o.debugging > 8)
    printf(" --------------------------------------- FUNCTION LOOP ---------------------------------\n");

  while (loop) {

    if (o.debugging > 8)
      printf(" ------------------ RDP LOOP -----------------\n");

    p = rdp_recv_data(con, &pdu_type);
    if (p == NULL) {
      if (o.debugging > 8)
        printf("LOOP NOTH NULL DATA\n");

      //con->inbuf->get_data(NULL, info->packet_len);
      //info->packet_len = 0;
      //info->rdp_packet = NULL;
      return LOOP_NOTH;
    }

    switch (pdu_type) {
      case RDP_PDU_DEMAND_ACTIVE:
        if (o.debugging > 8)
          printf("PDU DEMAND ACTIVE\n");
        rdp_demand_active_confirm(con, p);
        break;

      case RDP_PDU_DEACTIVATE:
        if (o.debugging > 8)
          printf("PDU deactivate\n");
        break;

      case RDP_PDU_REDIRECT:
        if (o.debugging > 8)
          printf("PDU REDIRECT\n");
        break;

      case RDP_PDU_DATA:
        if (o.debugging > 8)
          printf("PDU DATA\n");
        pdudata_ret = rdp_parse_rdpdata_pdu(con, p);
        if (pdudata_ret == 1) {
          info->login_result = LOGIN_SUCCESS;
        } else if (pdudata_ret == -1) {
          return LOOP_DISC;
        }

        break;

      default:
        if (o.debugging > 8)
          printf("PDU default\n");
        break;

    }

    loop = info->rdp_next_packet < info->rdp_packet_end;

  }

  con->inbuf->get_data(NULL, info->packet_len);
  info->packet_len = 0;
  info->rdp_packet = NULL;

  if (info->login_result != LOGIN_INIT)
    return LOOP_AUTH;

  switch (pdu_type) {
    case RDP_PDU_DEMAND_ACTIVE:
      return LOOP_WRITE;
    case RDP_PDU_DEACTIVATE:
    case RDP_PDU_REDIRECT:
    case RDP_PDU_DATA:
    default:
      return LOOP_NOTH;
  }

}




static u_char *
rdp_recv_data(Connection *con, uint8_t *pdu_type)
{
  rdp_state *info = (rdp_state *)con->misc_info;
  uint16_t length;

  /* WARNING: This only supports RDP version 4 */

  if (info->rdp_packet == NULL) {

    info->rdp_packet = rdp_secure_recv_data(con);
    if (info->rdp_packet == NULL) {
      if (o.debugging > 8)
        printf("rdp packet NULL!\n");
      return NULL;
    } 
    info->rdp_next_packet = info->rdp_packet;

    /* Time to get the next TCP segment */
  } else if ((info->rdp_next_packet >= info->rdp_packet_end) 
      || (info->rdp_next_packet == NULL)) {

    if (o.debugging > 8)
      printf(" RECV DATA TCP NEXT SEGMENT\n");
    /* Eat away the ISO packet */
    con->inbuf->get_data(NULL, info->packet_len);
    return NULL;

  } else {

    if (o.debugging > 8)
      printf("NEXT PACKET\n");
    info->rdp_packet = info->rdp_next_packet;
  }


  /* Get the length */
  length = *(uint16_t *)info->rdp_packet;
  info->rdp_packet += 2;

  /* Get pdu type */
  *pdu_type = *(uint16_t *)info->rdp_packet & 0xf;
  info->rdp_packet += 2;

  /* Skip userid */
  info->rdp_packet += 2;

  if (o.debugging > 8)
    printf("    RDP length: %u\n", length);
  info->rdp_next_packet += length;

#if 0
  printf("-----------DATA--------\n");
  char *string = hexdump((u8*)info->rdp_packet, length);
  log_write(LOG_PLAIN, "%s", string);
  printf("-----------DATA--------\n");
#endif

  return info->rdp_packet;
}



static u_char*
rdp_secure_recv_data(Connection *con)
{
  u_char *p;
  uint16_t channel;
  uint32_t flags;
  rdp_state *info = (rdp_state *)con->misc_info;
  uint32_t datalen;


  while ((p = rdp_mcs_recv_data(con, &channel)) != NULL) {

    flags = *(uint32_t *)p;
    p += 4;

    if (flags & SEC_ENCRYPT) {

      /* Skip signature */
      p += 8;

      /* Decrypt Data */
      if (info->decrypt_use_count == 4096) {
        /* Normally we should update our keys here, but we never get to receive
         * more than 4096 RDP packets in one authentication session (since we
         * close the connection after 1 attempt and reconnect with new keys),
         * so we don't bother with this.
         */
        info->decrypt_use_count = 0;
      }

      datalen = (info->rdp_packet_end - p);

      if (o.debugging > 8)
        printf("  Sec length: %u\n", datalen);

      RC4(&info->rc4_decrypt_key, datalen, p, p);
      info->decrypt_use_count++;
    }

    if (flags & SEC_LICENCE_NEG) {
      if (o.debugging > 8)
        printf("SEC LICENSE\n");

      /* Eat away the ISO packet */
      con->inbuf->get_data(NULL, info->packet_len);

      return NULL;
    }

    if (flags & 0x0400) {
      if (o.debugging > 8)
        printf("----SEC REDIRECT-----\n");
    }

    if (channel != MCS_GLOBAL_CHANNEL) {
      if (o.debugging > 8)
        printf("non-global channel\n");

    }

    return p;
  }

  return NULL;
}


static u_char *
rdp_mcs_recv_data(Connection *con, uint16_t *channel)
{
  u_char *p;
  char error[64];
  uint8_t opcode;
  rdp_state *info = (rdp_state *)con->misc_info;

  p = rdp_iso_recv_data_loop(con);
  if (p == NULL)
    return NULL;

  /* Check opcode */
  opcode = (*(uint8_t *)p) >> 2;
  p += 1;

  if (opcode != MCS_SDIN) {
    if (opcode != MCS_DPUM) {
      snprintf(error, sizeof(error), "Expected data packet, but got 0x%x.",
          opcode);
      con->service->end.orly = true;
      con->service->end.reason = Strndup(error, strlen(error));
    }
    if (o.debugging > 8)
      printf(" ----------MCS ERR\n");
    return NULL;
  }

  /* Skip userid */
  p += 2;

  /* Store channel for later use (big endian value) */
  *channel = ntohs(*(uint16_t *)p);
  p += 2;

  /* Skip flags */
  p += 1;

  /* Skip length */
  uint8_t length = *(uint8_t *)p;
  p += 1;
  if (length & 0x80)
    p += 1;


  return p;
}


static u_char *
rdp_iso_recv_data_loop(Connection *con)
{
  iso_tpkt *tpkt;
  iso_itu_t_data *itu_t;
  char error[64];
  rdp_state *info = (rdp_state *)con->misc_info;
  u_char *p;

  if (o.debugging > 8)
    printf("TCP length: %u\n", con->inbuf->get_len());

  tpkt = (iso_tpkt *) ((u_char *)con->inbuf->get_dataptr());
  itu_t = (iso_itu_t_data *) ((u_char *)tpkt + sizeof(iso_tpkt));

  if (tpkt->version != 3)
    fatal("rdp_module: not supported TPKT version: %d\n", tpkt->version);

  info->packet_len = ntohs(tpkt->length);

  if (info->packet_len < 4) {
    con->service->end.orly = true;
    con->service->end.reason = Strndup("Bad tptk packet header.", 23);
    return NULL;
  }

  info->rdp_packet_end = (u_char *)tpkt + info->packet_len;

  p = ((u_char *)(itu_t) + sizeof(iso_itu_t_data));

  if (itu_t->code != ISO_PDU_DT) {
    snprintf(error, sizeof(error), "Expected data packet, but got 0x%x.",
        itu_t->code);
    con->service->end.orly = true;
    con->service->end.reason = Strndup(error, strlen(error));
    return NULL;
  }

  return p;
}


static int
rdp_iso_recv_data(Connection *con)
{
  iso_tpkt *tpkt;
  iso_itu_t_data *itu_t;
  char error[64];
  rdp_state *info = (rdp_state *)con->misc_info;


  tpkt = (iso_tpkt *) ((const char *)con->inbuf->get_dataptr());
  itu_t = (iso_itu_t_data *) ((const char *)tpkt + sizeof(iso_tpkt));

  if (tpkt->version != 3)
    fatal("rdp_module: not supported TPKT version: %d\n", tpkt->version);

  if (ntohs(tpkt->length) < 4) {
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






/*****************************************************************************
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
        " packet. %ld more bytes specified", end - real_end);
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
        /* store modulus length for later use */
        info->server_public_key_length = mod_len;

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



/*****************************************************************************
 * Parses the MCS connect response which comes as a reply from the server for
 * our MCS connect initial request. This packet contains the server's public
 * crypto key, which we store using 'rdp_get_crypto()'.
 */
static int
rdp_mcs_connect_response(Connection *con)
{
  //mcs_response *mcs;
  u_char *p;
  char error[64];

  if (rdp_iso_recv_data(con) < 0)
    return -1;

  p = ((u_char *)con->inbuf->get_dataptr() + sizeof(iso_tpkt)
      + sizeof(iso_itu_t_data));

  // mcs = (mcs_response *)p;

  int length;
  p = rdp_parse_ber(p, MCS_CONNECT_RESPONSE, &length);
  p = rdp_parse_ber(p, BER_TAG_RESULT, &length);
  uint8_t result = *(uint8_t *)p;
  p += 1;

  /* Check result parameter */
  if (result != 0) {
    snprintf(error, sizeof(error), "MCS connect result: %x\n", result);
    con->service->end.orly = true;
    con->service->end.reason = Strndup(error, strlen(error));
    return -1;
  }


  p = rdp_parse_ber(p, BER_TAG_INTEGER, &length);
  p += length;

  /* Now parse MCS_TAG_DOMAIN_PARAMS header and ignore as many bytes as the
   * length of this header.
   */
  p = rdp_parse_ber(p, MCS_TAG_DOMAIN_PARAMS, &length);
  p += length;

  p = rdp_parse_ber(p, BER_TAG_OCTET_STRING, &length);

#if 0
  p += sizeof(mcs_response);

  p++; /* now p should point to length of the header */
  uint8_t mcs_domain_len = *p;
  p += mcs_domain_len; /* ignore that many bytes */

  /* Now p points to the BER header of mcs_data - ignore header */
  p += 5;
#endif

  /* Ignore the 21 bytes of the T.124 ConferenceCreateResponse */
  p += 21;

  /* Now parse Server Data Blocks (serverCoreData, serverNetworkData,
   * serverSecurityData) 
   */
  uint8_t len = *(uint8_t *)p;
  p++;
  if (len & 0x80) {
    len = *(uint8_t *)p;
    p++;
  }

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
        p += 2;
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


/*****************************************************************************
 * Cryptographically signs and encrypts the data and puts them in Ncrack's
 * outbuf. It also creates the security header which is nothing more than the
 * 32bit flags (which must contain SEC_ENCRYPT). The security header precedes
 * the data. Since this function appends the header, the signature and the
 * encrypted data in the 'outbuf' everything preceding them, like the ISO and
 * MCS headers must already be there.
 */
static void
rdp_encrypt_data(Connection *con, uint8_t *data, uint32_t datalen,
    uint32_t flags)
{
  rdp_state *info = (rdp_state *)con->misc_info;
  sec_header sec;

  sec.flags = flags;

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
  if (info->encrypt_use_count == 4096) {
    info->encrypt_use_count = 0;
    /* Normally we should update our keys here, but we never get to receive
     * more than 4096 RDP packets in one authentication session (since we
     * close the connection after 1 attempt and reconnect with new keys),
     * so we don't bother with this.
     */
  }
  RC4(&info->rc4_encrypt_key, datalen, data, data);
  info->encrypt_use_count++;

  /* This is the security header, which is after the ISO and MCS headers */
  con->outbuf->append(&sec, sizeof(sec));
  /* Everything below the security header is the encrypted data. */
  con->outbuf->append(data, datalen);

}


/*****************************************************************************
 * Prepares a Client Security Exchange PDU. This packet contains the client's
 * random data portion needed for the cryptographic exchange. This was created
 * by using nbase's PRNG and later encrypted in the 'rdp_get_crypto()'
 * function. 
 * http://msdn.microsoft.com/en-us/library/cc240471%28v=PROT.10%29.aspx
 */
static void
rdp_security_exchange(Connection *con)
{
  /* This is the length of the data of this specific portion of the packet 
   * Things like the lengths of the rest of the headers (MCS, ISO) aren't
   * included.
   */
  uint32_t sec_length; 
  uint32_t total_length;
  uint32_t flags;
  rdp_state *info = (rdp_state *)con->misc_info;

  /* We don't use the sec_header struct here, since the security header
   * now includes only the flags field (32 bit). We also don't call
   * rdp_encrypt_data(), since the data aren't encrypted for this packet.
   */
  sec_length = info->server_public_key_length + 8; /* padding size = 8 */

  /* 4 is the length field itself and another 4 for the security header
   * (which has only the 32bit flags field)
   */
  total_length = sec_length + 4 + 4;

  total_length += sizeof(mcs_data);
  rdp_iso_data(con, total_length);
  total_length -= sizeof(mcs_data);
  rdp_mcs_data(con, total_length);

  flags = SEC_CLIENT_RANDOM;
  /* Security header part */
  con->outbuf->append(&flags, sizeof(flags));

  /* Client Security Exchange part */
  con->outbuf->append(&sec_length, sizeof(sec_length));
  con->outbuf->append(info->crypted_random, info->server_public_key_length);
  con->outbuf->append(pad0, 8); /* paddding */

}


/*****************************************************************************
 * Prepares a Client Info PDU. Secure Settings Exchange phase.
 * http://msdn.microsoft.com/en-us/library/cc240473%28v=PROT.10%29.aspx
 * http://msdn.microsoft.com/en-us/library/cc240474%28v=PROT.10%29.aspx
 * http://msdn.microsoft.com/en-us/library/cc240475%28v=PROT.10%29.aspx
 */
static void
rdp_client_info(Connection *con)
{
  Buf *data; 
  char domain[16];
  char shell[256];
  char workingdir[256];
  uint16_t username_length, password_length, domain_length,
           shell_length, workingdir_length;
  uint32_t total_length;
  uint32_t flags = RDP_LOGON_AUTO | RDP_LOGON_NORMAL;

  data = new Buf();
  domain[0] = shell[0] = workingdir[0] = 0;

  /* We need to convert every string data to its unicode equivalent.
   * unicode_alloc() dynamically allocates the data, so be sure to free the
   * memory later.
   */
  char *u_domain = unicode_alloc(domain);
  char *u_username = unicode_alloc(con->user);
  char *u_password = unicode_alloc(con->pass);
  char *u_shell = unicode_alloc(shell);
  char *u_workdingdir = unicode_alloc(workingdir);

  domain_length = strlen(domain) * 2;
  username_length = strlen(con->user) * 2;
  password_length = strlen(con->pass) * 2;
  shell_length = strlen(shell) * 2;
  workingdir_length = strlen(workingdir) * 2;

  /* Now fill in the data to our temporary buffer. These will be later
   * encrypted by rdp_encrypt_data()
   */
  data->append(pad0, 4);
  data->append(&flags, sizeof(flags));

  data->append(&domain_length, sizeof(domain_length));
  data->append(&username_length, sizeof(username_length));
  data->append(&password_length, sizeof(password_length));
  data->append(&shell_length, sizeof(shell_length));
  data->append(&workingdir_length, sizeof(workingdir_length));

  /* Make sure the minimum length is 2, which means only the unicode NULL
   * (2 bytes) character is sent. Note, that this is not the special
   * additional NULL character that follows every string for this header,
   * but the string itself denoting it is empty.
   */
  data->append(u_domain, domain_length ? domain_length : 2);
  data->append(u_username, username_length ? username_length : 2);
  data->append(pad0, 2);  /* extra unicode NULL terminator */

  data->append(u_password, password_length ? password_length : 2);
  data->append(pad0, 2);

  data->append(u_shell, shell_length ? shell_length : 2);
  data->append(u_workdingdir, workingdir_length ? workingdir_length : 2);

  /* 18 = the size of all above fields (pad0, flags and the lengths of each
   * variable
   * 10 = the size of the unicode NULL terminators for each of the above 5
   * strings, which are not included in the lengths 
   * see: http://msdn.microsoft.com/en-us/library/cc240475%28v=PROT.10%29.aspx
   */
  if (o.debugging > 8)
    printf("username: %s pass: %s\n", con->user, con->pass);

  total_length = 18 + domain_length + username_length + password_length +
    shell_length + workingdir_length + 10; 

#if 0
  printf("-----------DATA--------\n");
  char *string = hexdump((u8*)data->get_dataptr(), data->get_len());
  log_write(LOG_PLAIN, "%s", string);
  printf("-----------DATA--------\n");
#endif

  total_length += sizeof(mcs_data) + sizeof(sec_header);
  rdp_iso_data(con, total_length);
  total_length -= sizeof(mcs_data);
  rdp_mcs_data(con, total_length);

  rdp_encrypt_data(con, (uint8_t *)data->get_dataptr(), data->get_len(),
      SEC_LOGON_INFO | SEC_ENCRYPT);

  delete data;
  free(u_domain);
  free(u_username);
  free(u_password);
  free(u_shell);
  free(u_workdingdir);
}


/*****************************************************************************
 * Sends a certain scancode by calling 'rdp_input_msg()' accordingly. Note
 * that the data will be saved in Ncrack's 'outbuf'.
 */
static void
rdp_scancode_msg(Connection *con, uint32_t time, uint16_t flags,
    uint8_t scancode)
{
  rdp_input_msg(con, time, RDP_INPUT_SCANCODE, flags, scancode, 0);

}


/*****************************************************************************
 * Sends an input message - this can be for example a keystroke or a mouse
 * click. Ncrack usually needs to send the 'ENTER' scancode to emulate the
 * behaviour of pressing (or clicking) 'OK' on the window that appears
 * whenever the user authentication fails. The data are saved in
 * Ncrack's 'outbuf'.
 */
static void
rdp_input_msg(Connection *con, uint32_t time, uint16_t message_type,
    uint16_t device_flags, uint16_t param1, uint16_t param2)
{
  rdp_input_event input;
  Buf *data = new Buf();

  input.time = time;
  input.message_type = message_type;
  input.device_flags = device_flags;
  input.param1 = param1;
  input.param2 = param2;

  data->append(&input, sizeof(input));

  rdp_data(con, data, RDP_DATA_PDU_INPUT);
}


static void 
rdp_fonts_send(Connection *con, uint16_t sequence)
{
  Buf *data = new Buf();
  rdp_fonts fonts;

  fonts.seq = sequence;

  data->append(&fonts, sizeof(fonts));

  rdp_data(con, data, RDP_DATA_PDU_FONT2);
}



static void
rdp_synchronize(Connection *con)
{
  Buf *data = new Buf();
  rdp_sync sync;
  data->append(&sync, sizeof(sync));

  rdp_data(con, data, RDP_DATA_PDU_SYNCHRONISE);

}


static void
rdp_control(Connection *con, uint16_t action)
{
  Buf *data = new Buf();
  rdp_ctrl control;

  control.action = action;
  data->append(&control, sizeof(control));

  rdp_data(con, data, RDP_DATA_PDU_CONTROL);

}


static void
rdp_confirm_active(Connection *con)
{
  rdp_state *info = (rdp_state *)con->misc_info;
  rdp_confirm_active_pdu pdu;
  uint16_t caplen;
  rdp_general_caps general;
  rdp_bitmap_caps bitmap;
  rdp_order_caps order;
  rdp_bmpcache_caps bmpcache;
  rdp_colcache_caps colcache;
  rdp_activate_caps activate;
  rdp_control_caps control;
  rdp_pointer_caps pointer;
  rdp_share_caps share;
  rdp_caps_0x0d caps1;
  rdp_caps_0x0c caps2;
  rdp_caps_0x0e caps3;
  rdp_caps_0x10 caps4;
  uint16_t total_length;
  uint32_t flags = 0x0030 | SEC_ENCRYPT;
  Buf *data = new Buf();

  caplen = RDP_CAPLEN_GENERAL + RDP_CAPLEN_BITMAP + RDP_CAPLEN_ORDER
    + RDP_CAPLEN_BMPCACHE + RDP_CAPLEN_COLCACHE + RDP_CAPLEN_ACTIVATE
    + RDP_CAPLEN_CONTROL + RDP_CAPLEN_POINTER + RDP_CAPLEN_SHARE 
    + sizeof(caps1) + sizeof(caps2) + sizeof(caps3) + sizeof(caps4)
    + 4;

  pdu.length = 2 + 14 + caplen + sizeof(RDP_SOURCE);
  pdu.mcs_userid = info->mcs_userid + 1001;
  pdu.shareid = info->shareid;
  pdu.caplen = caplen;

  data->append(&pdu, sizeof(pdu));
  data->append(&general, sizeof(general));
  data->append(&bitmap, sizeof(bitmap));
  data->append(&order, sizeof(order));
  data->append(&bmpcache, sizeof(bmpcache));
  data->append(&colcache, sizeof(colcache));
  data->append(&activate, sizeof(activate));
  data->append(&control, sizeof(control));
  data->append(&pointer, sizeof(pointer));
  data->append(&share, sizeof(share));
  data->append(&caps1, sizeof(caps1));
  data->append(&caps2, sizeof(caps2));
  data->append(&caps3, sizeof(caps3));
  data->append(&caps4, sizeof(caps4));

  total_length = data->get_len();
  total_length += sizeof(mcs_data) + sizeof(sec_header);
  rdp_iso_data(con, total_length);
  total_length -= sizeof(mcs_data);
  rdp_mcs_data(con, total_length);

#if 0
  printf("-----------DATA-------- %u \n", data->get_len());
  char *string = hexdump((u8*)data->get_dataptr(), data->get_len());
  log_write(LOG_PLAIN, "%s", string);
  printf("-----------DATA--------\n");
#endif

  rdp_encrypt_data(con, (uint8_t *)data->get_dataptr(), data->get_len(), flags);

  delete data;

  /* reset order state */
  info->order_state_type = RDP_ORDER_PATBLT;
  memset(&info->memblt, 0, sizeof(info->memblt));

} 



/* 
 * must free data after completion 
 */
static void
rdp_data(Connection *con, Buf *data, uint8_t pdu_type)
{
  rdp_hdr_data hdr;
  rdp_state *info = (rdp_state *)con->misc_info;
  uint32_t flags = SEC_ENCRYPT;
  Buf *rdp = new Buf();
  uint32_t total_length;

  hdr.length = data->get_len() + sizeof(hdr);
  hdr.mcs_userid = info->mcs_userid + 1001;
  hdr.shareid = info->shareid;
  hdr.remaining_length = hdr.length - 14;
  hdr.type = pdu_type;

  rdp->append(&hdr, sizeof(hdr));
  rdp->append(data->get_dataptr(), data->get_len());

  total_length = sizeof(hdr) + data->get_len();  
  total_length += sizeof(mcs_data) + sizeof(sec_header);
  rdp_iso_data(con, total_length);
  total_length -= sizeof(mcs_data);
  rdp_mcs_data(con, total_length);

  rdp_encrypt_data(con, (uint8_t *)rdp->get_dataptr(), rdp->get_len(), flags);

  delete rdp;
  delete data;

}



void
ncrack_rdp(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  void *ioptr;
  rdp_state *info = NULL;
  int loop_val;

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

      if (rdp_iso_connection_confirm(con) < 0)
        return ncrack_module_end(nsp, con);

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

      con->state = RDP_SEC_EXCHANGE;

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

    case RDP_SEC_EXCHANGE:

      if (rdp_loop_read(nsp, con) < 0)
        break;

      con->state = RDP_CLIENT_INFO;

      if (rdp_mcs_channel_join_confirm(con) < 0)
        return ncrack_module_end(nsp, con);

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      rdp_security_exchange(con);

      delete con->inbuf;
      con->inbuf = NULL;

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case RDP_CLIENT_INFO:

      con->state = RDP_DEMAND_ACTIVE;

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      rdp_client_info(con);

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case RDP_DEMAND_ACTIVE:

      if (rdp_loop_read(nsp, con) < 0)
        break;

      con->state = RDP_DEMAND_ACTIVE;

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      loop_val = rdp_process_loop(con);
      if (loop_val != LOOP_WRITE) {
        //nsock_timer_create(nsp, ncrack_timer_handler, 0, con);
        delete con->inbuf;
        con->inbuf = NULL;
        break;
      }

      con->state = RDP_DEMAND_ACTIVE_SYNC;
      delete con->inbuf;
      con->inbuf = NULL;

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case RDP_DEMAND_ACTIVE_SYNC:

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      con->state = RDP_DEMAND_ACTIVE_INPUT_SYNC;

      rdp_synchronize(con);
      rdp_control(con, RDP_CTL_COOPERATE);
      rdp_control(con, RDP_CTL_REQUEST_CONTROL);

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case RDP_DEMAND_ACTIVE_INPUT_SYNC:


      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      con->state = RDP_DEMAND_ACTIVE_FONTS;

      rdp_input_msg(con, 0, RDP_INPUT_SYNCHRONIZE, 0, 0, 0);

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());  
      break;

    case RDP_DEMAND_ACTIVE_FONTS:

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      con->state = RDP_LOOP;

      rdp_fonts_send(con, 1);
      rdp_fonts_send(con, 2);

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());  
      break;

    case RDP_LOOP:

      if (rdp_loop_read(nsp, con) < 0)
        break;

      if (o.debugging > 8)
        printf("RDP LOOP STATE \n");
      con->state = RDP_LOOP;

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      loop_val = rdp_process_loop(con);

      switch (loop_val) {

        case LOOP_WRITE:

          con->state = RDP_DEMAND_ACTIVE_SYNC;
          nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
              (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
          break;

        case LOOP_DISC:

          delete con->inbuf;
          con->inbuf = NULL;
            
          con->force_close = true;
          rdp_disconnect(con);

          nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
              (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
          return ncrack_module_end(nsp, con);

          break;

        case LOOP_NOTH:

          nsock_timer_create(nsp, ncrack_timer_handler, 0, con);
          break;

        case LOOP_AUTH:

          if (info->login_result == LOGIN_SUCCESS) {
            con->auth_success = true;
          }
          
          delete con->inbuf;
          con->inbuf = NULL;

          con->force_close = true;
          rdp_disconnect(con);

          nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
              (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
          return ncrack_module_end(nsp, con);

          break;

        default:
          nsock_timer_create(nsp, ncrack_timer_handler, 0, con);
          break;
      }


      break;
  }

}

