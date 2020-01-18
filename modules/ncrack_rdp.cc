
/***************************************************************************
 * ncrack_rdp.cc -- ncrack module for RDP                                  *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2019 Insecure.Com LLC ("The Nmap  *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed Nmap technology into proprietary      *
 * software, we sell alternative licenses (contact sales@nmap.com).        *
 * Dozens of software vendors already license Nmap technology such as      *
 * host discovery, port scanning, OS detection, version detection, and     *
 * the Nmap Scripting Engine.                                              *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, the Nmap Project grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * The Nmap Project has permission to redistribute Npcap, a packet         *
 * capturing driver and library for the Microsoft Windows platform.        *
 * Npcap is a separate work with it's own license rather than this Nmap    *
 * license.  Since the Npcap license does not permit redistribution        *
 * without special permission, our Nmap Windows binary packages which      *
 * contain Npcap may not be redistributed without special permission.      *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, we are happy to help.  As mentioned above, we also *
 * offer an alternative license to integrate Nmap into proprietary         *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing support and updates.  They also fund the continued         *
 * development of Nmap.  Please email sales@nmap.com for further           *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify            *
 * otherwise) that you are offering the Nmap Project the unlimited,        *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because     *
 * the inability to relicense code has caused devastating problems for     *
 * other Free Software projects (such as KDE and NASM).  We also           *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
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


typedef struct stream_struct
{
  u_char *p;
  u_char *end;
  u_char *data;
  unsigned int size;
} *stream;



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

  stream assembled[0x0F];

  int login_result;

  /* 
   * hack to find pattern for RDPv5 to determine when
   * there is an authentication failure, since Windows
   * does not explicitly send a status message about that
   * if we detect a certain number of patterns a specific number
   * of times, then we can assume that this is a failure
   */
  int login_pattern_fail; 

  int rdp_version; /* 4, 5, 6 */

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
static u_char *rdp_mcs_recv_data(Connection *con, uint16_t *channel, bool *fastpath, uint8_t *fastpath_header);
static u_char *rdp_secure_recv_data(Connection *con, bool *fastpath);
static u_char *rdp_recv_data(Connection *con, uint8_t *pdu_type);
static void rdp_data(Connection *con, Buf *data, uint8_t pdu_type);
static void rdp_synchronize(Connection *con);
static void rdp_control(Connection *con, uint16_t action);
static void rdp_confirm_active(Connection *con);
static void rdp_input_msg(Connection *con, uint32_t time, uint16_t message_type,
    uint16_t device_flags, uint16_t param1, uint16_t param2);
//static void rdp_scancode_msg(Connection *con, uint32_t time, uint16_t flags,
//    uint8_t scancode);
static void rdp_demand_active_confirm(Connection *con, u_char *p);
static int rdp_parse_rdpdata_pdu(Connection *con, u_char *p);
static char *rdp_disc_reason(uint32_t code);
static void rdp_fonts_send(Connection *con, uint16_t sequence);
static void rdp_disconnect(Connection *con);
static u_char *rdp_iso_recv_data_loop(Connection *con, bool *fastpath, uint8_t *fastpath_header);
static void rdp_parse_update_pdu(Connection *con, u_char *p);
static void rdp_parse_orders(Connection *con, u_char *p, uint16_t num);
//static void rdp_parse_second_order(u_char *p);
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
static u_char *rdp_process_fastpath(Connection *con, u_char *p); 
//static u_char *rdp_parse_bitmap_update(u_char *p);
static void rdp_parse_bmpcache2(Connection *con, u_char *p, uint16_t sec_flags, bool compressed);


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

#define FASTPATH_MULTIFRAGMENT_MAX_SIZE 65535UL

#define FASTPATH_OUTPUT_ENCRYPTED 0x2
#define FASTPATH_OUTPUT_COMPRESSION_USED	(0x2 << 6)

#define FASTPATH_FRAGMENT_SINGLE	(0x0 << 4)
#define FASTPATH_FRAGMENT_LAST		(0x1 << 4)
#define FASTPATH_FRAGMENT_FIRST		(0x2 << 4)
#define FASTPATH_FRAGMENT_NEXT		(0x3 << 4)

#define RDP_MPPC_COMPRESSED	0x20

#define FASTPATH_UPDATETYPE_ORDERS		0x0
#define FASTPATH_UPDATETYPE_BITMAP		0x1
#define FASTPATH_UPDATETYPE_PALETTE		0x2
#define FASTPATH_UPDATETYPE_SYNCHRONIZE		0x3
#define FASTPATH_UPDATETYPE_SURFCMDS		0x4
#define FASTPATH_UPDATETYPE_PTR_NULL		0x5
#define FASTPATH_UPDATETYPE_PTR_DEFAULT		0x6
#define FASTPATH_UPDATETYPE_PTR_POSITION	0x8
#define FASTPATH_UPDATETYPE_COLOR		0x9
#define FASTPATH_UPDATETYPE_CACHED		0xA
#define FASTPATH_UPDATETYPE_POINTER		0xB


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

enum RDP_SECONDARY_ORDER_TYPE
{
	RDP_ORDER_RAW_BMPCACHE = 0,
	RDP_ORDER_COLCACHE = 1,
	RDP_ORDER_BMPCACHE = 2,
	RDP_ORDER_FONTCACHE = 3,
	RDP_ORDER_RAW_BMPCACHE2 = 4,
	RDP_ORDER_BMPCACHE2 = 5,
	RDP_ORDER_BRUSHCACHE = 7
};

/* RDP_BMPCACHE2_ORDER */
#define ID_MASK			0x0007
#define MODE_MASK		0x0038
#define SQUARE			0x0080
#define PERSIST			0x0100
#define FLAG_51_UNKNOWN		0x0800
#define MODE_SHIFT		3
#define LONG_FORMAT		0x80
#define BUFSIZE_MASK		0x3FFF

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

#define PERF_DISABLE_FULLWINDOWDRAG	0x02
#define PERF_DISABLE_MENUANIMATIONS	0x04
#define PERF_ENABLE_FONT_SMOOTHING	0x80

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
    num_caps = 16;
    memset(&pad, 0, sizeof(pad));
  } 

} __attribute__((__packed__)) rdp_confirm_active_pdu;


/* RDP capabilities */
#define RDP_CAPSET_GENERAL 1  /* generalCapabilitySet in T.128 p.138 */
#define RDP_CAPLEN_GENERAL 0x18
/* extraFlags, [MS-RDPBCGR] 2.2.7.1.1 */
#define FASTPATH_OUTPUT_SUPPORTED	0x0001
#define LONG_CREDENTIALS_SUPPORTED	0x0004
#define AUTORECONNECT_SUPPORTED		0x0008
#define ENC_SALTED_CHECKSUM		0x0010
#define NO_BITMAP_COMPRESSION_HDR	0x0400
typedef struct rdp_general_caps {

  uint16_t type;
  uint16_t len;

  uint16_t os_major;
  uint16_t os_minor;
  uint16_t protocol_version;
  uint16_t pad;
  uint16_t compression_type;
  uint16_t extra_flags; /* careful with this, might trigger rdp5 */
  uint16_t update_cap;
  uint16_t remote_unshare_cap;
  uint16_t compression_level;
  uint8_t refresh_rect;
  uint8_t suppress_output;

  rdp_general_caps() {

    type = RDP_CAPSET_GENERAL;
    len = RDP_CAPLEN_GENERAL;
    os_major = 1;
    os_minor = 3;
    protocol_version = 0x200;
    pad = 0;
    compression_type = 0;
    extra_flags = 0;
    update_cap = 0;
    remote_unshare_cap = 0;
    compression_level = 0;
    refresh_rect = 0;
    suppress_output = 0;
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
  uint8_t high_color_flags;
  uint8_t drawing_flags;
  uint16_t multiple_rectangle;
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
    high_color_flags = 0;
    drawing_flags = 0;
    multiple_rectangle = 1;
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


#define RDP_CAPSET_BMPCACHE2	19
#define RDP_CAPLEN_BMPCACHE2	0x28
#define BMPCACHE2_C0_CELLS	0x78
#define BMPCACHE2_C1_CELLS	0x78
#define BMPCACHE2_C2_CELLS	0x150
typedef struct rdp_bmpcache_caps2 {

  uint16_t type;
  uint16_t len;
  uint16_t bitmap_cache_persist;
  uint16_t caches_num; /* big endian */
  uint32_t bmp_c0_cells;
  uint32_t bmp_c1_cells;
  uint32_t bmp_c2_cells;
  uint8_t unused[20];

  rdp_bmpcache_caps2() {
    type = RDP_CAPSET_BMPCACHE2;
    len = RDP_CAPLEN_BMPCACHE2;
    bitmap_cache_persist = 0;
    caches_num = htons(3);
    bmp_c0_cells = BMPCACHE2_C0_CELLS;
    bmp_c1_cells = BMPCACHE2_C1_CELLS;
    bmp_c2_cells = BMPCACHE2_C2_CELLS;
    memset(&unused, 0, sizeof(unused));
  }

} __attribute__((__packed__)) rdp_bmpcache_caps2;


#define RDP_CAPSET_BRUSHCACHE	15
#define RDP_CAPLEN_BRUSHCACHE	0x08
typedef struct rdp_brushcache_caps {
  uint16_t type;
  uint16_t len;
  uint32_t cache_type;

  rdp_brushcache_caps() {
    type = RDP_CAPSET_BRUSHCACHE;
    len = RDP_CAPLEN_BRUSHCACHE;
    cache_type = 1;
  }

} __attribute__((__packed__)) rdp_brushcache_caps;


#define RDP_CAPSET_MULTIFRAGMENTUPDATE 26
#define RDP_CAPLEN_MULTIFRAGMENTUPDATE 8
typedef struct rdp_multifragment_caps {

  uint16_t type;
  uint16_t len;
  uint32_t max_request_size;

  rdp_multifragment_caps() {
    type = RDP_CAPSET_MULTIFRAGMENTUPDATE;
    len = RDP_CAPLEN_MULTIFRAGMENTUPDATE;
    max_request_size = 65535;
  }

} __attribute__((__packed__)) rdp_multifragment_caps;


#define RDP_CAPSET_LARGE_POINTER	27
#define RDP_CAPLEN_LARGE_POINTER	6
typedef struct rdp_large_pointer_caps {

  uint16_t type;
  uint16_t len;
  uint16_t flags;

  rdp_large_pointer_caps() {
    type = RDP_CAPSET_LARGE_POINTER;
    len = RDP_CAPLEN_LARGE_POINTER;
    flags = 1;
  }
  
} __attribute__((__packed__)) rdp_large_pointer_caps;


#define RDP_CAPSET_GLYPHCACHE	16
#define RDP_CAPLEN_GLYPHCACHE	52
typedef struct rdp_glyphcache_caps {
  
  uint16_t type;
  uint16_t len;
  uint16_t entries1; uint16_t maxcellsize1;
  uint16_t entries2; uint16_t maxcellsize2;
  uint16_t entries3; uint16_t maxcellsize3;
  uint16_t entries4; uint16_t maxcellsize4;
  uint16_t entries5; uint16_t maxcellsize5;
  uint16_t entries6; uint16_t maxcellsize6;
  uint16_t entries7; uint16_t maxcellsize7;
  uint16_t entries8; uint16_t maxcellsize8;
  uint16_t entries9; uint16_t maxcellsize9;
  uint16_t entries10; uint16_t maxcellsize10;
  uint32_t frag_cache;
  uint16_t glyph_support_level;
  uint16_t pad0;

  rdp_glyphcache_caps() {
    type = RDP_CAPSET_GLYPHCACHE;
    len = RDP_CAPLEN_GLYPHCACHE;
    entries1 = 254; maxcellsize1 = 4;
    entries2 = 254; maxcellsize2 = 4;
    entries3 = 254; maxcellsize3 = 8;
    entries4 = 254; maxcellsize4 = 8;
    entries5 = 254; maxcellsize5 = 16;
    entries6 = 254; maxcellsize6 = 32;
    entries7 = 254; maxcellsize7 = 64;
    entries8 = 254; maxcellsize8 = 128;
    entries9 = 254; maxcellsize9 = 256;
    entries10 = 64; maxcellsize10 = 2048;
    frag_cache = 0x01000100;
    glyph_support_level = 0x0002;
    pad0 = 0;
  }

} __attribute__((__packed__)) rdp_glyphcache_caps;


#define RDP_CAPSET_FONT		14
#define RDP_CAPLEN_FONT		8
typedef struct rdp_font_caps {
  
  uint16_t type;
  uint16_t len;
  uint16_t flags;
  uint16_t pad0;

  rdp_font_caps() {
    type = RDP_CAPSET_FONT;
    len = RDP_CAPLEN_FONT;
    flags = 0x0001;
    pad0 = 0;
  }
} __attribute__((__packed__)) rdp_font_caps;



#define RDP_CAPSET_INPUT	13
#define RDP_CAPLEN_INPUT	88
typedef struct rdp_input_caps {

  uint16_t type;
  uint16_t len;
  uint16_t flags;
  uint16_t pad0;
  uint32_t keyboard_layout;
  uint32_t keyboard_type;
  uint32_t keyboard_subtype;
  uint32_t keyboard_funckey;
  uint8_t ime_filename[64];

  rdp_input_caps() {
    type = RDP_CAPSET_INPUT;
    len = RDP_CAPLEN_INPUT;
    flags = 0x0001;
    pad0 = 0;
    keyboard_layout = 0x409;
    keyboard_type = 0x4;
    keyboard_subtype = 0;
    keyboard_funckey = 0xC;
    memset(ime_filename, 0, sizeof(ime_filename));

    //for (int i = 0; i < sizeof(ime_filename) - 1; i++) {
    //  ime_filename[i] = '\0'; 
    //  ime_filename[i+1] = 0;
    //}
  }

} __attribute__((__packed__)) rdp_input_caps;


#define RDP_CAPSET_SOUND	12
#define RDP_CAPLEN_SOUND	8
typedef struct rdp_sound_caps {

    uint16_t type;
    uint16_t len;
    uint16_t sound_flags;
    uint16_t pad0; 

    rdp_sound_caps() {
      type = RDP_CAPSET_SOUND;
      len = RDP_CAPLEN_SOUND;
      sound_flags = 0x0001;
      pad0 = 0;
    }

} __attribute__((__packed__)) rdp_sound_caps;



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


#define RDP_CAPLEN_NEWPOINTER	0x0a

typedef struct rdp_newpointer_caps {
  
  uint16_t type;
  uint16_t len;
  uint16_t color_ptr;
  uint16_t cache_size;
  uint16_t cache_size_new;

  rdp_newpointer_caps() {
    type = RDP_CAPSET_POINTER;
    len = RDP_CAPLEN_NEWPOINTER;
    color_ptr = 1;
    cache_size = 20;
    cache_size_new = 20;
  }

} __attribute__((__packed__)) rdp_newpointer_caps;


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


/* TPKT header - fastpath version */
typedef struct iso_tpkt_fast {

  uint8_t version;  /* default version = 3 */
  uint8_t length1;
  uint8_t length2;  /* total packet length (including this header) - be */

} __attribute__((__packed__)) iso_tpkt_fast;


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


/* negotiate protocol */
typedef struct iso_neg {
  uint8_t negreq;
  uint8_t zero;
  uint16_t eight;
  uint32_t neg_proto;

  iso_neg() {
    negreq = 1;  // negotiate request 
    zero = 0;
    eight = 8;
    neg_proto = 0; // RDP = 0, SSL = 1, HYBRID = 2
  }
} __attribute__((__packed__)) iso_neg;


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
  uint8_t server_selected_protocol[4]; /* all 0 */

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


/* 
 * TS_TIME_ZONE_INFORMATION  
 * (RDPv5 only)
 */
#if 0
typedef struct ts_timezone_info {

  uint32_t timezone;



} __attribute__((__packed__)) ts_timezone_info;
#endif



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

static uint8_t pad0[64] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0
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
  iso_tpkt *tpkt;
  iso_tpkt_fast *fast_tpkt = NULL;

  if (o.debugging > 9)
    printf("----rdp loop read----\n");

  /* Make sure we get at least 4 bytes: this is the TPKT header which
   * contains the total size of the message
   */
  if (con->inbuf == NULL || con->inbuf->get_len() < 4) {
    nsock_read(nsp, con->niod, ncrack_read_handler, RDP_TIMEOUT, con);
    return -1;
  }

  /* Get message length from TPKT header. It is in big-endian byte order */
  tpkt = (iso_tpkt *) ((u_char *)con->inbuf->get_dataptr());
  if (tpkt->version != 3) { // fastpath
    fast_tpkt = (iso_tpkt_fast *)((u_char *)con->inbuf->get_dataptr());
    total_length = fast_tpkt->length1;
    if (total_length & 0x80) {
      total_length &= ~0x80;
      total_length = (total_length << 8) + fast_tpkt->length2;
    }
  } else {
    total_length = ntohs(tpkt->length); // big endian
  }

  if (o.debugging > 9) {
    printf("total length: %u \n", total_length);
    printf("inbuf length: %u \n", con->inbuf->get_len());
  }

  /* If we haven't received all the bytes of the message, according to the
   * total length that we calculated, then try and get the rest */
  if (con->inbuf == NULL || con->inbuf->get_len() < total_length) {
    nsock_read(nsp, con->niod, ncrack_read_handler, RDP_TIMEOUT, con);
    return -1;
  }

  if (o.debugging > 9)
    printf("RDP LOOP READ SUCCESS length: %d \n", total_length);

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
  iso_neg neg;
  uint16_t length = 30 + strlen(COOKIE_USERNAME) + 8;  // + 8 for RDP version 5

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

  // send negotiation request 
  con->outbuf->append(&neg, sizeof(neg));

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

  uint16_t datalen = 259 + 4;
  uint16_t total_length = datalen + 115;

#if 0
  printf("total_length: mcs=%d ccr=%d ccd=%d csd=%d cluster=%d total:%d \n",
      sizeof(mcs), sizeof(ccr), sizeof(ccd), sizeof(csd), sizeof(cluster), 
      sizeof(mcs) + sizeof(ccr) + sizeof(ccd) + sizeof(csd) + sizeof(cluster));
#endif

  rdp_iso_data(con, 379 + 4);

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
  int length = 250 + 4;


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
  ccd.hdr.length = 216;
  ccd.version1 = 4;   /* RDP 5 by default -- for RDP 4 the version1 would be 1 */
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
  memset(&ccd.server_selected_protocol, 0, 4);

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

    rdp_discmap.insert(make_pair(0x0000, "No information available"));
    rdp_discmap.insert(make_pair(0x0001, "Server initiated disconnect"));
    rdp_discmap.insert(make_pair(0x0002, "Server initiated logoff"));
    rdp_discmap.insert(make_pair(0x0003, "Server idle timeout reached"));
    rdp_discmap.insert(make_pair(0x0004, "Server logon timeout reached"));
    rdp_discmap.insert(make_pair(0x0005, "The session was replaced"));
    rdp_discmap.insert(make_pair(0x0006, "The server is out of memory"));
    rdp_discmap.insert(make_pair(0x0007, "The server denied the connection"));
    rdp_discmap.insert(make_pair(0x0008,
          "The server denied the connection for security reason"));
    rdp_discmap.insert(make_pair(0x0100, "Internal licensing error"));
    rdp_discmap.insert(make_pair(0x0101, "No license server available"));
    rdp_discmap.insert(make_pair(0x0102, "No valid license available"));
    rdp_discmap.insert(make_pair(0x0103, "Invalid licensing message"));
    rdp_discmap.insert(make_pair(0x0104,
          "Hardware id doesn't match software license"));
    rdp_discmap.insert(make_pair(0x0105, "Client license error"));
    rdp_discmap.insert(make_pair(0x0106,
          "Network error during licensing protocol"));
    rdp_discmap.insert(make_pair(0x0107,
          "Licensing protocol was not completed"));
    rdp_discmap.insert(make_pair(0x0108,
          "Incorrect client license enryption"));
    rdp_discmap.insert(make_pair(0x0109, "Can't upgrade license"));
    rdp_discmap.insert(make_pair(0x010a,
          "The server is not licensed to accept remote connections"));
    rdp_discmap.insert(make_pair(-1,
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
    //if (length <= sizeof(text))
    // the above is always true because length is always <=255 
    // however, if you change the text to be less than 256, we would have a problem
    memcpy(text, p, length);
    p += length;
#if 0
    // below would always be false, because length always <= 255
    if (length > sizeof(text)) {
      if (o.debugging > 2)
        fprintf(stderr, "Text message too long!\n");
      return p;
    }
#endif
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

  if (info->memblt.opcode == 0xcc &&
      info->memblt.x == 256 &&
      info->memblt.y == 256 &&
      info->memblt.cx == 64 &&
      info->memblt.cy == 64 &&
      info->memblt.cache_id == 2) {

      info->login_pattern_fail++;

      // we need to see this pattern 6 times to indicate failure
      if (info->login_pattern_fail >= 6) {
      
        if (o.debugging > 9) 
          printf("================ WIN 2012 FAIL ================\n");
        info->login_result = LOGIN_FAIL;
        info->login_pattern_fail = 0;
      }

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
rdp_parse_bmpcache2(Connection *con, u_char *p, uint16_t sec_flags, bool compressed)
{
    uint8_t cache_id, cache_idx_low, Bpp, width, height;
    uint16_t buffer_size, cache_idx;
    //rdp_state *info = (rdp_state *) con->misc_info;

    cache_id = sec_flags & ID_MASK;
    Bpp = ((sec_flags & MODE_MASK) >> MODE_SHIFT) - 2;

    if (sec_flags & PERSIST)
      p += 8; /* skip bitmap id */

    if (sec_flags & SQUARE) {
      width = *(uint8_t *)p;
      p += 1;
      height = width;
    } else {
      width = *(uint8_t *)p;
      p += 1;
      height = *(uint8_t *)p;
      p += 1;
    }

    buffer_size = ntohs(*(uint16_t *)p);
    p += 2;
    buffer_size &= BUFSIZE_MASK;

    cache_idx = *(uint8_t *)p;
    p += 1;

    if (cache_idx & LONG_FORMAT) {
      cache_idx_low = *(uint8_t *)p;
      p += 1;
      cache_idx = ((cache_idx ^ LONG_FORMAT) << 8) + cache_idx_low;
    }

    if (o.debugging > 9)
      printf("rdp_parse_bmpcache2(), compr=%d, flags=%x, cx=%d, cy=%d, id=%d, idx=%d, Bpp=%d, bs=%d\n",
	       compressed, sec_flags, width, height, cache_id, cache_idx, Bpp, buffer_size);

#if 0
    /* Windows 2012 fail fingerprint */
    if (compressed == true &&
        sec_flags == 0x4a2 &&
        width == 64 && 
        height == 64 &&
        cache_id == 1 &&
        //cache_idx == 3 &&
        Bpp == 2 && 
        buffer_size == 25) {
      if (o.debugging > 9) 
        printf("================ WIN 2012 FAIL ================\n");
      info->login_result = LOGIN_FAIL;
    }
#endif

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

      if (o.debugging > 9)
        printf("SECONDARY ORDERS \n");

      /* parse secondary order: we just ignore everything here after we parse
       * the length field to know how many bytes to skip to move on to the next
       * order
       */
      uint16_t second_length = *(uint16_t *)p; 
      p += 2;
      uint16_t sec_flags = *(uint16_t *)p;
      p += 2;
      uint8_t sec_type = *(uint8_t *)p;
      p += 1;

      switch (sec_type)
      {
        case RDP_ORDER_RAW_BMPCACHE:
          //process_raw_bmpcache(s);
          break;
        case RDP_ORDER_COLCACHE:
          //process_colcache(s);
          break;
        case RDP_ORDER_BMPCACHE:
          //process_bmpcache(s);
          break;
        case RDP_ORDER_FONTCACHE:
          //process_fontcache(s);
          break;
        case RDP_ORDER_RAW_BMPCACHE2:
          rdp_parse_bmpcache2(con, p, sec_flags, false);	/* uncompressed */
          break;
        case RDP_ORDER_BMPCACHE2:
          rdp_parse_bmpcache2(con, p, sec_flags, true);	/* compressed */
          break;
        case RDP_ORDER_BRUSHCACHE:
          //process_brushcache(s, flags);
          break;
        default:
          if (o.debugging > 8)
             printf("process_secondary_order(), unhandled secondary order %d\n", sec_type);
      }
      
      /* now add length and ignore that many bytes */
      p += (int16_t) second_length + 7;

    } else {

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
      if (o.debugging > 8) {
        printf("PDU data unimplemented %u\n", pdu_type);
        
        rdp_state *info = (rdp_state *)con->misc_info;
        printf("============== INCOMING DATA ===============\n");
        char *string = hexdump((u8*)info->rdp_packet, info->rdp_packet_end - info->rdp_packet);
        log_write(LOG_PLAIN, "%s", string);
        printf("============= INCOMING DATA END ===============\n");
        
      }
      break;
  }

  return 0;

}

/* not used currently */
#if 0 
static u_char *
rdp_parse_bitmap_update(u_char *p)
{
  uint16_t num, width, height, bpp, Bpp, compress, buffer_size, size;
  int i = 0;

  num = *(uint16_t *)p;
  p += 2;

  printf("num: %d\n", num);

  for (i = 0; i < num; i++) {
    p += 2; // left
    p += 2; // top
    p += 2; // right
    p += 2; // bottom
    width = *(uint16_t *) p;
    p += 2; 
    height = *(uint16_t *) p;
    p += 2; 
    bpp = *(uint16_t *) p;
    Bpp = (bpp + 7) / 8;
    p += 2;
    compress = *(uint16_t *) p;
    p += 2; 
    buffer_size = *(uint16_t *) p;
    p += 2;

    if (!compress) {
      int j;
      for (j = 0; j < height; j++)
        p += width * Bpp;
      continue;
    }

    if (compress & 0x400) {
      size = buffer_size;
    } else {
      p += 2;
      size = *(uint16_t *) p;
      p += 4;
    }

    p += size; 
  }

  return p;
}
#endif



u_char *
rdp_process_fastpath_code(Connection *con, u_char *p, uint8_t code)
{
	uint16_t num;

	switch (code)
	{
		case FASTPATH_UPDATETYPE_ORDERS:
      num = *(uint16_t *) p;
      p += 2;
      if (o.debugging > 9)
        printf("RDP PARSE ORDERS \n");
			rdp_parse_orders(con, p, num);
			break;
		case FASTPATH_UPDATETYPE_BITMAP:
      p += 1;
			//p = rdp_parse_bitmap_update(p);
			break;
		case FASTPATH_UPDATETYPE_PALETTE:
      p += 2;
			//p = rdp_parse_palette(p);
			break;
		case FASTPATH_UPDATETYPE_SYNCHRONIZE:
			break;
		case FASTPATH_UPDATETYPE_PTR_NULL:
			break;
		case FASTPATH_UPDATETYPE_PTR_DEFAULT:
			break;
		case FASTPATH_UPDATETYPE_PTR_POSITION:
      p += 2;
      p += 2;
			break;
		case FASTPATH_UPDATETYPE_COLOR:
			//process_colour_pointer_pdu(s);
			break;
		case FASTPATH_UPDATETYPE_CACHED:
			//process_cached_pointer_pdu(s);
			break;
		case FASTPATH_UPDATETYPE_POINTER:
			//process_new_pointer_pdu(s);
			break;
		default:
      if (o.debugging > 9)
			  printf("unhandled opcode %d\n", code);
	}
  return p;

}

u_char *
rdp_process_fastpath(Connection *con, u_char *p)
{
  rdp_state *info = (rdp_state *)con->misc_info;
  uint8_t header, code, frag, compression, ctype = 0;
  uint16_t length;
  uint8_t *next;

  while (p < info->rdp_packet_end) {
    header = *(uint8_t *) p;
    p += 1;

    code = header & 0x0F;
    frag = header & 0x30;
    compression = header & 0xC0; 

    if (compression & FASTPATH_OUTPUT_COMPRESSION_USED) {
      ctype = *(uint8_t *) p;
      p += 1;
    }

    length = *(uint16_t *) p;
    p += 2;

    if (o.debugging > 9)
      printf("FASTPATH LENGTH: %d \n", length);

    info->rdp_next_packet = next = p + length;

    if (ctype & RDP_MPPC_COMPRESSED) {
      if (o.debugging > 9)
        printf(" ----------- COMPRESSED \n");
    }

    if (frag == FASTPATH_FRAGMENT_SINGLE) {
      rdp_process_fastpath_code(con, p, code);
    } else {
      if (o.debugging > 9)
        printf(" ---------- FRAGMENTED \n");

      if (info->assembled[code] == NULL) {
        info->assembled[code] = (stream_struct *)safe_malloc(sizeof(struct stream_struct));
        memset(info->assembled[code], 0, sizeof(struct stream_struct));

        // realloc
        u_char *data;
        if (info->assembled[code]->size < FASTPATH_MULTIFRAGMENT_MAX_SIZE) {
          data = info->assembled[code]->data;
          info->assembled[code]->size = FASTPATH_MULTIFRAGMENT_MAX_SIZE;
          info->assembled[code]->data = (u_char *)safe_realloc(data, FASTPATH_MULTIFRAGMENT_MAX_SIZE);
          info->assembled[code]->p = info->assembled[code]->data + (info->assembled[code]->p - data);
          info->assembled[code]->end = info->assembled[code]->data + (info->assembled[code]->end - data);
        }

        // reset 
        struct stream_struct tmp;
        tmp = *(info->assembled[code]);
        memset(info->assembled[code], 0, sizeof(struct stream_struct));
        info->assembled[code]->size = tmp.size;
        info->assembled[code]->end = info->assembled[code]->p = info->assembled[code]->data = tmp.data;
      }

      if (frag == FASTPATH_FRAGMENT_FIRST) {
        // reset 
        struct stream_struct tmp;
        tmp = *(info->assembled[code]);
        memset(info->assembled[code], 0, sizeof(struct stream_struct));
        info->assembled[code]->size = tmp.size;
        info->assembled[code]->end = info->assembled[code]->p = info->assembled[code]->data = tmp.data;
      }

      memcpy(info->assembled[code]->p, p, length);
      info->assembled[code]->p += length;

      if (frag == FASTPATH_FRAGMENT_LAST) {
        printf(" -------- LAST FRAGMENT \n");

        info->assembled[code]->end = info->assembled[code]->p;
        info->assembled[code]->p = info->assembled[code]->data;

        rdp_process_fastpath_code(con, info->assembled[code]->p, code);
      }
		}

    p = next;

  }
  return p;

}




enum { LOOP_WRITE, LOOP_DISC, LOOP_NOTH, LOOP_AUTH };
static int
rdp_process_loop(Connection *con)
{
  bool loop = true;
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

      // TODO: check if these 3 lines should stay here 
      con->inbuf->get_data(NULL, info->packet_len);
      info->packet_len = 0;
      info->rdp_packet = NULL;

      // we need this extra check here for RDPv5 because of fastpath
      if (info->login_result != LOGIN_INIT)
        return LOOP_AUTH;

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
      case RDP_PDU_ENHANCED_REDIRECT:
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

  if (o.debugging > 9)
    printf("-----eating away packet for length: %d \n", info->packet_len);

  con->inbuf->get_data(NULL, info->packet_len);

  if (o.debugging > 9)
    printf("-----bytes left in buf: %d \n", con->inbuf->get_len());

  if (con->inbuf->get_len() == 0) {
    delete con->inbuf;
    con->inbuf = NULL;
  }

  info->packet_len = 0;
  info->rdp_packet = NULL;

  if (info->login_result != LOGIN_INIT)
    return LOOP_AUTH;

  switch (pdu_type) {
    case RDP_PDU_DEMAND_ACTIVE:
      return LOOP_WRITE;
    case RDP_PDU_DEACTIVATE:
    case RDP_PDU_REDIRECT:
    case RDP_PDU_ENHANCED_REDIRECT:
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
  bool fastpath = false;

  if (info->rdp_packet == NULL) {

    if (o.debugging > 9)
      printf("BEFORE RDP SECURE RECV DATA \n");
    info->rdp_packet = rdp_secure_recv_data(con, &fastpath);
    if (info->rdp_packet == NULL) {
      if (o.debugging > 8)
        printf("rdp packet NULL!\n");
      return NULL;
    } 
    if (fastpath == true) {
      if (o.debugging > 9)
        printf("rdp_recv_data fastpath = true\n");
      
      rdp_process_fastpath(con, info->rdp_packet);
      return NULL;
    } 

    info->rdp_next_packet = info->rdp_packet;
    

    /* Time to get the next TCP segment */
  } else if ((info->rdp_next_packet >= info->rdp_packet_end) 
      || (info->rdp_next_packet == NULL)) {

    if (o.debugging > 9) {
      //printf("rdp_packet_end: %x \n", info->rdp_packet_end);
      //printf("rdp_next_packet: %x \n", info->rdp_next_packet);
      ;
    }

    if (o.debugging > 8)
      printf(" RECV DATA TCP NEXT SEGMENT %u\n", info->packet_len);
    /* Eat away the ISO packet */
    con->inbuf->get_data(NULL, info->packet_len);
    return NULL;

  } else {

    if (o.debugging > 8)
      printf("NEXT PACKET\n");
    info->rdp_packet = info->rdp_next_packet;
  }


  /* parse TS SHARE CONTROL HEADER */

  /* Get the length */
  length = *(uint16_t *)info->rdp_packet;
  info->rdp_packet += 2;

  if (length == 0x8000) {
    if (o.debugging > 9)
      printf(" SKIP OVER THIS MESSAGE \n");
		/* skip over this message in stream */
		info->rdp_next_packet += 8;
		return NULL;
	}

  /* Get pdu type */
  *pdu_type = *(uint16_t *)info->rdp_packet & 0xf;
  info->rdp_packet += 2;

  /* Skip userid */
  info->rdp_packet += 2;

  if (o.debugging > 8)
    printf("    RDP length: %u\n", length);
  info->rdp_next_packet += length;

  if (o.debugging > 8) {
    printf("============= INCOMING DATA ==============\n");
    char *string = hexdump((u8*)info->rdp_packet, length);
    log_write(LOG_PLAIN, "%s", string);
    printf("============== INCOMING DATA END ==============\n");
  }

  return info->rdp_packet;
}



static u_char*
rdp_secure_recv_data(Connection *con, bool *fastpath)
{
  u_char *p;
  uint16_t channel;
  uint32_t flags;
  uint8_t fastpath_flags = 0;
  uint8_t fastpath_header = 0;
  rdp_state *info = (rdp_state *)con->misc_info;
  uint32_t datalen;


  while ((p = rdp_mcs_recv_data(con, &channel, fastpath, &fastpath_header)) != NULL) {

    if (*fastpath == true) {

      if (o.debugging > 9)
        printf("fastpath in rdp_secure_recvdata\n");

      fastpath_flags = (fastpath_header & 0xc0) >> 6;
      if (fastpath_flags & FASTPATH_OUTPUT_ENCRYPTED) {

        if (o.debugging > 9)
          printf("FASTPATH OUTPUT ENCRYPTED\n");
        /* Skip signature */
        p += 8;

        datalen = (info->rdp_packet_end - p);

        if (info->decrypt_use_count == 4096)
          info->decrypt_use_count = 0;
      
        RC4(&info->rc4_decrypt_key, datalen, p, p);
        info->decrypt_use_count++;
      }
      return p;
    }

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

      if (o.debugging > 9)
        printf("  Sec length: %u\n", datalen);

      RC4(&info->rc4_decrypt_key, datalen, p, p);
      info->decrypt_use_count++;
    }

    if (flags & SEC_LICENCE_NEG) {
      if (o.debugging > 9)
        printf("SEC LICENSE\n");

      /* Eat away the ISO packet */
      con->inbuf->get_data(NULL, info->packet_len);

      return NULL;
    }

    if (flags & 0x0400) {
      if (o.debugging > 9)
        printf("----SEC REDIRECT-----\n");
    }

    if (channel != MCS_GLOBAL_CHANNEL) {
      if (o.debugging > 9)
        printf("non-global channel\n");

    }

    return p;
  }

  return NULL;
}


static u_char *
rdp_mcs_recv_data(Connection *con, uint16_t *channel, bool *fastpath, uint8_t *fastpath_header)
{
  u_char *p;
  char error[64];
  uint8_t opcode;

  p = rdp_iso_recv_data_loop(con, fastpath, fastpath_header);
  if (p == NULL)
    return NULL;

  if (*fastpath == true)
    return p;

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
rdp_iso_recv_data_loop(Connection *con, bool *fastpath, uint8_t *fastpath_header)
{
  iso_tpkt *tpkt;
  iso_tpkt_fast *fast_tpkt = NULL;
  iso_itu_t_data *itu_t;
  char error[64];
  rdp_state *info = (rdp_state *)con->misc_info;
  u_char *p;
  bool length_bigger = false;

  if (o.debugging > 8)
    printf("TCP length: %u\n", con->inbuf->get_len());

  tpkt = (iso_tpkt *) ((u_char *)con->inbuf->get_dataptr());
  itu_t = (iso_itu_t_data *) ((u_char *)tpkt + sizeof(iso_tpkt));

  // this is a fastpath pdu if the T.123 version is not 3
  if (tpkt->version != 3) {
    if (o.debugging > 8)
      printf("FASTPATH\n");
    fast_tpkt = (iso_tpkt_fast *)((u_char *)con->inbuf->get_dataptr());
    *fastpath = true;
    *fastpath_header = fast_tpkt->version;
    info->packet_len = fast_tpkt->length1;
    if (info->packet_len & 0x80) {
      if (o.debugging > 9)
        printf("length bigger\n");
      info->packet_len &= ~0x80;
      info->packet_len = (info->packet_len << 8) + fast_tpkt->length2;
      length_bigger = true;
    }
    if (o.debugging > 9) {
      printf("fastpath length: %u\n", info->packet_len);

      printf("============== FASTPATH HEADER ===============\n");
      char *string = hexdump((u8*)fast_tpkt, sizeof(iso_tpkt_fast));
      log_write(LOG_PLAIN, "%s", string);
      printf("============= FASTPATH HEADER END ===============\n");
    }

    info->rdp_packet_end = (u_char *)fast_tpkt + info->packet_len;

  } else {
    info->packet_len = ntohs(tpkt->length);
    info->rdp_packet_end = (u_char *)tpkt + info->packet_len;
  }

  if (info->packet_len < 4) {
    con->service->end.orly = true;
    con->service->end.reason = Strndup("Bad tptk packet header.", 23);
    return NULL;
  }

  if (*fastpath == true) {
    if (o.debugging > 9)
      printf("fastpath return\n");

    // if length is not bigger then iso_tpkt_fast is 1 byte less
    if (length_bigger == true) 
      p = ((u_char *)(fast_tpkt) + sizeof(iso_tpkt_fast));
    else 
      p = ((u_char *)(fast_tpkt) - 1 + sizeof(iso_tpkt_fast));
    return p;
  }


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
  uint32_t mod_len = 0;
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
  rdp_state *info = (rdp_state *)con->misc_info;
  Buf *data; 
  char domain[16];
  char shell[256];
  char workingdir[256];
  uint16_t username_length, password_length, domain_length,
           shell_length, workingdir_length;
  uint32_t total_length;
  uint32_t flags = RDP_LOGON_AUTO | RDP_LOGON_NORMAL; // TODO: test the flags 
  int packetlen = 0;
  int err;

  uint32_t rdp5_performance_flags = (PERF_DISABLE_FULLWINDOWDRAG |
				  PERF_DISABLE_MENUANIMATIONS |
				  PERF_ENABLE_FONT_SMOOTHING);


  /* length of strings in TS_EXTENDED_PACKET includes null terminator */
	int len_ip = 2 * strlen("172.16.51.1") + 2;  // TODO: change this to non-hardcoded IP
	int len_dll = 2 * strlen("C:\\WINNT\\System32\\mstscax.dll") + 2;

  time_t t = time(NULL);
	time_t tzone;
  struct tm local_time;
  struct tm gm_time;

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
  
  char *u_ip = unicode_alloc("172.16.51.1");
  char *u_dll = unicode_alloc("C:\\WINNT\\System32\\mstscax.dll");
  char *u_gtb_normal = unicode_alloc("GTB, normaltid");
  char *u_gtb_sommar = unicode_alloc("GTB, sommartid");

  domain_length = strlen(domain) * 2;
  username_length = strlen(con->user) * 2;
  password_length = strlen(con->pass) * 2;
  shell_length = strlen(shell) * 2;
  workingdir_length = strlen(workingdir) * 2;

  if (info->rdp_version == 4) {

    /* Now fill in the data to our temporary buffer. These will be later
     * encrypted by rdp_encrypt_data()
     */

    //TODO: check if these need to be explicitly sent in little endian
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

  } else {

		packetlen =
			/* size of TS_INFO_PACKET */
			4 +	/* CodePage */
			4 +	/* flags */
			2 +	/* cbDomain */
			2 +	/* cbUserName */
			2 +	/* cbPassword */
			2 +	/* cbAlternateShell */
			2 +	/* cbWorkingDir */
			2 + domain_length +	/* Domain */
			2 + username_length +	/* UserName */
			2 + password_length +	/* Password */
			2 + shell_length +	/* AlternateShell */
			2 + workingdir_length +	/* WorkingDir */
			/* size of TS_EXTENDED_INFO_PACKET */
			2 +	/* clientAddressFamily */
			2 +	/* cbClientAddress */
			len_ip +	/* clientAddress */
			2 +	/* cbClientDir */
			len_dll +	/* clientDir */
			/* size of TS_TIME_ZONE_INFORMATION */
			4 +	/* Bias, (UTC = local time + bias */
			64 +	/* StandardName, 32 unicode char array, Descriptive standard time on client */
			16 +	/* StandardDate */
			4 +	/* StandardBias */
			64 +	/* DaylightName, 32 unicode char array */
			16 +	/* DaylightDate */
			4 +	/* DaylightBias */
			4 +	/* clientSessionId */
			4 +	/* performanceFlags */
			2 +	/* cbAutoReconnectCookie, either 0 or 0x001c */
			/* size of ARC_CS_PRIVATE_PACKET */
			0;	/* autoReconnectCookie: +28 if you have a cookie */

      data->append(pad0, 4);
      data->append(&flags, sizeof(flags));
      data->append(&domain_length, sizeof(domain_length));
      data->append(&username_length, sizeof(username_length));
      data->append(&password_length, sizeof(password_length));
      data->append(&shell_length, sizeof(shell_length));
      data->append(&workingdir_length, sizeof(workingdir_length));

      /* no null terminator needed because domain is null - same for other null vars */
      data->append(u_domain, domain_length ? domain_length : 2);
      data->append(u_username, username_length ? username_length : 2);
      data->append(pad0, 2);  /* extra unicode NULL terminator */
      data->append(u_password, password_length ? password_length : 2);
      data->append(pad0, 2);
      data->append(u_shell, shell_length ? shell_length : 2);
      data->append(u_workdingdir, workingdir_length ? workingdir_length : 2);

      /* TS_EXTENDED_INFO_PACKET */
      uint16_t af = 2;
      data->append(&af, 2);
      data->append(&len_ip, 2);
      data->append(u_ip, len_ip - 2); data->append(pad0, 2);
      data->append(&len_dll, 2);
      data->append(u_dll, len_dll - 2); data->append(pad0, 2);
      
      /* TS_TIME_ZONE_INFORMATION */
      err = n_localtime(&t, &local_time);
      if (err) 
        log_write(LOG_STDERR, "Timing error (n_localtime): %s\n", strerror(err));
      gmtime_r(&t, &gm_time);
      
      tzone = (mktime(&gm_time) - mktime(&local_time)) / 60;
      data->append(&tzone, 4);
      data->append(u_gtb_normal, 2 * strlen("GTB, normaltid"));
      data->append(pad0, 2);
      data->append(pad0, 62 - 2 * strlen("GTB, normaltid"));
  
      uint32_t val = 0x0a0000; data->append(&val, sizeof(val));
      val = 0x050000; data->append(&val, sizeof(val));
      val = 3; data->append(&val, sizeof(val));
      val = 0; data->append(&val, sizeof(val));
      val = 0; data->append(&val, sizeof(val));
      data->append(u_gtb_sommar, 2 * strlen("GTB, sommartid"));
      data->append(pad0, 2);
      data->append(pad0, 62 - 2 * strlen("GTB, sommartid"));
      
      val = 0x30000; data->append(&val, sizeof(val));
      val = 0x050000; data->append(&val, sizeof(val));
      val = 2; data->append(&val, sizeof(val));
      data->append(pad0, 4);
      val = 0xffffffc4; data->append(&val, sizeof(val)); /* daylight bias */

      data->append(pad0, 4); /* clientSessionId (must be 0) */
      data->append(&rdp5_performance_flags, sizeof(rdp5_performance_flags)); // rdp5 performance flags
      data->append(pad0, 2);  /* auto reconnect length */

      total_length = packetlen;

  }

  if (o.debugging > 9) {
    printf("-----------DATA OUTGOING --------\n");
    char *string = hexdump((u8*)data->get_dataptr(), data->get_len());
    log_write(LOG_PLAIN, "%s", string);
    printf("-----------DATA OUTGOING END --------\n");
  }

  total_length += sizeof(mcs_data) + sizeof(sec_header);
  rdp_iso_data(con, total_length);
  total_length -= sizeof(mcs_data);
  rdp_mcs_data(con, total_length);

  rdp_encrypt_data(con, (uint8_t *)data->get_dataptr(), data->get_len(),
      SEC_LOGON_INFO | SEC_ENCRYPT);

  delete data;
  free(u_gtb_normal);
  free(u_gtb_sommar);
  free(u_dll);
  free(u_ip);
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
#if 0
static void
rdp_scancode_msg(Connection *con, uint32_t time, uint16_t flags,
    uint8_t scancode)
{
  rdp_input_msg(con, time, RDP_INPUT_SCANCODE, flags, scancode, 0);

}
#endif


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
  rdp_bmpcache_caps2 bmpcache2;
  rdp_newpointer_caps newpointer;
  rdp_brushcache_caps brushcache;
  rdp_input_caps input;
  rdp_sound_caps sound;
  rdp_font_caps font;
  rdp_glyphcache_caps glyph;
  rdp_multifragment_caps multifrag;
  rdp_large_pointer_caps largepointer;
  uint16_t total_length;
  uint32_t flags = 0x0030 | SEC_ENCRYPT;
  Buf *data = new Buf();

  caplen = RDP_CAPLEN_GENERAL 
    + RDP_CAPLEN_BITMAP 
    + RDP_CAPLEN_ORDER
    + RDP_CAPLEN_COLCACHE
    + RDP_CAPLEN_ACTIVATE
    + RDP_CAPLEN_CONTROL
    + RDP_CAPLEN_SHARE 
    + RDP_CAPLEN_BRUSHCACHE
    + RDP_CAPLEN_INPUT
    + RDP_CAPLEN_FONT
    + RDP_CAPLEN_SOUND
    + RDP_CAPLEN_GLYPHCACHE
    + RDP_CAPLEN_MULTIFRAGMENTUPDATE
    + RDP_CAPLEN_LARGE_POINTER
    + 4;

  if (info->rdp_version >= 5) {
		caplen += RDP_CAPLEN_BMPCACHE2;
		caplen += RDP_CAPLEN_NEWPOINTER;
	} else {
		caplen += RDP_CAPLEN_BMPCACHE;
		caplen += RDP_CAPLEN_POINTER;
	}

  pdu.length = 2 + 14 + caplen + sizeof(RDP_SOURCE);
  pdu.mcs_userid = info->mcs_userid + 1001;
  pdu.shareid = info->shareid;
  pdu.caplen = caplen;

  if (info->rdp_version >= 5) {
    general.extra_flags |= NO_BITMAP_COMPRESSION_HDR;
		general.extra_flags |= AUTORECONNECT_SUPPORTED;
		general.extra_flags |= LONG_CREDENTIALS_SUPPORTED;
		general.extra_flags |= FASTPATH_OUTPUT_SUPPORTED;
  }

  data->append(&pdu, sizeof(pdu));
  data->append(&general, sizeof(general));
  data->append(&bitmap, sizeof(bitmap));
  data->append(&order, sizeof(order));

  if (info->rdp_version >= 5) {
    data->append(&bmpcache2, sizeof(bmpcache2));
    data->append(&newpointer, sizeof(newpointer));
  } else {
    data->append(&bmpcache, sizeof(bmpcache));
    data->append(&pointer, sizeof(pointer));
  }

  data->append(&colcache, sizeof(colcache));
  data->append(&activate, sizeof(activate));
  data->append(&control, sizeof(control));
  data->append(&share, sizeof(share));
  data->append(&brushcache, sizeof(brushcache));
  data->append(&input, sizeof(input));
  data->append(&sound, sizeof(sound));
  data->append(&font, sizeof(font));
  data->append(&glyph, sizeof(glyph));
  data->append(&multifrag, sizeof(multifrag));
  data->append(&largepointer, sizeof(largepointer));

  total_length = data->get_len();
  total_length += sizeof(mcs_data) + sizeof(sec_header);
  rdp_iso_data(con, total_length);
  total_length -= sizeof(mcs_data);
  rdp_mcs_data(con, total_length);

  if (o.debugging > 9) {
    printf("-----------CONFIRM ACTIVE OUTGOING DATA-------- %u \n", data->get_len());
    char *string = hexdump((u8*)data->get_dataptr(), data->get_len());
    log_write(LOG_PLAIN, "%s", string);
    printf("-----------OUTGOING DATA END--------\n");
  }

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
 
  if (o.debugging > 9) {
    printf("-----------OUTGOING DATA-------- %u \n", rdp->get_len());
    char *string = hexdump((u8*)rdp->get_dataptr(), rdp->get_len());
    log_write(LOG_PLAIN, "%s", string);
    printf("-----------OUTGOING DATA END--------\n");
  }

  rdp_encrypt_data(con, (uint8_t *)rdp->get_dataptr(), rdp->get_len(), flags);

  delete rdp;
  delete data;

}



void
ncrack_rdp(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;
  rdp_state *info = NULL;
  int loop_val;

  if (con->misc_info)
    info = (rdp_state *) con->misc_info;
  else {
    con->misc_info = (rdp_state *)safe_zalloc(sizeof(rdp_state));
    info = (rdp_state *)con->misc_info;
    info->rdp_version = 5;  //TODO: assume RDP version 5 for now
  }

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

      if (o.debugging > 9) {
        printf("RDP_DEMAND_ACTIVE_SYNC\n");
        printf("rdp_synchronize\n"); 
      }
      rdp_synchronize(con);
      if (o.debugging > 9) 
        printf("rdp_control cooperate\n");
      rdp_control(con, RDP_CTL_COOPERATE);
      if (o.debugging > 9) 
        printf("rdp_control request\n");
      rdp_control(con, RDP_CTL_REQUEST_CONTROL);

      nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case RDP_DEMAND_ACTIVE_INPUT_SYNC:


      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      if (o.debugging > 9) 
        printf("DEMAND_ACTIVE_INPUT_SYNC\n");

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

      if (o.debugging > 9) 
        printf("DEMAND_ACTIVE_FONTS\n");

      if (info->rdp_version >= 5) {
        // normally we would send a bmpcache2 here
        // but we don't have any so don't have to send anything
        if (o.debugging > 9) 
          printf("rdp_fonts_send\n");
        rdp_fonts_send(con, 3);
      } else {
        rdp_fonts_send(con, 1);
        rdp_fonts_send(con, 2);
      }

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

          if (o.debugging > 9) 
            printf(" ----- LOOP WRITE ------\n");

          con->state = RDP_DEMAND_ACTIVE_SYNC;
          nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
              (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
          break;

        case LOOP_DISC:

          if (o.debugging > 9) 
            printf(" ----- LOOP DISC ------\n");

          delete con->inbuf;
          con->inbuf = NULL;
            
          con->force_close = true;
          rdp_disconnect(con);

          nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
              (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
          return ncrack_module_end(nsp, con);

          break;

        case LOOP_NOTH:

          if (o.debugging > 9) 
            printf(" ----- LOOP NOTH ------\n");

          nsock_timer_create(nsp, ncrack_timer_handler, 0, con);
          break;

        case LOOP_AUTH:

          if (o.debugging > 9) 
            printf(" ----- LOOP AUTH ------\n");

          if (info->login_result == LOGIN_SUCCESS) {
            con->auth_success = true;
          }
          
          delete con->inbuf;
          con->inbuf = NULL;

          info->login_pattern_fail = 0;
          con->force_close = true;
          rdp_disconnect(con);

          nsock_write(nsp, nsi, ncrack_write_handler, RDP_TIMEOUT, con,
              (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
          return ncrack_module_end(nsp, con);

          break;

        default:

          if (o.debugging > 9) 
            printf(" ----- LOOP DEFAULT  ------\n");
          nsock_timer_create(nsp, ncrack_timer_handler, 0, con);
          break;
      }


      break;
  }

}

