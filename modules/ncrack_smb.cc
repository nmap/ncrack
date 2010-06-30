
/***************************************************************************
 * ncrack_smb.cc -- ncrack module for the SMB protocol                     *
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

#define SMB_TIMEOUT 20000

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_connect_handler(nsock_pool nsp, nsock_event nse,
    void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

enum states { SMB_INIT, SMB_NEG, SMB_FINI };

static int smb_loop_read(nsock_pool nsp, Connection *con);
static void smb_encode_header(Buf *buf, char command);
static void smb_encode_negotiate_protocol(Buf *buf);
static void smb_prepend_length(Buf *buf);
static int smb_decode_header(Connection *con);
static int smb_decode_negresp(Connection *con);



static void smb_free(Connection *con);

typedef struct smb_state {
  int login_mechanism;
  uint32_t session_key; /* value needs to be echoed back */
  u_char server_challenge[8]; /* random string for challenge/response */
  uint16_t max_mpx; /* maximum multiplexed connections */
  uint16_t pid; /* process id */

} smb_state;


/* 
 * SMB header based on Microsoft's struct:
 * http://msdn.microsoft.com/en-us/library/dd327707.aspx
 */
typedef struct smb_header {

  u_char protocol[4]; /* Contains 0xFF, 'SMB' */
  u_char command;     /* Command code */
  union {
    struct {
      u_char error_class; /* Error class */
      u_char reserved;    /* Reserved for future use */
      uint16_t error;     /* Error code */
    } __attribute__((__packed__)) dos_error;
    uint32_t status;
  } status;

  u_char flags;
  uint16_t flags2;
  union {
    uint16_t pad[6];              /* Ensure section is 12 bytes long */
    struct {
      uint16_t pid_high;          /* high part of PID */
      u_char security_signature[8]; /* reserved for security */
    }  __attribute__((__packed__)) extra;
  };

  uint16_t tid; /* Tree identifier */
  uint16_t pid; /* Caller's process id */
  uint16_t uid; /* Unauthenticated user id */
  uint16_t mid; /* mutliplex id */

} __attribute__((__packed__)) smb_header;


/* 
 * Negotiate Response header 
 */
typedef struct smb_negresp_header {
  u_char word_count;              /* Always 17 for this struct */
  struct {
    uint16_t dialect_index;       /* Selected dialect index    */
    u_char security_mode;         /* Server security flags     */
    uint16_t max_mpx_count;       /* Maximum Multiplex Count   */
    uint16_t max_num_vc;          /* Maximum Virtual Circuits  */
    uint32_t max_buffer_size;     /* Maximum SMB message size  */
    uint32_t max_raw_size;        /* Obsolete                  */
    uint32_t session_key;         /* Unique session ID         */
    uint32_t capabilities;        /* Server capabilities flags */
    uint32_t system_time_low;     /* Server time; low bytes    */
    uint32_t system_time_high;    /* Server time; high bytes   */
    int16_t server_time_zone;     /* Minutes from UTC; signed  */
    u_char encryption_key_length; /* 0 or 8                    */
  } __attribute__((__packed__)) words;
}  __attribute__((__packed__)) smb_negresp_header;


/* 
 * Session Setup AndX Request header
 */
typedef struct
{
  u_char word_count;  /* 12 or 13 words */
  struct
  {
    struct
    {
      u_char command;
      u_char reserved;
      uint16_t offset;
    } andx;
    uint16_t max_buffer_size;
    uint16_t max_mpx_count;
    uint16_t vc_number;
    uint32_t session_key;
    uint16_t lengths[];  /* 1 or 2 elements */
    uint32_t reserved;
    uint32_t capabilities;
  } __attribute__((__packed__)) words;
} __attribute__((__packed__)) smb_andx_req_header;


/* 
 * Session Setup AndX Request data
 */
typedef struct
{
  uint16_t byte_count;
  struct
  {
    union
    {
      u_char security_blob[];
      struct
      {
        u_char case_insensitive_password[];
        u_char case_sensitive_password[];
        u_char pad[];
        u_char account_name[];
        u_char primary_domain[];
      } __attribute__((__packed__)) non_ext_sec;
    } auth_stuff;
    u_char native_os[];
    u_char native_LanMan[];
    u_char pad2[];
  } __attribute__((__packed__)) bytes;
} __attribute__((__packed__)) smb_andx_req_data;



/* SMB commands */
#define SMB_COM_NEGOTIATE 0x72
#define SMB_COM_SESSION_SETUP_ANDX 0x73

/* SMB Flags */
#define SMB_FLAGS_CANONICAL_PATHNAMES 0x10
#define SMB_FLAGS_CASELESS_PATHNAMES 0x08

/* SMB Flags2 */
#define SMB_FLAGS2_32BIT_STATUS 0x4000
#define SMB_FLAGS2_EXECUTE_ONLY_READS 0x2000
#define SMB_FLAGS2_IS_LONG_NAME 0x0040
#define SMB_FLAGS2_KNOWS_LONG_NAMES 0x0001


static int
smb_loop_read(nsock_pool nsp, Connection *con)
{
  uint32_t netbios_length, total_length;
  void *ioptr;

  printf("SMB LOOP READ START\n");

  /* Make sure we get at least 4 bytes: these are the NetBIOS header which
   * contains the total size of the message
   */
  if (con->inbuf == NULL || con->inbuf->get_len() < 4) {
    nsock_read(nsp, con->niod, ncrack_read_handler, SMB_TIMEOUT, con);
    return -1;
  }

  /* Get message length from NetBIOS header. It is in big-endian byte order and
   * 24 bits in total, so do necessary conversions */
  ioptr = con->inbuf->get_dataptr();
  memcpy(&netbios_length, ioptr, sizeof(uint32_t));
  netbios_length = ntohl(netbios_length); /* convert to host-byte order */
  netbios_length &= 0x00FFFFFF; /* make it 24 bits */
  /* total length = netbios length + 4 (for the length itself) */
  total_length = netbios_length + 4; 

  printf("%u\n", total_length);


  /* If we haven't received all the bytes of the message, according to the
   * total length that we calculated, then try and get the rest */
  if (con->inbuf == NULL || con->inbuf->get_len() < total_length) {
    nsock_read(nsp, con->niod, ncrack_read_handler, SMB_TIMEOUT, con);
    return -1;
  }

  return 0;

}




/* Creates a string containing a SMB packet header. The header looks like this:
 *
 *
 * --------------------------------------------------------------------------------------------------
 * | 31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0 |
 * --------------------------------------------------------------------------------------------------
 * |         0xFF           |          'S'          |        'M'            |         'B'           |
 * --------------------------------------------------------------------------------------------------
 * |        Command         |                             Status...                                 |
 * --------------------------------------------------------------------------------------------------
 * |    ...Status           |        Flags          |                    Flags2                     |
 * --------------------------------------------------------------------------------------------------
 * |                    PID_high                    |                  Signature.....               |
 * --------------------------------------------------------------------------------------------------
 * |                                        ....Signature....                                       |
 * --------------------------------------------------------------------------------------------------
 * |              ....Signature                     |                    Unused                     |
 * --------------------------------------------------------------------------------------------------
 * |                      TID                       |                     PID                       |
 * --------------------------------------------------------------------------------------------------
 * |                      UID                       |                     MID                       |
 * ------------------------------------------------------------------------------------------------- 

 * All fields are, incidentally, encoded in little endian byte order.

 For the purposes here, the program doesn't care about most of the fields so they're given default 
 values. The "command" field is the only one we ever have to set manually, in my experience. The TID
 and UID need to be set, but those are stored in the smb state and don't require user intervention. 
 */
static void
smb_encode_header(Buf *buf, char command)
{

  smb_header header;

  /* Every SMB packet needs a NetBIOS Session Service Header prepended which
   * is the length of the packet in 4 bytes in big endian. The length field is
   * 17 or 24 bits depending on whether or not it is raw (SMB over TCP).
   *
   * For now allocate space in the buffer, and when everything is done go fill
   * in the actual length with smb_prepend_length()
   */
  buf->snprintf(4, "%c%c%c%c", 0, 0, 0, 0);

  /* -- SMB packet follows -- */

  /* SMB header: 0xFF SMB */
  header.protocol[0] = 0xFF;
  strncpy((char *)&header.protocol[1], "SMB", 3);

  header.command = command; 
  header.status.status = 0; 
  header.flags = SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES;
  header.flags2 = SMB_FLAGS2_32BIT_STATUS | SMB_FLAGS2_EXECUTE_ONLY_READS |
    SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_KNOWS_LONG_NAMES;
  memset(header.pad, 0, 2);
  header.extra.pid_high = 0;
  memset(&header.extra.security_signature, 0,
      sizeof(header.extra.security_signature));
  header.tid = 0;
  header.pid = 0;
  header.uid = 0;
  header.mid = 0;

  buf->append(&header, sizeof(smb_header));

}


static void
smb_encode_negotiate_protocol(Buf *buf)
{
  uint16_t byte_count = 14;

  /* word count */
  buf->snprintf(1, "%c", 0);

  /* byte count */
  buf->append(&byte_count, 2);

  /* List of strings */
  buf->snprintf(12, "%c%s%", 2, "NT LM 0.12");
  buf->snprintf(2, "%c%c", 2, 0);

}

static void
smb_prepend_length(Buf *buf)
{
  u_int len;
  void *ptr;
  uint32_t nbt_len;

  /* Now caluclate total length */
  len = buf->get_len();
  ptr = buf->get_dataptr();

  nbt_len = htonl(len - 4);
  memcpy(ptr, &nbt_len, sizeof(uint32_t));

}


/* 
 * Decodes SMB packet and stores the most improtant fields in smb_state
 */
static int
smb_decode_header(Connection *con)
{
  smb_state *info;
  smb_header *header;

  info = (smb_state *) con->misc_info;

  /* Point to SMB header, 4 bytes after the beginning of NetBIOS header.
   * Without any need for additional memory-copy operations, just have the
   * smb_header pointer point to the incoming data.
   */ 
  header = (smb_header *) ((const char *)(con->inbuf->get_dataptr()) + 4);

  /* First check if protocol magic number is correct */
  if (header->protocol[0] != 0xFF
      || strncmp((const char *)&header->protocol[1], "SMB", 3)) {
    return -1;
  }

  /* Store important values in smb_state for future reference */
  info->pid = header->pid;

  return 0;

}


static int
smb_decode_negresp(Connection *con)
{
  smb_negresp_header *neg;
  smb_state *info;
  char *ptr;

  info = (smb_state *) con->misc_info;

  /* Point to Negotiate Protocol Response Header */
  neg = (smb_negresp_header *) ((const char *)(con->inbuf->get_dataptr())
      + sizeof(smb_header) + 4);

  info->session_key = neg->words.session_key;
  info->max_mpx = neg->words.max_mpx_count;

  if (!neg->words.encryption_key_length)
    return -1;

  /* Get encryption key */
  ptr = (char*)neg + sizeof(smb_negresp_header) + 2;
  memcpy(info->server_challenge, ptr, 8);

}



void
ncrack_smb(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  void *ioptr;
  con->ops_free = &smb_free;
  smb_state *info = NULL;

  if (con->misc_info)
    info = (smb_state *) con->misc_info;

  switch (con->state)
  {
    case SMB_INIT:

      con->state = SMB_NEG;

      con->misc_info = (smb_state *)safe_zalloc(sizeof(smb_state));  
      con->outbuf = new Buf();
      smb_encode_header(con->outbuf, SMB_COM_NEGOTIATE);
      smb_encode_negotiate_protocol(con->outbuf);
      smb_prepend_length(con->outbuf);

      nsock_write(nsp, nsi, ncrack_write_handler, SMB_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;


    case SMB_NEG:

      if (smb_loop_read(nsp, con) < 0)
        break;

      smb_decode_header(con);
      smb_decode_negresp(con);

      con->state = SMB_FINI;

      break;


    case SMB_FINI:

      break;


  }



}



static void
smb_free(Connection *con)
{


}
