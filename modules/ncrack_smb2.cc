
/***************************************************************************
 * ncrack_smb2.cc -- ncrack module for the SMB2 protocol                   *
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
#include "ntlmssp.h"
#include "portable_endian.h"
#include <list>

#ifdef WIN32
#ifndef __attribute__
# define __attribute__(x)
#endif
# pragma pack(1)
#endif

#define SMB2_TIMEOUT 20000

#define SMB2_CMD_NEGPROT 0x00
#define SMB2_CMD_SESSETUP 0x01

#define SMB2_NEGOTIATE_SIGNING_ENABLED 0x0001

#define NT_STATUS_SUCCESS 0x00000000
#define NT_STATUS_MOREPRO 0xc0000016
#define NT_STATUS_LOGON_FAILURE 0xc000006d

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

enum states { SMB2_INIT, SMB2_NEGPROT, SMB2_SESSETUP1, SMB2_SESSETUP2, SMB2_FINI };

static int smb2_loop_read(nsock_pool nsp, Connection *con);
static void smb2_prepend_length(Buf *buf);

//static void smb_free(Connection *con);


struct smb2_state {
  struct auth_data *auth_data;
  uint64_t session_id;
  uint32_t msg_id;
};

static int
smb2_loop_read(nsock_pool nsp, Connection *con)
{
  uint32_t netbios_length, total_length;
  void *ioptr;

  /* Make sure we get at least 4 bytes: these are the NetBIOS header which
   * contains the total size of the message
   */
  if (con->inbuf == NULL || con->inbuf->get_len() < 4) {
    nsock_read(nsp, con->niod, ncrack_read_handler, SMB2_TIMEOUT, con);
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

  /* If we haven't received all the bytes of the message, according to the
   * total length that we calculated, then try and get the rest */
  if (con->inbuf == NULL || con->inbuf->get_len() < total_length) {
    nsock_read(nsp, con->niod, ncrack_read_handler, SMB2_TIMEOUT, con);
    return -1;
  }

  return 0;

}

static void
smb2_prepend_length(Buf *buf)
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

static void encode_u8(Buf *buf, uint8_t n) {
  buf->append(&n, 1);
}
static void encode_le64(Buf *buf, uint64_t n) {
  uint64_t u64 = htole64(n);
  buf->append(&u64, 8);
}
static void encode_le32(Buf *buf, uint32_t n) {
  uint32_t u32 = htole32(n);
  buf->append(&u32, 4);
}
static void encode_le16(Buf *buf, uint16_t n) {
  uint16_t u16 = htole16(n);
  buf->append(&u16, 2);
}
static void encode_be32(Buf *buf, uint32_t n) {
  uint32_t u32 = htonl(n);
  buf->append(&u32, 4);
}
/* not used */
#if 0 
static void encode_be16(Buf *buf, uint16_t n) {
  uint16_t u16 = htons(n);
  buf->append(&u16, 2);
}
#endif

static void smb2_encode_header(Connection *con, int cmd)
{
  smb2_state *smb2 = (smb2_state*)con->misc_info;
  
  encode_be32(con->outbuf,  0); // NetBios size, overwritten later
  encode_be32(con->outbuf, 0xFE534d42); // ProtocolID
  encode_le16(con->outbuf, 64); // StructureSize
  encode_le16(con->outbuf,  0); // CreditCharge
  encode_le32(con->outbuf,  0); // Status
  encode_le16(con->outbuf, cmd); // Command
  encode_le16(con->outbuf,  0); // CreditRequested
  encode_le32(con->outbuf,  0); // Flags
  encode_le32(con->outbuf,  0); // NextCommand
  encode_le64(con->outbuf,  smb2->msg_id++); // MessageId
  encode_le32(con->outbuf,  0); // Reserved
  encode_le32(con->outbuf,  0); // TreeId
  encode_le64(con->outbuf,  smb2->session_id); // SessionId
  encode_le64(con->outbuf,  0); // Signature (16 bytes)
  encode_le64(con->outbuf,  0); // Signature
}

static void smb2_encode_negprot_req(Connection *con)
{
  smb2_encode_header(con, SMB2_CMD_NEGPROT);

  encode_le16(con->outbuf, 36); // StructureSize
  encode_le16(con->outbuf,  1); // DialectCount
  encode_le16(con->outbuf, SMB2_NEGOTIATE_SIGNING_ENABLED); // SecurityMode
  encode_le16(con->outbuf,  0); // Reserved
  encode_le32(con->outbuf,  0); // Capabilities
  for (int i = 0; i < 16; i++) {
    encode_u8(con->outbuf,  rand()%256); // ClientGuid
  }
  encode_le64(con->outbuf,  0); // ClientStartTime
  encode_le16(con->outbuf,  0x0202); // Dialect

  smb2_prepend_length(con->outbuf);
}

static void smb2_encode_sessetup_req(Connection *con, unsigned char *in_sec_buf = NULL, uint16_t in_sec_len = 0)
{
  smb2_state *smb2 = (smb2_state*)con->misc_info;
  unsigned char *sec_buf;
  uint16_t sec_len;
  uint16_t *sec_off;

  if (!in_sec_buf) {
    smb2->auth_data = ntlmssp_init_context(con->user, con->pass, "", "", "abcdefgh");
  }
  ntlmssp_generate_blob(smb2->auth_data, in_sec_buf, in_sec_len, &sec_buf, &sec_len);

  smb2_encode_header(con, SMB2_CMD_SESSETUP);
  
  encode_le16(con->outbuf, 25); // StructureSize
  encode_u8(con->outbuf,    0); // Flags
  encode_u8(con->outbuf, SMB2_NEGOTIATE_SIGNING_ENABLED); // SecurityMode
  encode_le32(con->outbuf,  0); // Capabilities
  encode_le32(con->outbuf,  0); // Channel
  encode_le16(con->outbuf,  0); // SecurityBufferOffset
  sec_off = (uint16_t*)(((uint8_t*)con->outbuf->get_dataptr()) + con->outbuf->get_len() - 2);
  encode_le16(con->outbuf, sec_len); // SecurityBufferLength
  encode_le64(con->outbuf,  0); // PreviousSessionId
  *sec_off = htole16(con->outbuf->get_len() - 4);
  con->outbuf->append(sec_buf, sec_len);

  smb2_prepend_length(con->outbuf);  
}

static uint32_t smb2_get_status(Connection *con)
{
  uint32_t *p = (uint32_t*)(((uint8_t*)con->inbuf->get_dataptr()) + 4 + 4 + 2 + 2);
  return le32toh(*p);
}

static void smb2_get_sessetup_sec_buf(Connection *con, unsigned char **buf, uint16_t *len)
{
  uint8_t *start = ((uint8_t*)con->inbuf->get_dataptr()) + 4;
  uint8_t *rsp = start + 64;
  uint16_t *sec_off = (uint16_t *)(rsp + 2 + 2);
  uint16_t *sec_len = (uint16_t *)(rsp + 2 + 2 + 2);  
  *buf = (unsigned char*)(start + le16toh(*sec_off));
  *len = le16toh(*sec_len);
}

static uint64_t smb2_get_ses_id(Connection *con)
{
  uint8_t *start = ((uint8_t*)con->inbuf->get_dataptr()) + 4;
  return le64toh(*((uint64_t*)(start+4+2+2+4+2+2+4+4+8+4+4)));
}


void
ncrack_smb2(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;
  smb2_state *smb2 = (smb2_state*)con->misc_info;
  //con->ops_free = &smb_free;

  switch (con->state)
  {
    case SMB2_INIT:

      con->state = SMB2_NEGPROT;

      con->misc_info = (smb2_state *)safe_zalloc(sizeof(smb2_state));
      con->outbuf = new Buf();
      smb2_encode_negprot_req(con);

      nsock_write(nsp, nsi, ncrack_write_handler, SMB2_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;


    case SMB2_NEGPROT:
      if (smb2_loop_read(nsp, con) < 0)
        break;
      con->state = SMB2_SESSETUP1;

      // smb_decode_header(con);
      // smb_decode_negresp(con);

      /* Change state without any read or write */
      nsock_timer_create(nsp, ncrack_timer_handler, 0, con);
      break;

    case SMB2_SESSETUP1:

      if (smb2_loop_read(nsp, con) < 0)
        break;

      con->state = SMB2_SESSETUP2;

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      smb2->session_id = smb2_get_ses_id(con);
      smb2_encode_sessetup_req(con);

      delete con->inbuf;
      con->inbuf = NULL;

      nsock_write(nsp, nsi, ncrack_write_handler, SMB2_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;
      
    case SMB2_SESSETUP2:

      if (smb2_loop_read(nsp, con) < 0)
        break;
     
      con->state = SMB2_FINI;

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      {
	unsigned char *buf;
	uint16_t len;
	smb2_get_sessetup_sec_buf(con, &buf, &len);
	smb2->session_id = smb2_get_ses_id(con);	
	smb2_encode_sessetup_req(con, buf, len);
      }

      delete con->inbuf;
      con->inbuf = NULL;

      nsock_write(nsp, nsi, ncrack_write_handler, SMB2_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;


    case SMB2_FINI:

      if (smb2_loop_read(nsp, con) < 0)
        break;

      con->state = SMB2_SESSETUP1;

      if (smb2_get_status(con) == NT_STATUS_SUCCESS)
	con->auth_success = true;
      else if (smb2_get_status(con) == NT_STATUS_LOGON_FAILURE)
	con->auth_success = false;

      ntlmssp_destroy_context(smb2->auth_data);
      smb2->auth_data = NULL;
      smb2->session_id = 0;
      
      delete con->inbuf;
      con->inbuf = NULL;

      return ncrack_module_end(nsp, con);
  }
}


#if 0
static void
smb_free(Connection *con)
{


}
#endif
