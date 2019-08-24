/***************************************************************************
 * ncrack_vnc.cc -- ncrack module for the vnc protocol                     *
 * Coded by rhh                                                            *
 *  http://rycon.hu/                                                       *
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
#include <list>
#include <crypto.h>

#define TIMEOUT 20000
#define MAXPWLEN 8
#define CHALLENGESIZE 16

#define MAXMSPWLEN 32
#define CHALLENGESIZEMS 64

#define BYTES_TO_READ 1024

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_connect_handler(nsock_pool nsp, nsock_event nse,
    void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

enum states { VNC_INIT, VNC_HANDSHAKE, VNC_SECURITY_TYPE, VNC_AUTH, VNC_SECURITY_RESULT };

/*
 * Encrypt CHALLENGESIZE bytes in memory using a password.
 */
static void
vncEncryptBytes(unsigned char *bytes, char *passwd)
{
    unsigned char key[8];
    size_t i;

    /* key is simply password padded with nulls */

    for (i = 0; i < 8; i++) {
        if (i < strlen(passwd)) {
            key[i] = passwd[i];
        } else {
            key[i] = 0;
        }
    }

    deskey(key, EN0);

    for (i = 0; i < CHALLENGESIZE; i += 8) {
        des(bytes+i, bytes+i);
    }
}


static int
buf_check(int n, char* p) {
  int i;
  for(i=0; i<n; i++)
    if(p[i] != 0 ) 
      return p[i];
  return 0;
}

static uint8_t* 
str2uint8(char* p, int str_length, int uint_length)
{
  uint8_t* retme;
  retme = new uint8_t[str_length];

  for(int i=0; i < str_length; i++)
    retme[i] = (uint8_t)p[i];

  if(uint_length>str_length)
    for(int i=str_length; i < uint_length; i++)
      retme[i] = (uint8_t)0;

  return retme;
}

void
ncrack_vnc(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  char version_test[] = {2,0};

  switch (con->state)
  {
    case VNC_INIT: 
      con->state = VNC_HANDSHAKE;

      break;

    case VNC_HANDSHAKE:

      /* Wait till we receive the server's input */
      if(con->inbuf == NULL)
        break;

      //buf_print(con->inbuf->get_len(), (char*)con->inbuf->get_dataptr());

      /* We may have hit our limit, so we need to check */
      if (memsearch((const char *)con->inbuf->get_dataptr(), "Too many authentication failures", con->inbuf->get_len())|| 
          memsearch((const char *)con->inbuf->get_dataptr(), "Too many security failures", con->inbuf->get_len())) {
        if (o.debugging > 5)
          error("%s Too many authentication failures (a)", serv->HostInfo());

        con->close_reason = MODULE_ERR;
        con->force_close = true;
        return ncrack_module_end(nsp, con);
      }

      /* vnc begins with the server sending a version like "RFB 003.008\n" or "RFB 003.003\n"
       * determine which one to use, and then continue
       */
      if (memsearch((const char *)con->inbuf->get_dataptr(), "RFB 003.008", con->inbuf->get_len())) {
        con->outbuf = new Buf();
        con->outbuf->snprintf(12 , "RFB 003.008\n");
        nsock_write(nsp, nsi, ncrack_write_handler, TIMEOUT, con, (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
        con->state = VNC_SECURITY_TYPE;
      }
      else {
        con->outbuf = new Buf();
        con->outbuf->snprintf(12 , "RFB 003.003\n");
        nsock_write(nsp, nsi, ncrack_write_handler, TIMEOUT, con, (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
        con->state = VNC_AUTH;
      }
      /* We are now waiting for a SECURITY_TYPE response back, which could be several bytes */

      break;

    case VNC_SECURITY_TYPE:
      if(con->inbuf == NULL)
        break;
      
      if (memsearch((const char *)con->inbuf->get_dataptr(), "Too many authentication failures", con->inbuf->get_len())|| 
          memsearch((const char *)con->inbuf->get_dataptr(), "Too many security failures", con->inbuf->get_len())) {
        if (o.debugging > 5)
          error("%s Too many authentication failures (b)", serv->HostInfo());

        con->close_reason = MODULE_ERR;
        con->force_close = true;
        return ncrack_module_end(nsp, con);
      }

      /* At this point in the game, we should have gotten the number of security protocols,
       * and a list of those protocols (like 0x02, 0x0210)
       * handling VNC Authentication, which is 0x02, so let's ship that back and be on our way.
       */
      if (memsearch((const char *)con->inbuf->get_dataptr(), version_test, con->inbuf->get_len())) {
        uint8_t sec_version; sec_version = 0x02;
        con->outbuf = new Buf();
        con->outbuf->append(&sec_version, sizeof(uint8_t));
        nsock_write(nsp, nsi, ncrack_write_handler, TIMEOUT, con, (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
        con->state = VNC_AUTH;
      }
      /*
      else {
        error("%s This VNC server doesn't support VNC Auth.\n", serv->HostInfo());
        con->service->end.orly = true;
        //con->service->end.reason = Strndup("This VNC server doesn't support VNC Auth.", 23);

        con->close_reason = MODULE_ERR;
        con->force_close = true;
        return ncrack_module_end(nsp, con);
      }
      */

      /* Now we're waiting to hear back from the server whether we are good to go or not.  0 is go, 1 is fail */

      break;

    case VNC_AUTH:
      /* At this point, we should have gotten a 16-unsigned byte challenege */

      if(con->inbuf == NULL)
        break;

      /* des_data will hold the challenge before vncEncryptBytes() and the response after */
      uint8_t* des_data; 

      /* if length is 20, we are in protocol version 003.003, which means we've gotten 
       *    back a 4-byte security version number, as well as the challenge.
       */
      if(con->inbuf->get_len() == 20) {
        des_data = str2uint8((char*)con->inbuf->get_dataptr()+4, 16, 16);
        vncEncryptBytes(des_data, con->pass);
      }
      /* if it's exactly 16, we're in 003.007 or 003.008, so we can encrypt the challenge
       *   and continue
       */
      else if(con->inbuf->get_len() == 16) {
        /* des_data will hold the challenge before vncEncryptBytes() and the response after */
        des_data = str2uint8((char*)con->inbuf->get_dataptr(), 16, 16);
        vncEncryptBytes(des_data, con->pass);
      }
      /* If we have a 4 byte response, we've received only the version, but not the request yet.  So
       *   just break, and get the response next go round.
       */
      else if(con->inbuf->get_len() == 4) {
        if (memsearch((const char *)con->inbuf->get_dataptr(), version_test, con->inbuf->get_len()))
          break;
        else {
          if (o.debugging > 5)
            error("%s The server claims not to support VNC Auth. (Can be an auth limit problem)\n", serv->HostInfo()); 
          return ncrack_module_end(nsp, con);
        }
      }
      /* if we don't get 20, 16 or 4, then I'm confused as to what has happened.  I suppose
       *  we should probably terminate this connection.  Hasn't really come up in my tests.
       */
      else {
        if (o.debugging)
          error("%s Challenge not the right length (%d, when 16 expected)!\n", serv->HostInfo(), con->inbuf->get_len());
        return ncrack_module_end(nsp, con);
      }

      /* Ship our encrypted challenge back to the server, and await a result */
      con->outbuf = new Buf();
      con->outbuf->append(des_data, 16*sizeof(uint8_t));
      nsock_write(nsp, nsi, ncrack_write_handler, TIMEOUT, con, (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());

      con->state = VNC_SECURITY_RESULT;

      break;

    case VNC_SECURITY_RESULT:

      if(con->inbuf == NULL)
        break;

      /* okay, at this point, we expect to have at least 4 bytes in response.  If more, then we have a failure message
       *  However, we'll still check to make sure all bytes are 0 (the OK message) before we set auth_success to true
       */
      if(con->inbuf->get_len() >= 4 && buf_check(con->inbuf->get_len(), (char*)con->inbuf->get_dataptr()) == 0)
        con->auth_success = true;

      return ncrack_module_end(nsp, con);

      con->state = VNC_INIT;

      break;

  }
  /* Clean up when we are done with our buffers. */
  if(con->inbuf) 
    delete con->inbuf;
  con->inbuf = NULL;
  if(con->outbuf) 
    delete con->outbuf;
  con->outbuf = NULL;

  /* Read the next thrilling chapter from the server */
  nsock_read(nsp, nsi, ncrack_read_handler, BYTES_TO_READ, con);
}
