
/***************************************************************************
 * ncrack_ssh.cc -- ncrack module for the SSH protocol                     *
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

/* OpenSSH include-files */
#include "opensshlib.h"

#include "ssh2.h"
#include "openssl/dh.h"
#include "buffer.h"
#include "sshbuf.h"
#include "kex.h"
#include "sshconnect.h"
#include "packet.h"
#include "misc.h"
#include "cipher.h"
#include "compat.h"
#include "mac.h"

#define SSH_TIMEOUT 20000
#define CLIENT_VERSION "SSH-2.0-OpenSSH_7.1\n"


extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

enum states { SSH_INIT, SSH_ID_EX, SSH_KEY, SSH_KEY2, SSH_KEY3, SSH_KEY4,
  SSH_AUTH, SSH_AUTH2, SSH_AUTH3, SSH_AUTH4, SSH_FINI };

static void ssh_free(Connection *con);



static inline int
ssh_loop_read(nsock_pool nsp, Connection *con, ncrack_ssh_state *info)
{
  u_int packetlen = 0;

  /* If we have data in the I/O buffer, which means that we had previously
   * scheduled an nsock read event, then append the new data we got inside
   * the 'input' buffer which will be processed by the openssh library
   */
  if (con->inbuf != NULL) {
    packetlen = con->inbuf->get_len();

    //printf("packetlen read by nsock: %d\n", packetlen);
    if (packetlen > 0) {
      buffer_append(info->input, con->inbuf->get_dataptr(), packetlen);
      delete con->inbuf;
      con->inbuf = NULL;
    }

    //printf("info input length: %d \n", sshbuf_len(info->input));
  }

  //printf("ncrack state %d\n", con->state);

  info->type = ncrackssh_ssh_packet_read(info);
  if (info->type == SSH_MSG_NONE) {
    //printf("ssh loop MSG NONE\n");
    nsock_read(nsp, con->niod, ncrack_read_handler, SSH_TIMEOUT, con);
    return -1;
  } else if (info->type == SSH2_MSG_DISCONNECT) {
    //printf("ssh loop MSG DISCONNECT\n");
    return -2;
  }

  //printf("info->type: %d\n", info->type);

  //printf("final input packet length %d\n", sshbuf_len(info->input));

  delete con->inbuf;
  con->inbuf = NULL;
  return 0;
}



void
ncrack_ssh(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  void *ioptr;
  u_int buflen;
  ncrack_ssh_state *info = NULL;
  con->ops_free = &ssh_free;
  int r = 0;

  if (con->misc_info)
    info = (ncrack_ssh_state *) con->misc_info;

  switch (con->state)
  {
    case SSH_INIT:

      con->state = SSH_ID_EX;
      con->misc_info = (ncrack_ssh_state *)safe_zalloc(sizeof(ncrack_ssh_state));
      nsock_read(nsp, nsi, ncrack_read_handler, SSH_TIMEOUT, con);
      break;

    case SSH_ID_EX:

      buflen = con->inbuf->get_len();
      ioptr = con->inbuf->get_dataptr();
      if (!memsearch((const char *)ioptr, "\n", buflen)) {
        con->state = SSH_ID_EX;
        nsock_read(nsp, nsi, ncrack_read_handler, SSH_TIMEOUT, con);
        break;
      }
      if (strncmp((const char *)ioptr, "SSH-", 4)) {
        con->inbuf->clear();
        con->state = SSH_ID_EX;
        nsock_read(nsp, nsi, ncrack_read_handler, SSH_TIMEOUT, con);
        break;
      }
      con->state = SSH_KEY;

      info->server_version_string = Strndup((char *)ioptr, buflen);
      ncrackssh_compat_datafellows(info);

      chop(info->server_version_string);

      /* NEVER forget to free allocated memory and also NULL-assign ptr */
      delete con->inbuf;
      con->inbuf = NULL;

      if (con->outbuf)
        delete con->outbuf;

      con->outbuf = new Buf();
      con->outbuf->append(CLIENT_VERSION, sizeof(CLIENT_VERSION)-1);
      info->client_version_string = Strndup(
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      chop(info->client_version_string);

      nsock_write(nsp, nsi, ncrack_write_handler, SSH_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());

      break;

    case SSH_KEY:

      con->state = SSH_KEY2;

      /* sends "Key Exchange Init" */

      /* Initialize cipher contexts and keys as well as internal opensshlib
       * buffers (input, output, incoming_packet, outgoing_packet)
       */
      ssh_packet_set_connection(info);

      ncrackssh_ssh_kex2(info, info->client_version_string,
          info->server_version_string);

      nsock_write(nsp, nsi, ncrack_write_handler, SSH_TIMEOUT, con,
          (const char *)buffer_ptr(info->output),
          buffer_len(info->output));

      buffer_consume(info->output, buffer_len(info->output));

      break;


    case SSH_KEY2:

      r = ssh_loop_read(nsp, con, info);
      if (r == -1)
        break;
      else if (r == -2) {
        con->force_close = true;
        con->close_reason = MODULE_ERR;
        return ncrack_module_end(nsp, con);
      }


      /* Receives: "Key Exchange Init"
       * Sends: "Diffie-Hellman GEX Request"
       */
      con->state = SSH_KEY3;

      ncrackssh_kex_input_kexinit(info);

      nsock_write(nsp, nsi, ncrack_write_handler, SSH_TIMEOUT, con,
          (const char *)buffer_ptr(info->output), buffer_len(info->output));
      buffer_consume(info->output, buffer_len(info->output));

      break;

    case SSH_KEY3:

      r = ssh_loop_read(nsp, con, info);
      if (r == -1)
        break;
      else if (r == -2) {
        con->force_close = true;
        con->close_reason = MODULE_ERR;
        return ncrack_module_end(nsp, con);
      }

      /* Receives: "Diffie-Hellman Key Exchange Reply" and
       * Sends: "Diffie-Hellman GEX Init"
       */

      con->state = SSH_KEY4;

      if (info->kex->kex_type == KEX_ECDH_SHA2) {
        //printf("KEX ECDH SHA2 \n");
        ncrackssh_input_kex_ecdh_reply(info);
        con->state = SSH_AUTH;
      } else if (info->kex->kex_type == KEX_DH_GRP1_SHA1
                 || info->kex->kex_type == KEX_DH_GRP14_SHA1) {
        //printf("dh client\n");
        ncrackssh_input_kex_dh(info);
        con->state = SSH_AUTH;
      } else if (info->kex->kex_type == KEX_C25519_SHA256) {
        //printf("c25519 client\n");
        ncrackssh_input_kex_c25519_reply(info);
        con->state = SSH_AUTH;
      } else {
        //printf("dh gex sha\n");
        ncrackssh_input_kex_dh_gex_group(info);
      }

      nsock_write(nsp, nsi, ncrack_write_handler, SSH_TIMEOUT, con,
          (const char *)buffer_ptr(info->output), buffer_len(info->output));
      buffer_consume(info->output, buffer_len(info->output));

      break;

    case SSH_KEY4:
      
      r = ssh_loop_read(nsp, con, info);
      if (r == -1)
        break;
      else if (r == -2) {
        con->force_close = true;
        con->close_reason = MODULE_ERR;
        return ncrack_module_end(nsp, con);
      }

      /* Receives: "Diffie-Hellman GEX Reply" and
       * Sends: "New keys"
       */
      con->state = SSH_AUTH;

      ncrackssh_input_kex_dh_gex_reply(info);

      nsock_write(nsp, nsi, ncrack_write_handler, SSH_TIMEOUT, con,
          (const char *)buffer_ptr(info->output), buffer_len(info->output));
      buffer_consume(info->output, buffer_len(info->output));

      break;

    case SSH_AUTH:

      r = ssh_loop_read(nsp, con, info);
      if (r == -1)
        break;
      else if (r == -2) {
        con->force_close = true;
        con->close_reason = MODULE_ERR;
        return ncrack_module_end(nsp, con);
      }

      /* Receives: "New keys"
       * Sends "Encrypted Request 1"
       */

      con->state = SSH_AUTH2;

      ncrackssh_ssh_start_userauth2(info);

      nsock_write(nsp, nsi, ncrack_write_handler, SSH_TIMEOUT, con,
          (const char *)buffer_ptr(info->output), buffer_len(info->output));
      buffer_consume(info->output, buffer_len(info->output));

      break;

    case SSH_AUTH2:

#if 0
      if (info->kex->kex_type == KEX_DH_GEX_SHA1 || info->kex->kex_type == KEX_DH_GEX_SHA256) {
        //printf("SSH AUTH 2 loop read \n");
        if (ssh_loop_read(nsp, con, info) < 0)
          break;
      }
#endif

      r = ssh_loop_read(nsp, con, info);
      if (r == -1)
        break;
      else if (r == -2) {
        con->force_close = true;
        con->close_reason = MODULE_ERR;
        return ncrack_module_end(nsp, con);
      }

      con->state = SSH_AUTH3;

      /*
       * If server doesn't support "password" authentication method then
       * there is no point in doing any more attempts, so we can mark the
       * service as finished.
       */
      if (ncrackssh_ssh_userauth2_service_rep(info) < 0) {
        serv->end.orly = true;
        if (con->outbuf)
          delete con->outbuf;

        //printf("Server error\n");

        con->outbuf = new Buf();
        Snprintf((char *)con->outbuf->get_dataptr(), DEFAULT_BUF_SIZE,
            "Server denied authentication request: %d", info->type);
        serv->end.reason = Strndup((const char *)con->outbuf->get_dataptr(),
            (size_t)strlen((const char *)con->outbuf->get_dataptr()));
        return ncrack_module_end(nsp, con);
      }

      /* Jump straight to next state */
      nsock_timer_create(nsp, ncrack_timer_handler, 0, con);
      break;

    case SSH_AUTH3:

      /*
       * Sends credentials
       */
      con->state = SSH_FINI;

      //printf("SSH AUTH 3 \n");

      /* compare the current user with the previously saved on, so that if 
       * we get another username in the same connection, we close the
       * connection because ssh doesn't let us change the username midway
       */
      if (info->prev_user == NULL) {
        info->prev_user = con->user;
        //printf("null user: %s \n", info->prev_user);
      } else {
        if (info->prev_user != con->user) {
          //printf("CLOSING CONNECTION DUE TO DIFFERENT NAME\n");
          con->force_close = true;
          con->close_reason = MODULE_ERR;
          return ncrack_module_end(nsp, con);
        }

        info->prev_user = con->user;
        //printf("prev_user %d \n", con->user);
      }

      ncrackssh_ssh_userauth2(info, con->user, con->pass);

      nsock_write(nsp, nsi, ncrack_write_handler, SSH_TIMEOUT, con,
          (const char *)buffer_ptr(info->output), buffer_len(info->output));
      buffer_consume(info->output, buffer_len(info->output));

      break;

    case SSH_FINI:

      r = ssh_loop_read(nsp, con, info);
      if (r == -1)
        break;
#if 0
      else if (r == -2) {
        con->force_close = true;
        con->close_reason = MODULE_ERR;
        return ncrack_module_end(nsp, con);
      }
#endif

      /*
       * If we get a disconnect message at this stage, then it probably
       * means that we reached the server's authentication limit per
       * connection.
       */
      if (info->type == SSH2_MSG_DISCONNECT) {
        return ncrack_module_end(nsp, con);
      }

      if (info->type == SSH2_MSG_USERAUTH_SUCCESS) {
        //printf("succeed\n");
        con->auth_success = true;
        con->force_close = true;
      } else if (info->type == SSH2_MSG_USERAUTH_FAILURE) {
        //printf("failed!\n");
        con->state = SSH_AUTH3;
      } else if (info->type == SSH2_MSG_USERAUTH_BANNER) {
        //printf("Got banner!\n");
      }


      return ncrack_module_end(nsp, con);
  }
}


static void
ssh_free(Connection *con)
{
  ncrack_ssh_state *p;
  if (!con->misc_info)
    return;

  p = (ncrack_ssh_state *)con->misc_info;

  if (p->kex) {
    if (p->kex->peer->alloc > 0)
      free(p->kex->peer->d);
    if (p->kex->my->alloc > 0)
      free(p->kex->my->d);
    if (p->kex->session_id)
      free(p->kex->session_id);
    free(p->kex);
  }

  /* Note that DH *dh has already been freed from
   * the openssh library */

  /* 2 keys */
  for (int i = 0; i < 2; i++) {
    if (p->newkeys[i]) {
      free(p->newkeys[i]->enc.iv);
      free(p->newkeys[i]->enc.key);
      free(p->newkeys[i]->mac.key);
      /* Without this specific call to cleanup the mac environment there
       * was a big memleak - reported by Valgrind to be starting from
       * mac_init() (opensshlib/mac.c). For some reason, no proper cleanup
       * was done and this explicit call for mac_clear() is needed.
       */
      mac_clear(&p->newkeys[i]->mac);
      if (p->newkeys[i]->comp.name)
        free(p->newkeys[i]->comp.name);
      if (p->newkeys[i]->enc.name)
        free(p->newkeys[i]->enc.name);
      if (p->newkeys[i]->mac.name)
        free(p->newkeys[i]->mac.name);
      free(p->newkeys[i]);
    }
  }

  EVP_CIPHER_CTX_free(p->receive_context.evp);
  EVP_CIPHER_CTX_free(p->send_context.evp);

  buffer_free(p->input);
  buffer_free(p->output);
  buffer_free(p->incoming_packet);
  buffer_free(p->outgoing_packet);

  if (p->client_version_string)
    free(p->client_version_string);
  if (p->server_version_string)
    free(p->server_version_string);
  if (p->disc_reason)
    free(p->disc_reason);

}

