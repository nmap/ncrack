
/***************************************************************************
 * ncrack_telnet.cc -- ncrack module for the TELNET protocol               *
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


/* Telnet Commands */
#define IAC   255   /* interpret as command: */
#define DONT  254   /* you are not to use option */
#define DO    253   /* please, you use option */
#define WONT  252 	/* I won't use option */
#define WILL  251 	/* I will use option */
#define SB    250   /* interpret as subnegotiation */
#define	SE    240   /* end sub negotiation */

/* Telnet Options */
#define LINEMODE 34

#define WILL_LINEMODE "\xff\xfb\x22"
#define DO_LINEMODE "\xff\xfd\x22"


extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_timer_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

typedef struct telnet_info {
  bool linemode; /* true if peer supports linemode */
  /* Some devices don't even bother to answer our question of whether they
   * support linemode or not, and thus we need a separate boolean to tell us
   * if we sent a request, so we can try only once.
   */
  bool asked_for_linemode;
  bool linemode_not_supported;  /* peer told us that he doesn't support linemode */
  bool can_start_auth;
  char *userptr;
  char *passptr;
} telnet_info;


enum states { TELNET_INIT, TELNET_OPTIONS_1, TELNET_OPTIONS_2, TELNET_AUTH, TELNET_ECHO_USER,
  TELNET_PASS_R, TELNET_PASS_W, TELNET_FINI };

void
ncrack_telnet(nsock_pool nsp, Connection *con)
{
  char lbuf[BUFSIZE]; /* local buffer */
  /* We can't let nsock handle the size by looking at '\0'
   * because telnet uses 0 as a valid value for options 
   * (e.g binary transmission option) */
  size_t lbufsize;  
  nsock_iod nsi = con->niod;
  telnet_info *info = NULL;
  size_t datasize;
  char *recvbufptr = NULL;
  size_t recvbuflen = 0;
  char *localbufptr = lbuf;
  if (con->misc_info)
    info = (telnet_info *) con->misc_info;

  switch (con->state)
  {
    case TELNET_INIT:
      con->peer_might_close = false;
      con->misc_info = (telnet_info *)safe_zalloc(sizeof(telnet_info));
      con->state = TELNET_OPTIONS_1;
      nsock_read(nsp, nsi, ncrack_read_handler, 50000, con);
      break;

    case TELNET_OPTIONS_1:

      recvbufptr = (char *)con->inbuf->get_dataptr();
      recvbuflen = con->inbuf->get_len();

      /* Telnet Option Parsing */
      while (*recvbufptr == (char) IAC
          && ((size_t)(recvbufptr - (char *)con->inbuf->get_dataptr()) < recvbuflen)
          && ((localbufptr - lbuf) < BUFSIZE - 3)) {

        /* For every option other than linemode we reject it */
        if (recvbufptr[1] == (char) WILL) {
          if (recvbufptr[2] == (char) LINEMODE) {
            /* reply is needed only when we haven't asked explicitly if the peer
             * supports linemode itself
             */
            if (info->asked_for_linemode == false) {
              memcpy(localbufptr, WILL_LINEMODE, sizeof(WILL_LINEMODE));
              localbufptr += 3;
            }
            info->linemode = true;
          } else {
            snprintf(localbufptr, 4, "%c%c%c", IAC, DONT, recvbufptr[2]);
            localbufptr += 3;
          }
          recvbufptr += 3;

        } else if (recvbufptr[1] == (char) WONT) {
          if (recvbufptr[2] == LINEMODE) {
            info->linemode = false;
            info->linemode_not_supported = true;
          } else {
            snprintf(localbufptr, 4, "%c%c%c", IAC, DONT, recvbufptr[2]);
            localbufptr += 3;
          }
          recvbufptr += 3;

        } else if (recvbufptr[1] == (char) DONT) {
          if (recvbufptr[2] == LINEMODE) {
            info->linemode = false;
            info->linemode_not_supported = true;
          }
          snprintf(localbufptr, 4, "%c%c%c", IAC, WONT, recvbufptr[2]);
          localbufptr += 3;
          recvbufptr += 3;

        } else if (recvbufptr[1] == (char) DO) {
          if (recvbufptr[2] == LINEMODE) {
            if (info->asked_for_linemode == false) {
              memcpy(localbufptr, WILL_LINEMODE, sizeof(WILL_LINEMODE));
              localbufptr += 3;
            }
            info->linemode = true;
          } else {
            snprintf(localbufptr, 4, "%c%c%c", IAC, WONT, recvbufptr[2]);
            localbufptr += 3;
          }
          recvbufptr += 3;

          /* We just ignore any suboption we receive */
        } else if (recvbufptr[1] == (char) SB) {
          while (*recvbufptr != (char) SE
              && (size_t)((recvbufptr - (char *)con->inbuf->get_dataptr())) < recvbuflen)
            recvbufptr++;
          recvbufptr++;
        }
      }

      /* If peer didn't sent linemode as part of its options and didn't sent a 
       * command saying he doesn't support it and this is the first time we
       * request it from him, then try to ask him explicitly if
       * he supports it.
       */
      if (info->linemode == false
          && info->linemode_not_supported == false
          && info->asked_for_linemode == false) {
        if ((localbufptr - lbuf) < BUFSIZE - 3) {
          memcpy(localbufptr, WILL_LINEMODE, sizeof(WILL_LINEMODE));
          info->asked_for_linemode = true;
          localbufptr += 3;
        }
      }

      datasize = recvbuflen - (recvbufptr - (char *)con->inbuf->get_dataptr());

      /* Now check for banner and login prompt */
      if (datasize > 0) {
        if (o.debugging > 8) {
          //memprint(recvbufptr, datasize);
          //printf("\n");
        }
        /* If we see a certain pattern that denotes that we can start
         * authentication then we note that down. */
        if (memsearch(recvbufptr, "login", datasize) 
            || memsearch(recvbufptr, "username", datasize)) 
          info->can_start_auth = true;
      }

      lbufsize = localbufptr - lbuf;

      con->state = TELNET_OPTIONS_2;
      /* If we have something to send then do so. Else just wait until you
       * receive a relevant authentication pattern to start cracking. 
       */
      if (localbufptr != lbuf) {
        nsock_write(nsp, nsi, ncrack_write_handler, 10000, con, lbuf, lbufsize);
      } else {
        if (info->can_start_auth == true)
          con->state = TELNET_AUTH;
        /* That's a bit of a hack, but we need the module to be called again
         * with a changed state without issuing a read or write this time. And
         * thus we create a timer event with a timeout of 0 milliseconds */
        nsock_timer_create(nsp, ncrack_timer_handler, 0, con);
      }
      break;

    case TELNET_OPTIONS_2:
      delete con->inbuf;
      con->inbuf = NULL;

      con->state = TELNET_OPTIONS_1;
      nsock_read(nsp, nsi, ncrack_read_handler, 10000, con);
      break;

    case TELNET_AUTH:
      if (info->linemode) {
        con->state = TELNET_PASS_R;
        snprintf(lbuf, sizeof(lbuf), "%s\r", con->user);
        nsock_write(nsp, nsi, ncrack_write_handler, 10000, con, lbuf, -1);
      } else {
        con->state = TELNET_ECHO_USER;
        /* Since our peer doesn't support linemode, we need to send each
         * character of the username in individual packets. We send 1 byte
         * and wait for the server's echo and so on...
         */
        if (con->inbuf) {
          recvbufptr = (char *)con->inbuf->get_dataptr();
          recvbuflen = con->inbuf->get_len();
        }

        if (!info->userptr)
          info->userptr = con->user;
        
        /* OK, here's the deal: we need to account for the fact that some
         * telnet daemons (hint: cisco routers) send the initial login prompt
         * and then start sending telnet options. Since we have already, sent
         * the first username character by now, we will just have to ignore
         * those options, and wait until we see our character echoed back in
         * order to go on sending the rest of the username.
         */
        if (con->inbuf && info->userptr > con->user
            && (size_t)((info->userptr - con->user)) != strlen(con->user)) {
          /* Some telnet daemons send the echo reply with a \0 byte in front of
           * the echoed characted. Damn inconsistencies. */
          if ((recvbuflen > 2 && recvbufptr[1] != *(info->userptr - 1))
              || (recvbuflen == 1 && recvbufptr[0] != *(info->userptr - 1))) {
            nsock_timer_create(nsp, ncrack_timer_handler, 0, con);
            break;
          }
        }

        /* we can move on to reading the password prompt */
        if (recvbufptr && info->userptr > con->user &&
            memsearch(recvbufptr, "\r", recvbuflen)) {
          if (memsearch(recvbufptr, "password", recvbuflen)) 
            con->state = TELNET_PASS_W;
          else
            con->state = TELNET_PASS_R;
          nsock_timer_create(nsp, ncrack_timer_handler, 0, con);
          break;
        }

        if ((size_t)(info->userptr - con->user) == strlen(con->user)) {
          lbuf[0] = '\r'; 
          lbuf[1] = '\0';
          nsock_write(nsp, nsi, ncrack_write_handler, 10000, con, lbuf, 2);
        } else {
          lbuf[0] = info->userptr[0];
          info->userptr++;
          nsock_write(nsp, nsi, ncrack_write_handler, 10000, con, lbuf, 1);
        }
      }
      break;

    case TELNET_ECHO_USER:
      delete con->inbuf;
      con->inbuf = NULL;

      con->state = TELNET_AUTH;
      nsock_read(nsp, nsi, ncrack_read_handler, 10000, con);
      break;

    case TELNET_PASS_R:
      delete con->inbuf;
      con->inbuf = NULL;

      con->state = TELNET_PASS_W;
      nsock_read(nsp, nsi, ncrack_read_handler, 10000, con);
      break;

    case TELNET_PASS_W:
      /* After some testing, it seems that we can send the password
       * as one packet, even if linemode is disabled. */
      con->state = TELNET_FINI;
      snprintf(lbuf, sizeof(lbuf), "%s\r", con->pass);
      con->peer_might_close = true;
      nsock_write(nsp, nsi, ncrack_write_handler, 10000, con, lbuf, -1);
      break;

    case TELNET_FINI:
      if (con->inbuf) {
        recvbufptr = (char *)con->inbuf->get_dataptr();
        recvbuflen = con->inbuf->get_len();
      }

      if (memsearch(recvbufptr, "incorrect", recvbuflen)
          || memsearch(recvbufptr, "fail", recvbuflen)) {
        con->auth_success = false;
        con->state = TELNET_AUTH;
        info->userptr = NULL;
        info->passptr = NULL;
        con->peer_might_close = false;
        
        /* 
         * If telnetd sent the final answer along with the new login prompt
         * (something which happens with some daemons), then we don't need to 
         * check if the peer has closed the connection because obviously he hasn't!
         */
        if (memsearch(recvbufptr, "login", recvbuflen)
            || memsearch(recvbufptr, "username", recvbuflen))
          con->peer_alive = true;

        delete con->inbuf;
        con->inbuf = NULL;
        
        return ncrack_module_end(nsp, con);

      } else if (memsearch(recvbufptr, ">", recvbuflen)
          || memsearch(recvbufptr, "$", recvbuflen)
          || memsearch(recvbufptr, "#", recvbuflen)) {
        con->auth_success = true;

        delete con->inbuf;
        con->inbuf = NULL;

        return ncrack_module_end(nsp, con);

      } else {  /* wait for more replies */

        delete con->inbuf;
        con->inbuf = NULL;

        con->state = TELNET_FINI;
        nsock_read(nsp, nsi, ncrack_read_handler, 10000, con);
      }
  }

}

