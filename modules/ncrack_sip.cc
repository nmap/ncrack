
/***************************************************************************
 * ncrack_sip.cc -- ncrack module for the SIP  protocol                    *
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

using namespace std;

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

static int sip_loop_read(nsock_pool nsp, Connection *con);


typedef struct sip_info {
  int cseq;
} sip_info;


enum states { SIP_INIT, SIP_STATUS };

#define SIP_TIMEOUT 10000


void
ncrack_sip(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  sip_info *info = NULL;
  struct sockaddr_storage local;
  struct sockaddr_in *local4 = NULL; 
  struct sockaddr_in6 *local6 = NULL; 
  int family = 0;
  local4 = (struct sockaddr_in *)&local;
  local6 = (struct sockaddr_in6 *)&local;
  u16 localport = 0;
  char localport_s[6];
  char cseq_s[6];

  if (con->misc_info) {
    info = (sip_info *) con->misc_info;
  } else {
    info = (sip_info *) safe_zalloc(sizeof(sip_info));
    info->cseq = 0;
  }


  switch (con->state)
  { 

    case SIP_INIT:

      nsock_iod_get_communication_info(nsi, NULL, &family, (struct sockaddr*)&local,
                                       NULL, sizeof(struct sockaddr_storage));
      if (family == AF_INET6) {
        localport = ntohs(local6->sin6_port);
      } else {
        localport = ntohs(local4->sin_port);
      }

      snprintf(localport_s, sizeof(localport_s), "%d", localport);
      printf("local port %s \n", localport_s);

      snprintf(cseq_s, sizeof(cseq_s), "%d", info->cseq);


      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();
      
      con->outbuf->snprintf(strlen(serv->target->NameIP()) + strlen("192.168.25.1") + strlen(localport_s) + strlen(con->user) \
           + strlen(serv->target->NameIP()) + strlen(con->user) + strlen(serv->target->NameIP()) + strlen(serv->target->NameIP()) \
           + strlen(cseq_s) + 
           strlen("REGISTER sip: SIP/2.0\r\nVia: SIP/2.0/TCP :\r\nFrom: <sip:@>\r\nTo: <sip:@>\r\n" "Call-ID: 1234@\r\nCSeq:  REGISTER\r\nContent-Length: 0\r\n\r\n"),
           "REGISTER sip:%s SIP/2.0\r\n"
           "Via: SIP/2.0/TCP %s:%d\r\n"
           "From: <sip:%s@%s>\r\n"
           "To: <sip:%s@%s>\r\n" "Call-ID: 1234@%s\r\n" \
           "CSeq: %i REGISTER\r\n" "Content-Length: 0\r\n\r\n", serv->target->NameIP(), "192.168.25.1", localport, con->user, 
           serv->target->NameIP(), con->user, serv->target->NameIP(), serv->target->NameIP(), info->cseq);

      info->cseq++;

      con->state = SIP_STATUS;

      nsock_write(nsp, nsi, ncrack_write_handler, SIP_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());

      break;

    case SIP_STATUS:

      if (sip_loop_read(nsp, con) < 0)
        break;

      printf("---------------memprint-------------\n");
      memprint((const char *)con->inbuf->get_dataptr(), con->inbuf->get_len());
      printf("---------------memprint-------------\n");


      break;
  }



}



static int
sip_loop_read(nsock_pool nsp, Connection *con)
{

  if (con->inbuf == NULL) {
    nsock_read(nsp, con->niod, ncrack_read_handler, SIP_TIMEOUT, con);
    return -1;
  }

  if (!memsearch((const char *)con->inbuf->get_dataptr(), "\r\n\r\n",
        con->inbuf->get_len())) {
    nsock_read(nsp, con->niod, ncrack_read_handler, SIP_TIMEOUT, con);
    return -1;
  }

  return 0;
}

