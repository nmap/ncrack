/***************************************************************************
 * ncrack_http.cc -- ncrack module for the HTTP protocol                   *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
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



#define USER_AGENT "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1) Gecko/20090703 Shiretoko/3.5\r\n"
#define HTTP_LANG "Accept-Language: en-us,en;q=0.5\r\n"
#define HTTP_ENCODING "Accept-Encoding: gzip,deflate\r\n"
#define HTTP_CHARSET "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
#define HTTP_ACCEPT "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
#define HTTP_CACHE "Cache-Control: max-age=0, max-age=0, max-age=0, max-age=0\r\n"

//#define USER_AGENT "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)"
#define HTTP_UNKNOWN "Service might not be HTTP."
#define HTTP_NOAUTH_SCHEME "Service didn't reply with authentication scheme."
#define HTTP_TIMEOUT 10000

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

static void http_basic(nsock_pool nsp, Connection *con);
enum states { HTTP_INIT, HTTP_GET_AUTH1, HTTP_GET_AUTH2, HTTP_BASIC_AUTH,
  HTTP_FINI };

/* Basic Authentication substates */
enum { BASIC_SEND, BASIC_RECV, BASIC_RESULTS };

typedef struct http_info {
  char *auth_scheme;
  int substate;
} http_info;

typedef struct http_state {
  bool reconnaissance;
  char *auth_scheme;
  int state;
  int keep_alive;
} http_state;


void
ncrack_http(nsock_pool nsp, Connection *con)
{
  Buf *lbuf; /* local buffer */
  char *start, *end;  /* auxiliary pointers */
  int i;
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  http_info *info = NULL;
  http_state *hstate = NULL;
  if (con->misc_info)
    info = (http_info *) con->misc_info;

  if (serv->module_data && !con->misc_info) {
    hstate = (http_state *)serv->module_data;
    con->state = hstate->state;
    con->misc_info = (http_info *)safe_zalloc(sizeof(http_info));
    info = (http_info *)con->misc_info;
    info->auth_scheme = hstate->auth_scheme;
    serv->more_rounds = false;
  }

  switch (con->state)
  { 
    case HTTP_INIT:

      con->state = HTTP_GET_AUTH1;

      lbuf = new Buf();
      lbuf->append("GET ", sizeof("GET ")-1);
      if (serv->path[0] != '/')
        lbuf->append("/", 1);
      lbuf->append(serv->path, strlen(serv->path));
      lbuf->append(" HTTP 1.1\r\nHost: ", sizeof(" HTTP 1.1\r\nHost: ")-1);
      if (serv->target->targetname)
        lbuf->append(serv->target->targetname, strlen(serv->target->targetname));
      else 
        lbuf->append(serv->target->NameIP(), strlen(serv->target->NameIP()));
      lbuf->append("\r\nUser-Agent: ", sizeof("\r\nUser-Agent: ")-1);
      lbuf->append(USER_AGENT, sizeof(USER_AGENT)-1);
      lbuf->append("\r\n\r\n", sizeof("\r\n\r\n")-1);

      nsock_write(nsp, nsi, ncrack_write_handler, HTTP_TIMEOUT, con,
        (const char *)lbuf->get_dataptr(), lbuf->get_len());
      delete lbuf;
      break;

    case HTTP_GET_AUTH1:

      con->state = HTTP_GET_AUTH2;
      nsock_read(nsp, nsi, ncrack_read_handler, HTTP_TIMEOUT, con);
      break;

    case HTTP_GET_AUTH2:

      //memprint((const char *)con->iobuf->get_dataptr(), con->iobuf->get_len());
      
      /* If target doesn't need authorization for the path selected, then
       * there is no point in trying to crack it. So inform the core engine
       * to mark the service as finished.
       */
      if (!memsearch((const char *)con->iobuf->get_dataptr(),
            "401 Authorization Required", con->iobuf->get_len())) {
        serv->end.orly = true;
        start = memsearch((const char *)con->iobuf->get_dataptr(),
            "HTTP", con->iobuf->get_len());
        if (!start) {
          serv->end.reason = Strndup(HTTP_UNKNOWN, sizeof(HTTP_UNKNOWN) - 1);
          return ncrack_module_end(nsp, con);
        }
        i = 0;
        end = start;
        while (*end != '\n' && *end != '\r' && i != con->iobuf->get_len()) {
          end++;
          i++;
        }
        serv->end.reason = Strndup(start, i);
        return ncrack_module_end(nsp, con);
      }

      /* Now that we are sure that the service actually needs authentication,
       * we can move on to parsing the reply to get the exact type of
       * authentication scheme used.
       */
      if (!(start = memsearch((const char *)con->iobuf->get_dataptr(),
            "WWW-Authenticate:", con->iobuf->get_len()))) {
        serv->end.orly = true;
        serv->end.reason = Strndup(HTTP_NOAUTH_SCHEME,
            sizeof(HTTP_NOAUTH_SCHEME) - 1);
        return ncrack_module_end(nsp, con);
      }
      start += sizeof("WWW-Authenticate: ") - 1;
      end = start;
      i = 0;
      while (*end != ' ' && i != con->iobuf->get_len()) {
        end++;
        i++;
      }
      con->misc_info = (http_info *)safe_zalloc(sizeof(http_info));
      info = (http_info *)con->misc_info;
      info->auth_scheme = Strndup(start, i);
      //printf("%s \n", info->auth_scheme);
      if (!strcmp("Basic", info->auth_scheme)) {
        //con->state = HTTP_BASIC_AUTH;
        //info->substate = BASIC_SEND;
        serv->module_data = (http_state *)safe_zalloc(sizeof(http_state));
        hstate = (http_state *)serv->module_data;
        hstate->auth_scheme = Strndup(info->auth_scheme,
            strlen(info->auth_scheme));
        hstate->state = HTTP_BASIC_AUTH;
        hstate->reconnaissance = true;
        serv->more_rounds = true;

        delete con->iobuf;
        con->iobuf = NULL;
        return ncrack_module_end(nsp, con);

      } else {
        fatal("Current authentication can't be handled!\n");
      }
      break;

    case HTTP_BASIC_AUTH:

      http_basic(nsp, con);
      break;

  }


}



static void
http_basic(nsock_pool nsp, Connection *con)
{
  Buf *auxbuf;
  unsigned char *tmp;
  char *b64;
  size_t tmplen;
  Service *serv = con->service;
  nsock_iod nsi = con->niod;
  http_info *info = (http_info *)con->misc_info;

  switch (info->substate) {
    case BASIC_SEND:

      auxbuf = new Buf();
      auxbuf->append("GET ", sizeof("GET ") - 1);
      if (serv->path[0] != '/')
        auxbuf->append("/", 1);
      auxbuf->append(serv->path, strlen(serv->path));
      auxbuf->append(" HTTP/1.1\r\nHost: ", sizeof(" HTTP/1.1\r\nHost: ") - 1);
      if (serv->target->targetname)
        auxbuf->append(serv->target->targetname, strlen(serv->target->targetname));
      else 
        auxbuf->append(serv->target->NameIP(), strlen(serv->target->NameIP()));
      auxbuf->append("\r\nUser-Agent: ", sizeof("\r\nUser-Agent: ") - 1);
      auxbuf->append(USER_AGENT, sizeof(USER_AGENT) - 1);
#if 0
      auxbuf->append(HTTP_ACCEPT, sizeof(HTTP_ACCEPT) - 1);
      auxbuf->append(HTTP_LANG, sizeof(HTTP_LANG) - 1);
      auxbuf->append(HTTP_ENCODING, sizeof(HTTP_ENCODING) - 1);
      auxbuf->append(HTTP_CHARSET, sizeof(HTTP_CHARSET) - 1);
#endif

      /* Try sending keep-alive values and see how much authentication attempts
       * we can do in that time-period.
       */
      auxbuf->append("Keep-Alive: 300\r\nConnection: keep-alive\r\n",
          sizeof("Keep-Alive: 300\r\nConnection: keep-alive\r\n") - 1);

      //auxbuf->append(HTTP_CACHE, sizeof(HTTP_CACHE) - 1);

      auxbuf->append("Authorization: Basic ",
          sizeof("Authorization: Basic ") - 1);

      tmplen = strlen(con->user) + strlen(con->pass) + 2;
      tmp = (unsigned char *)safe_malloc(tmplen);
      Snprintf((char *)tmp, tmplen, "%s:%s", con->user, con->pass);
      b64 = b64enc(tmp, tmplen);
      //printf("%s \n", b64);
      auxbuf->append(b64, strlen(b64));
      free(b64);
      free(tmp);
      auxbuf->append("\r\n\r\n", sizeof("\r\n\r\n")-1);

      nsock_write(nsp, nsi, ncrack_write_handler, HTTP_TIMEOUT, con,
        (const char *)auxbuf->get_dataptr(), auxbuf->get_len());
      
      info->substate = BASIC_RECV;
      delete auxbuf;
      break;

    case BASIC_RECV:

      info->substate = BASIC_RESULTS;
      nsock_read(nsp, nsi, ncrack_read_handler, HTTP_TIMEOUT, con);
      break;

    case BASIC_RESULTS:

      info->substate = BASIC_SEND;
      //memprint((const char *)con->iobuf->get_dataptr(), con->iobuf->get_len());
      if (memsearch((const char *)con->iobuf->get_dataptr(),
            "200 OK", con->iobuf->get_len())) {
        con->auth_success = true;
      }
      delete con->iobuf;
      con->iobuf = NULL;
      ncrack_module_end(nsp, con);
      break;
  }
}

