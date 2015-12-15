
/***************************************************************************
 * ncrack_http.cc -- ncrack module for the HTTP protocol                   *
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
#include "http.h"
#include <list>

#include <map>
using namespace std;
bool http_map_initialized = false;
map<int, const char*> http_map;

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
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

static int http_loop_read(nsock_pool nsp, Connection *con);
static void http_basic(nsock_pool nsp, Connection *con);
static void http_digest(nsock_pool nsp, Connection *con);
static void http_set_error(Service *serv, const char *reply);
static char *http_decode(int http_code);

static void http_free(Connection *con);


enum states { HTTP_INIT, HTTP_GET_AUTH, HTTP_BASIC_AUTH, HTTP_DIGEST_AUTH };

/* Basic Authentication substates */
enum { BASIC_SEND, BASIC_RESULTS };

/* Digest Authentication substates */
enum { DIGEST_SEND, DIGEST_RESULTS };


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
  char *start, *end;  /* auxiliary pointers */
  int i;
  char *http_reply = NULL;   /* server's message reply */
  size_t tmpsize;
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  http_info *info = NULL;
  http_state *hstate = NULL;
  con->ops_free = &http_free;

  if (con->misc_info) {
    info = (http_info *) con->misc_info;
  }

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

      con->state = HTTP_GET_AUTH;

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      con->outbuf->append("GET ", 4);
      if (serv->path[0] != '/')
        con->outbuf->append("/", 1);
      con->outbuf->snprintf(strlen(serv->path) + 17, "%s HTTP/1.1\r\nHost: ",
          serv->path);
      if (serv->target->targetname)
        con->outbuf->append(serv->target->targetname,
            strlen(serv->target->targetname));
      else 
        con->outbuf->append(serv->target->NameIP(),
            strlen(serv->target->NameIP()));

      con->outbuf->snprintf(115, "\r\nUser-Agent: %sConnection: close\r\n\r\n",
          USER_AGENT);

      nsock_write(nsp, nsi, ncrack_write_handler, HTTP_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case HTTP_GET_AUTH:

      if (http_loop_read(nsp, con) < 0)
        break;

      //memprint((const char *)con->iobuf->get_dataptr(),
      //con->iobuf->get_len());
      
      /* If target doesn't need authorization for the path selected, then
       * there is no point in trying to crack it. So inform the core engine
       * to mark the service as finished.
       */
      if (!memsearch((const char *)con->inbuf->get_dataptr(),
            "401", con->inbuf->get_len())) {
        serv->end.orly = true;
        start = memsearch((const char *)con->inbuf->get_dataptr(),
            "HTTP", con->inbuf->get_len());
        if (!start) {
          http_set_error(serv, http_reply);
          return ncrack_module_end(nsp, con);
        }
        i = 0;
        end = start;
        while (*end != '\n' && *end != '\r' && i != con->inbuf->get_len()) {
          end++;
          i++;
        }
        http_reply = Strndup(start, i);
        /* Now try to decode the HTTP reply we got into a message format,
         * suitable for human viewing.
         */
        http_set_error(serv, http_reply);
        free(http_reply);
        return ncrack_module_end(nsp, con);
      }

      /* Now that we are sure that the service actually needs authentication,
       * we can move on to parsing the reply to get the exact type of
       * authentication scheme used.
       */
      if (!(start = memsearch((const char *)con->inbuf->get_dataptr(),
            "WWW-Authenticate:", con->inbuf->get_len()))) {
        serv->end.orly = true;
        serv->end.reason = Strndup(HTTP_NOAUTH_SCHEME,
            sizeof(HTTP_NOAUTH_SCHEME) - 1);
        return ncrack_module_end(nsp, con);
      }
      start += sizeof("WWW-Authenticate: ") - 1;
      end = start;
      i = 0;
      while (*end != ' ' && i != con->inbuf->get_len()) {
        end++;
        i++;
      }
      con->misc_info = (http_info *)safe_zalloc(sizeof(http_info));
      info = (http_info *)con->misc_info;
      info->auth_scheme = Strndup(start, i);

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

        return ncrack_module_end(nsp, con);

      } else if (!strcmp("Digest", info->auth_scheme)) {

        serv->module_data = (http_state *)safe_zalloc(sizeof(http_state));
        hstate = (http_state *)serv->module_data;
        hstate->auth_scheme = Strndup(info->auth_scheme, 
            strlen(info->auth_scheme));
        hstate->state = HTTP_DIGEST_AUTH;
        hstate->reconnaissance = true;
        serv->more_rounds = true;

        http_digest(nsp, con);

        //return ncrack_module_end(nsp, con);
      
      } else {
        serv->end.orly = true;

        /* Instead of going through this trouble, I should really
         * make something like a combination of Strndup and sscanf */
        tmpsize = sizeof("Current authentication can't be handled: \n")
              + strlen(info->auth_scheme);
        serv->end.reason = (char *)safe_malloc(tmpsize);
        snprintf(serv->end.reason, tmpsize,
            "Current authentication can't be handled: %s\n",
            info->auth_scheme);

        return ncrack_module_end(nsp, con);
        
      }
      break;

    case HTTP_BASIC_AUTH:

      http_basic(nsp, con);
      break;

    case HTTP_DIGEST_AUTH:

      http_digest(nsp, con);
      break;

  }

}


/* 
 * Sets the reason why this service can no longer be cracked, by parsing the
 * http reply we got. If we don't have available information about the returned
 * HTTP code, then we just set the current reply as the reason.
 */
static void
http_set_error(Service *serv, const char *reply)
{
  assert(serv);
  char *msg = NULL;
  size_t len = strlen(reply);

  if (!reply) {
    serv->end.reason = Strndup(HTTP_UNKNOWN, sizeof(HTTP_UNKNOWN) - 1);
    return;
  }

  if (memsearch(reply, "200", len))
    msg = http_decode(200);
  else if (memsearch(reply, "400", len))
    msg = http_decode(400);
  else if (memsearch(reply, "403", len))
    msg = http_decode(403);
  else if (memsearch(reply, "404", len))
    msg = http_decode(404);
  else 
    msg = Strndup(reply, strlen(reply));
    
  serv->end.reason = msg;   
}


static char *
http_decode(int http_code)
{
  char *ret;

  if (http_map_initialized == false) {
    http_map_initialized = true;
    http_map.insert(make_pair<int, const char*>(200, "File or directory requested doesn't seem "
          "to be password protected. (200 OK)"));
    http_map.insert(make_pair<int, const char*>(400, "Malformed syntax on our part. "
          "(400 Bad Request)"));
    http_map.insert(make_pair<int, const char*>(401, "File or directory has forbidden access. "
          "(403 Forbidden)"));
    http_map.insert(make_pair<int, const char*>(404, "File or directory doesn't seem to exist. "
          "(404 Not Found)"));
    http_map.insert(make_pair<int, const char*>(-1, "Unknown HTTP error"));
  }

  map<int, const char*>::iterator mi = http_map.end();
  mi = http_map.find(http_code);
  if (mi == http_map.end()) {
    /* fallback to key -1 */
    mi = http_map.find(-1);
  }
  ret = Strndup(mi->second, strlen(mi->second));

  return ret;
}




static int
http_loop_read(nsock_pool nsp, Connection *con)
{

  if (con->inbuf == NULL) {
    nsock_read(nsp, con->niod, ncrack_read_handler, HTTP_TIMEOUT, con);
    return -1;
  }

  if (!memsearch((const char *)con->inbuf->get_dataptr(), "\r\n\r\n",
        con->inbuf->get_len())) {
    nsock_read(nsp, con->niod, ncrack_read_handler, HTTP_TIMEOUT, con);
    return -1;
  }

  return 0;
}



static void
http_digest(nsock_pool nsp, Connection *con)
{
  Service *serv = con->service;
  nsock_iod nsi = con->niod;
  http_info *info = (http_info *)con->misc_info;
  struct http_header *h;
  char *header;
  struct http_challenge challenge;
  char *response_hdr;


  switch(info->substate) {
    case DIGEST_SEND:

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      if (http_read_header((char *)con->inbuf->get_dataptr(), con->inbuf->get_len(),
          &header) < 0) {
          printf("Error reading response header.\n");
          return ncrack_module_end(nsp, con);
      }

      if (http_parse_header(&h, header) != 0) {
          printf("Error parsing response header.\n");
          return ncrack_module_end(nsp, con);
      }
      free(header);
      header = NULL;

      if (http_header_get_challenge(h, &challenge) == NULL) {
          printf("Error getting Authenticate challenge.\n");
          http_header_free(h);
          return ncrack_module_end(nsp, con);
      }
      http_header_free(h);

      response_hdr = http_digest_proxy_authorization(&challenge, 
          con->user, con->pass, "GET", serv->path);

      if (response_hdr == NULL) {
          printf("Error building Authorization header.\n");
          http_challenge_free(&challenge);

          if (header != NULL)
            free(header);
          return ncrack_module_end(nsp, con);
      }

      con->outbuf->append(response_hdr, strlen(response_hdr));
      con->outbuf->append("\r\n\r\n", sizeof("\r\n\r\n")-1);

      nsock_write(nsp, nsi, ncrack_write_handler, HTTP_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());


      info->substate = DIGEST_RESULTS;
      break;

    case DIGEST_RESULTS:
      if (http_loop_read(nsp, con) < 0)
        break;

      info->substate = DIGEST_SEND;

      // we need to get the new nonce
      ((http_state *) serv->module_data)->state = HTTP_GET_AUTH;

      //memprint((const char *)con->iobuf->get_dataptr(),
      //  con->iobuf->get_len());

      /* If we get a "200 OK" HTTP response OR a "301 Moved Permanently" which
       * happpens when we request access to a directory without an ending '/',
       * then it means our credentials were correct.
       */
      if (memsearch((const char *)con->inbuf->get_dataptr(),
            "200 OK", con->inbuf->get_len()) 
          || memsearch((const char *)con->inbuf->get_dataptr(),
            "301", con->inbuf->get_len())) {
        con->auth_success = true;
      }

      /* The in buffer has to be cleared out, because we are expecting
       * possibly new answers in the same connection.
       */
      delete con->inbuf;
      con->inbuf = NULL;

      ncrack_module_end(nsp, con);
      break;
  }

}





static void
http_basic(nsock_pool nsp, Connection *con)
{
  char *tmp;
  char *b64;
  size_t tmplen;
  Service *serv = con->service;
  nsock_iod nsi = con->niod;
  http_info *info = (http_info *)con->misc_info;

  switch (info->substate) {
    case BASIC_SEND:

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      con->outbuf->append("GET ", 4);
      if (serv->path[0] != '/')
        con->outbuf->append("/", 1);

      con->outbuf->snprintf(strlen(serv->path) + 17, "%s HTTP/1.1\r\nHost: ",
          serv->path);
      if (serv->target->targetname)
        con->outbuf->append(serv->target->targetname, 
            strlen(serv->target->targetname));
      else 
        con->outbuf->append(serv->target->NameIP(),
            strlen(serv->target->NameIP()));

      con->outbuf->snprintf(94, "\r\nUser-Agent: %s", USER_AGENT);

#if 0
      con->outbuf->append(HTTP_ACCEPT, sizeof(HTTP_ACCEPT) - 1);
      con->outbuf->append(HTTP_LANG, sizeof(HTTP_LANG) - 1);
      con->outbuf->append(HTTP_ENCODING, sizeof(HTTP_ENCODING) - 1);
      con->outbuf->append(HTTP_CHARSET, sizeof(HTTP_CHARSET) - 1);
#endif

      /* Try sending keep-alive values and see how much authentication attempts
       * we can do in that time-period.
       */
      //con->outbuf->append(HTTP_CACHE, sizeof(HTTP_CACHE) - 1);

      con->outbuf->append("Keep-Alive: 300\r\nConnection: keep-alive\r\n", 41);
      con->outbuf->append("Authorization: Basic ", 21);

      tmplen = strlen(con->user) + strlen(con->pass) + 1;
      tmp = (char *)safe_malloc(tmplen + 1);
      sprintf(tmp, "%s:%s", con->user, con->pass);

      b64 = (char *)safe_malloc(BASE64_LENGTH(tmplen) + 1);
      base64_encode(tmp, tmplen, b64);

      //b64 = b64enc(tmp, tmplen - 1);
      //printf("%s %s %s \n", con->user, con->pass, b64);
      con->outbuf->append(b64, strlen(b64));
      free(b64);
      free(tmp);
      con->outbuf->append("\r\n\r\n", sizeof("\r\n\r\n")-1);

      nsock_write(nsp, nsi, ncrack_write_handler, HTTP_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      
      info->substate = BASIC_RESULTS;
      break;

    case BASIC_RESULTS:
      if (http_loop_read(nsp, con) < 0)
        break;

      info->substate = BASIC_SEND;
      //memprint((const char *)con->iobuf->get_dataptr(),
      //  con->iobuf->get_len());

      /* If we get a "200 OK" HTTP response OR a "301 Moved Permanently" which
       * happpens when we request access to a directory without an ending '/',
       * then it means our credentials were correct.
       */
      if (memsearch((const char *)con->inbuf->get_dataptr(),
            "200 OK", con->inbuf->get_len()) 
          || memsearch((const char *)con->inbuf->get_dataptr(),
            "301", con->inbuf->get_len())) {
        con->auth_success = true;
      }

      /* The in buffer has to be cleared out, because we are expecting
       * possibly new answers in the same connection.
       */
      delete con->inbuf;
      con->inbuf = NULL;

      ncrack_module_end(nsp, con);
      break;
  }
}


static void
http_free(Connection *con)
{
  http_info *p = NULL;
  http_state *s = NULL;
  if (!con->misc_info)
    return;

  p = (http_info *)con->misc_info;
  if (con->service->module_data)
    s = (http_state *)con->service->module_data;

  /* We only deallocate the 'auth_scheme' string from the http_info struct
   * when it hasn't been assigned from the module http_state (thus we check
   * that the pointers are different). If we freed it, when the two
   * pointers referred to the same memory address, then the http_state's
   * would be deallocated as well, something we don't want to happen.
   */
  if (p->auth_scheme && s && s->auth_scheme 
      && p->auth_scheme != s->auth_scheme)
    free(p->auth_scheme);

}


