/***************************************************************************
 * ncrack_winrm.cc -- ncrack module for the WinRM protocol                 *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
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
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
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
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
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
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
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
#include "http.h"
#include <list>

#include <map>
using namespace std;

#define USER_AGENT "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1) Gecko/20090703 Shiretoko/3.5\r\n"
#define HTTP_LANG "Accept-Language: en-us,en;q=0.5\r\n"
#define HTTP_ENCODING "Accept-Encoding: gzip,deflate\r\n"
#define HTTP_CHARSET "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
#define HTTP_ACCEPT "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
#define HTTP_CACHE "Cache-Control: max-age=0, max-age=0, max-age=0, max-age=0\r\n"

//#define USER_AGENT "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)"
#define HTTP_UNKNOWN "Service might not be HTTP."
#define HTTP_NOAUTH_SCHEME "Service didn't reply with authentication scheme."
#define WINRM_TIMEOUT 10000

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

static void winrm_basic(nsock_pool nsp, Connection *con);
static int winrm_loop_read(nsock_pool nsp, Connection *con);
static void winrm_free(Connection *con);


enum states { WINRM_INIT, WINRM_BASIC_AUTH, WINRM_FINI };

/* Basic Authentication substates */
enum { BASIC_SEND, BASIC_RESULTS };


typedef struct winrm_info {
  char *auth_scheme;
  int substate;
} winrm_info;

typedef struct winrm_state {
  bool reconnaissance;
  char *auth_scheme;
  int state;
  int keep_alive;
} winrm_state;


void
ncrack_winrm(nsock_pool nsp, Connection *con)
{
  char *start, *end;  /* auxiliary pointers */
  size_t i;
  char *winrm_reply = NULL;   /* server's message reply */
  size_t tmpsize;
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  winrm_info *info = NULL;
  winrm_state *hstate = NULL;
  con->ops_free = &winrm_free;

  if (con->misc_info) {
    info = (winrm_info *) con->misc_info;
    //printf("info substate: %d \n", info->substate);
  }

  if (con->misc_info == NULL) {
    con->misc_info = (winrm_info *)safe_zalloc(sizeof(winrm_info));
    info = (winrm_info *)con->misc_info;
  } 

  switch (con->state)
  {
    case WINRM_INIT:
 
      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      winrm_basic(nsp, con);
  
      break;


    case WINRM_BASIC_AUTH:

      //winrm_basic(nsp, con);
      break;

  }

}

static int
winrm_loop_read(nsock_pool nsp, Connection *con)
{
  //printf("loop read\n");

  if (con->inbuf == NULL) {
    nsock_read(nsp, con->niod, ncrack_read_handler, WINRM_TIMEOUT, con);
    return -1;
  }

  if (!memsearch((const char *)con->inbuf->get_dataptr(), "\r\n\r\n",
        con->inbuf->get_len())) {
    nsock_read(nsp, con->niod, ncrack_read_handler, WINRM_TIMEOUT, con);
    return -1;
  }

  return 0;
}



static void
winrm_basic(nsock_pool nsp, Connection *con)
{
  char *tmp;
  char *b64;
  size_t tmplen;
  Service *serv = con->service;
  nsock_iod nsi = con->niod;
  winrm_info *info = (winrm_info *)con->misc_info;

  switch (info->substate) {
    case BASIC_SEND:

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      con->outbuf->append("POST ", 5);
      con->outbuf->append("/wsman", 6);

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

      con->outbuf->append("Content-Length: 0\r\n", 19);
      con->outbuf->append("Authorization: Basic ", 21);

      tmplen = strlen(con->user) + strlen(con->pass) + 1;
      tmp = (char *)safe_malloc(tmplen + 1);
      sprintf(tmp, "%s:%s", con->user, con->pass);

      b64 = (char *)safe_malloc(BASE64_LENGTH(tmplen) + 1);
      base64_encode(tmp, tmplen, b64);

      con->outbuf->append(b64, strlen(b64));
      free(b64);
      free(tmp);
      con->outbuf->append("\r\n\r\n", sizeof("\r\n\r\n")-1);

      nsock_write(nsp, nsi, ncrack_write_handler, WINRM_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      
      info->substate = BASIC_RESULTS;
      break;

    case BASIC_RESULTS:
      if (winrm_loop_read(nsp, con) < 0)
        break;

      info->substate = BASIC_SEND;
      //memprint((const char *)con->iobuf->get_dataptr(),
      //  con->iobuf->get_len());

      /* If we get a "200 OK" HTTP response OR a "301 Moved Permanently" 
       * OR 411 (which is the server's way of telling us we didn't issue
       * any command because the Content Length was 0 */
      if (memsearch((const char *)con->inbuf->get_dataptr(),
            "200 OK", con->inbuf->get_len()) 
          || memsearch((const char *)con->inbuf->get_dataptr(),
            "301", con->inbuf->get_len())
          || memsearch((const char *)con->inbuf->get_dataptr(),
            "411", con->inbuf->get_len())) {
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
winrm_free(Connection *con)
{

  winrm_info *p = NULL;
  if (con->misc_info == NULL)
    return;

  p = (winrm_info *)con->misc_info;
  free(p->auth_scheme);

}

