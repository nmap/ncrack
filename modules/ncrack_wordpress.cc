
/***************************************************************************
 * ncrack_wordpress.cc -- ncrack module for wordpress                      *
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

using namespace std;

#define USER_AGENT "Ncrack (https://nmap.org/ncrack)\r\n"
#define WORDPRESS_TIMEOUT 10000

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

static int wordpress_loop_read(nsock_pool nsp, Connection *con);

enum states { WORDPRESS_INIT, WORDPRESS_GET, WORDPRESS_AUTH, WORDPRESS_FINI };

typedef struct wordpress_info {
  int wpadmin_ok;
} wp_info;


typedef struct http_info {
  /* true if Content-Length in received HTTP packet > 0 */
  int content_expected;
  int chunk_expected;
} http_info;


void
ncrack_wordpress(nsock_pool nsp, Connection *con)
{
  Service *serv = con->service;
  nsock_iod nsi = con->niod;
  wp_info *info; 
  char tmp[16];
  size_t formlen;
  info = NULL;


  if (serv->module_data) {
    info = (wp_info *) serv->module_data;
    /* Check if we have already verified existence for the wp-login panel
     * the serv->module_data carries data across all connections because it is
     * in the Service variable, not the Connection one.
     * If we have verified the existence and we just started this connection, 
     * then jump straight to the WORDPRESS_AUTH state - so we only need to do this
     * once for this particular service (not once per connection) */
    if (info->wpadmin_ok && con->state == WORDPRESS_INIT)
      con->state = WORDPRESS_AUTH;
  }

  if (serv->module_data == NULL) {
    serv->module_data = (wp_info *)safe_zalloc(sizeof(wp_info));
    info = (wp_info *)serv->module_data;
  } 

  switch (con->state)
  {
    case WORDPRESS_INIT:

      /* 
       * You only have to verify the existence of the login panel once when
       * the module begins. That's why we need to keep track of this amongst
       * all the connections of the module against this particular host.
       */
      info->wpadmin_ok = 1;

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      con->outbuf->append("GET ", 4);
      
      if (strlen(serv->path) > 1) {
        /* user provided path in command-line */
        con->outbuf->append("/", 1);
        con->outbuf->snprintf(strlen(serv->path), "%s", serv->path);
      } else {
        /* default path - /wp-login.php */
        con->outbuf->append("/wp-login.php", 13);       
      }

      con->outbuf->append(" HTTP/1.1\r\nHost: ", 17);

      if (serv->target->targetname)
        con->outbuf->append(serv->target->targetname, strlen(serv->target->targetname));
      else 
        con->outbuf->append(serv->target->NameIP(), strlen(serv->target->NameIP()));

      con->outbuf->snprintf(48, "\r\nUser-Agent: %s", USER_AGENT);
      /* We want to "keep-alive" the connection as long as possible, because the time cost
       * of a new TCP connection is usually higher than the waiting time for a response for
       * each authentication attempt. 
       * This is a general concept in network authentication cracking and that Ncrack tries
       * to abide by: we want to have as many connections as optimally possible
       * without DoS-ing the service while at the same time maximizing the number of
       * authentication attempts per connection.
       */
      con->outbuf->append("Keep-Alive: 300\r\nConnection: keep-alive\r\n", 41);

      /* mark end of HTTP packet */
      con->outbuf->append("\r\n", 2);

      /* 
       * after the write operation, the module will start at the WORDPRESS_GET state
       */
      con->state = WORDPRESS_GET;

      nsock_write(nsp, nsi, ncrack_write_handler, WORDPRESS_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case WORDPRESS_GET: 

      if (wordpress_loop_read(nsp, con) < 0)
        break;

      /*
       * If we get a "200 OK" HTTP response OR a "301 Moved Permanently" which
       * happpens when we request access to a directory without an ending '/',
       * then it means the page exists.
       */
      if (memsearch((const char *)con->inbuf->get_dataptr(), "200 OK", con->inbuf->get_len()) 
          || memsearch((const char *)con->inbuf->get_dataptr(), "301", con->inbuf->get_len())) {
        con->state = WORDPRESS_AUTH;
      } else {
       /*
        * If service replies with an error, then there is no point in pursuing further
        * Mark the service as finished and call ncrack_module_end to exit the module. 
        * Setting the end.orly value to true will acknowledge to the Ncrack core engine that 
        * it should no longer call this module against this particular target.
        */
        serv->end.orly = true;
        serv->end.reason = Strndup("No service available on that URL.", 68);
        return ncrack_module_end(nsp, con);
      }

      delete con->inbuf;
      con->inbuf = NULL;
      /* Jump straight to next state */
      nsock_timer_create(nsp, ncrack_timer_handler, 0, con);
      break;

    case WORDPRESS_AUTH:

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      con->outbuf->append("POST ", 5);
      /* 
       * the following are almost exactly like the initial HTTP GET query we sent in WORDPRESS_INIT
       */
       if (strlen(serv->path) > 1) {
        /* user provided path in command-line */
        con->outbuf->append("/", 1);
        con->outbuf->snprintf(strlen(serv->path), "%s", serv->path);
      } else {
        /* default path */
        con->outbuf->append("/wp-login.php", 13); 
      }
      con->outbuf->append(" HTTP/1.1\r\nHost: ", 17);
      if (serv->target->targetname)
        con->outbuf->append(serv->target->targetname, strlen(serv->target->targetname));
      else 
        con->outbuf->append(serv->target->NameIP(), strlen(serv->target->NameIP()));
      con->outbuf->snprintf(48, "\r\nUser-Agent: %s", USER_AGENT);
      con->outbuf->append("Keep-Alive: 300\r\nConnection: keep-alive\r\n", 41);
      /* Up until this point, the data we put in the buffer were exactly the same as in the HTTP
       * GET request, from hereon the data are different: 
       * We need to add the Content-Type and Content-Length along with the wordpress form
       */
      con->outbuf->append("Content-Type: application/x-www-form-urlencoded\r\n", 49); 
      
      /* Now we need to calculate the content-length of the form before we append the form 
       * to the buffer. The content-length is exactly the length of the form.
       * The form is a string that is formed as follows in the HTTP packet: 
       * pwd=password&log=username 
       * where password is a placeholder for every password and username is a placeholder for
       * every username 
       */
      formlen = strlen(con->user) + strlen(con->pass) + sizeof("log&log==") - 1;
      snprintf(tmp, sizeof(tmp) - 1, "%lu", formlen);
      /* note this has two \r\n in the end - one for the end of Content-Length, the other
       * for the end of the HTTP header - because after that the form (data) follows
       */
      con->outbuf->snprintf(20 + strlen(tmp), "Content-Length: %s\r\n\r\n", tmp);

      /* Now append the form to the ougoing buffer */
      con->outbuf->append("pwd=", 4);
      con->outbuf->append(con->pass, strlen(con->pass));
      con->outbuf->append("&log=", 5);
      con->outbuf->append(con->user, strlen(con->user));

      /* That's it, we don't need to write anything else, just send the whole buffer out */
      con->state = WORDPRESS_FINI;

      nsock_write(nsp, nsi, ncrack_write_handler, WORDPRESS_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case WORDPRESS_FINI:

      /* let's read the reply to our authentication attempt now */
      if (wordpress_loop_read(nsp, con) < 0)
        break;

      /* we have to jump back to the WORDPRESS_AUTH after finishing with this one
       * so that we continue the brute-forcing 
       */
      con->state = WORDPRESS_AUTH;

      // useful for debugging
      //memprint((const char *)con->inbuf->get_dataptr(), con->inbuf->get_len());

      /*
       * If we get a "302" HTTP response then it's a redirect to wp-admin, meaning
       * the credentials were sent were correct. Otherwise we can assume they were
       * wrong. 
       */
      if (memsearch((const char *)con->inbuf->get_dataptr(), "302 Found", con->inbuf->get_len())) {
        con->auth_success = true;
      }

      /* don't forget to empty the inbuf */
      delete con->inbuf;
      con->inbuf = NULL;

      return ncrack_module_end(nsp, con);
      break;
  }

}

static int
wordpress_loop_read(nsock_pool nsp, Connection *con)
{
  http_info *http_state;  /* per connection state */
  char *ptr;
  char tmp[2];
  long int num;

  if (con->misc_info) {
    http_state = (http_info *)con->misc_info;
  } else {
    http_state = (http_info *)safe_zalloc(sizeof(http_info));
  }

  if (con->inbuf == NULL) {
    nsock_read(nsp, con->niod, ncrack_read_handler, WORDPRESS_TIMEOUT, con);
    return -1;
  }

  // Useful for debugging
  //memprint((const char *)con->inbuf->get_dataptr(), con->inbuf->get_len());

  /* Until when do we keep reading data? 
   * </html>\n is a good indicator but keep in mind other implementations might send </html>\r\n instead
   * Since we observer in wireshark that in the first reply by wordpress when we send it a HTTP GET request
   * the reply always ends in </html>\n then we search for that as the end of the packet (to avoid any 
   * fancy HTTP parsing) - we do this only when we are in WORDPRESS_GET state 
   */

  if ((ptr = memsearch((const char *)con->inbuf->get_dataptr(), "Content-Length:", con->inbuf->get_len()))) {
     /* make pointer point to the end of string "Content-Length:" (plus one space) */
     ptr += 16; /* it should now point to the Content-Length number */

     tmp[0] = *ptr;
     tmp[1] = '\0';
     num = strtol(tmp, NULL, 10);
     /* if first character of Content-length is anything else other than 0, then we expect to 
      * see an HTTP payload */
     if (num != 0) {
       http_state->content_expected = 1;
     }
  } else if ((ptr = memsearch((const char *)con->inbuf->get_dataptr(), "Transfer-Encoding: chunked", con->inbuf->get_len()))) {
    http_state->chunk_expected = 1;
  }

  /* If you have content (content-length > 0) then you need to read until </html> */
  if (http_state->content_expected) {
    if (!memsearch((const char *)con->inbuf->get_dataptr(), "</html>\n", con->inbuf->get_len())) {  
      http_state->content_expected = 0;
      nsock_read(nsp, con->niod, ncrack_read_handler, WORDPRESS_TIMEOUT, con);
      return -1;
    }
  } else if (http_state->chunk_expected) {
 
    if (con->state == WORDPRESS_GET && !memsearch((const char *)con->inbuf->get_dataptr(), "</html>\n\t", con->inbuf->get_len())) { 
      http_state->chunk_expected = 0;
      nsock_read(nsp, con->niod, ncrack_read_handler, WORDPRESS_TIMEOUT, con);
      return -1;
    } 

    if ((ptr = memsearch((const char *)con->inbuf->get_dataptr(), "\r\n\r\n", con->inbuf->get_len()))) {
      ptr += 4;
      if (memcmp(ptr, "\0", 1)) {
        http_state->chunk_expected = 0;
        return 0;
      }
    }
    
  } else {
    /* 
     * For the rest of the cases - when we need an indicator for the replies from wordpress to our authentication
     * attempts, we search for \r\n\r\n as the end of the packet 
     */
    if (!memsearch((const char *)con->inbuf->get_dataptr(), "\r\n\r\n", con->inbuf->get_len())) {
      nsock_read(nsp, con->niod, ncrack_read_handler, WORDPRESS_TIMEOUT, con);
      return -1;
    }
  }
  
 
  return 0;
}

