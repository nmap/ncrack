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

#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <time.h>
#include <stdlib.h>

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

#define NTLMSSP_SIGNATURE "\x4e\x54\x4c\x4d\x53\x53\x50"
#define SHORTPAIR(x) ((x) & 0xff), (((x) >> 8) & 0xff)
#define LONGQUARTET(x) ((x) & 0xff), (((x) >> 8) & 0xff), \
  (((x) >> 16) & 0xff), (((x) >> 24) & 0xff)

#define NEGOTIATE_UNICODE (1<<0)
#define NEGOTIATE_OEM (1<<1)
#define REQUEST_TARGET (1<<2)
#define NEGOTIATE_SEAL (1<<5)
#define NEGOTIATE_LM_KEY (1<<7)
#define NEGOTIATE_128 (1<<29)
#define NEGOTIATE_56 (1<<31)
#define NEGOTIATE_NTLM_KEY (1<<9)
#define NEGOTIATE_NTLM2_KEY (1<<19)
#define NEGOTIATE_TARGET_INFO (1<<23)

#define USE_NTLM 0
#define USE_LM 0
#define USE_NTLMv2 0

#define NTTIME_EPOCH 0x019DB1DED53E8000LL

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

static void winrm_basic(nsock_pool nsp, Connection *con);
static void winrm_negotiate(nsock_pool nsp, Connection *con);
static int winrm_loop_read(nsock_pool nsp, Connection *con);
static void winrm_free(Connection *con);

static void rand_str(char *dest, size_t length);
static void extend_key_56_to_64(const unsigned char *key_56, char *key);
static void setup_des_key(const unsigned char *key_56, DES_key_schedule *ks);
static uint64_t unix2nttime(time_t unix_time);

enum states { WINRM_INIT, WINRM_GET_AUTH, WINRM_BASIC_AUTH, WINRM_NEGOTIATE_AUTH, 
              WINRM_KERBEROS_AUTH, WINRM_CREDSSP_AUTH, WINRM_FINI };

/* Method identification substates */
enum { METHODS_SEND, METHODS_RESULTS };

/* Basic Authentication substates */
enum { BASIC_SEND, BASIC_RESULTS };

/* Negotiate Authentication substates */
enum { NEGOTIATE_CHALLENGE, NEGOTIATE_SEND, NEGOTIATE_RESULTS };


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
  // char *start, *end;  /* auxiliary pointers */
  // size_t i;
  // char *winrm_reply = NULL;   /* server's message reply */
  // size_t tmpsize;
  // char *methods; 
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  winrm_info *info = NULL;
  winrm_state *hstate = NULL;
  con->ops_free = &winrm_free;

  char *tmp;
  size_t tmplen;

  srand(time(NULL)); 

  if (con->misc_info) {
    info = (winrm_info *) con->misc_info;
    printf("info substate: %d \n", info->substate);
  }

  if (serv->module_data && con->misc_info == NULL) {
  //if (con->misc_info == NULL) {

    hstate = (winrm_state *)serv->module_data;
    con->misc_info = (winrm_info *)safe_zalloc(sizeof(winrm_info));
    info = (winrm_info *)con->misc_info;
    if (!strcmp(hstate->auth_scheme, "Basic") 
       || !strcmp(hstate->auth_scheme, "Negotiate")
      ) {
      printf("setting connection state\n");
      con->state = hstate->state;
    }
    info->auth_scheme = Strndup(hstate->auth_scheme, 
            strlen(hstate->auth_scheme));

    printf("got here scheme: %s\n", info->auth_scheme);

    // serv->more_rounds = false;
  } 

  printf("con->state: %d\n", con->state);

  switch (con->state)
  {
    case WINRM_INIT:
      
      con->state = WINRM_GET_AUTH;

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

      con->outbuf->append("Keep-Alive: 300\r\nConnection: keep-alive\r\n", 41);

      con->outbuf->append("Content-Length: 8\r\n", 19);
      con->outbuf->append("\r\n", 2);

      //send 8 random chars
      tmplen = 8 + 1;
      tmp = (char *)safe_malloc(tmplen + 1);
      rand_str(tmp, 8);
    
      con->outbuf->append(tmp, strlen(tmp));
      free(tmp);

      nsock_write(nsp, nsi, ncrack_write_handler, WINRM_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;      

    case WINRM_GET_AUTH:
      if (winrm_loop_read(nsp, con) < 0)
        break;

      //TODO we are missing something with the state.
      // serv->more_rounds = true is causing this behavior.

      
      /* We expect a 401 response which will contain all
       * the accepted authentication methods in the
       * WWW-Authenticate header. */
      if (memsearch((const char *)con->inbuf->get_dataptr(),
            "401", con->inbuf->get_len()) 
          && memsearch((const char *)con->inbuf->get_dataptr(),
            "WWW-Authenticate", con->inbuf->get_len())) {
        /* The response may contain more than one WWW-Authenticate
        *  header.
        */

        if (info == NULL) {
          con->misc_info = (winrm_info *)safe_zalloc(sizeof(winrm_info));
          info = (winrm_info *)con->misc_info;
          
        }
        if (memsearch((const char *)con->inbuf->get_dataptr(),
            "WWW-Authenticate: Basic", con->inbuf->get_len()))
          {

          info->auth_scheme = Strndup("Basic", strlen("Basic"));
          serv->module_data = (winrm_state *)safe_zalloc(sizeof(winrm_state));
          hstate = (winrm_state *)serv->module_data;
          hstate->auth_scheme = Strndup(info->auth_scheme, 
              strlen(info->auth_scheme));
          hstate->state = WINRM_BASIC_AUTH;
          hstate->reconnaissance = true;
          //serv->more_rounds = true;
          return ncrack_module_end(nsp, con);

        } else if (memsearch((const char *)con->inbuf->get_dataptr(),
              "WWW-Authenticate: Negotiate", con->inbuf->get_len()))
          {

          
          info->auth_scheme = Strndup("Negotiate", strlen("Negotiate"));

          // con->state = WINRM_NEGOTIATE_AUTH;
          serv->module_data = (winrm_state *)safe_zalloc(sizeof(winrm_state));
          hstate = (winrm_state *)serv->module_data;
          hstate->auth_scheme = Strndup(info->auth_scheme, 
              strlen(info->auth_scheme));
          hstate->state = WINRM_NEGOTIATE_AUTH;
          hstate->reconnaissance = true;
          // serv->more_rounds = true;
          // con->peer_alive = true;
          // winrm_negotiate(nsp, con);
          return ncrack_module_end(nsp, con);
        }   
      } 
     
      break;

    case WINRM_BASIC_AUTH:

      winrm_basic(nsp, con);
      break;

    case WINRM_NEGOTIATE_AUTH:

      winrm_negotiate(nsp, con);
      break;

    case WINRM_KERBEROS_AUTH:
      printf("Kerberos authentication technique not implemented yet.");
      break;

    case WINRM_CREDSSP_AUTH:
      printf("CREDSSP authentication technique not implemented yet.");
      break;

  }

}

static int
winrm_loop_read(nsock_pool nsp, Connection *con)
{
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
printf("ok\n");
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
printf("ok2\n");
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
winrm_negotiate(nsock_pool nsp, Connection *con)
{
  char *tmp;
  char *tmp2;
  char *tmp3;
  char *tmp4;
  char *b64;
  char *host;
  char *domain_temp;
  char *start, *end;
  char *challenge;
  char *timestamp;
  char *type2;
  char *type4 = NULL;
  char *target_info;
  char *target_name;
  // char *pw_upper;
  size_t i;
  size_t domainlen;
  size_t hostlen;
  size_t tmplen;
  size_t tmplen2;
  size_t tmplen3;
  size_t tmplen4;
  // size_t type2_len;
  size_t tmpsize;
  int targetinfo_offset;
  int targetinfo_length;

  char ntlm_sig[strlen(NTLMSSP_SIGNATURE)];                            
  // char dig[strlen(NTLMSSP_SIGNATURE) + 1]; /* temporary string */
  int ntlm_flags;
  unsigned char tmp_challenge[8];
  unsigned char tmp_buf[4];
  char tmp_buf2[4];
  char tmp_buf3[8];
  //unsigned char *timestamp;

  int target_offset;
  int target_length;  

  // size_t type2len;
  // int type2templen;
  Service *serv = con->service;
  nsock_iod nsi = con->niod;
  winrm_info *info = (winrm_info *)con->misc_info;
  static const char type2_marker[] = { 0x02, 0x00, 0x00, 0x00 };

  switch (info->substate) {
    case NEGOTIATE_CHALLENGE:

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

      con->outbuf->append("Keep-Alive: 300\r\nConnection: keep-alive\r\n", 41);
      con->outbuf->append("Authorization: Negotiate ", 25);


      tmplen = strlen("Workstation") + 1;
      domain_temp = (char *)safe_malloc(tmplen + 1);
      sprintf(domain_temp, "Workstation");

      tmplen = rand() % 8;
      tmp = (char *)safe_malloc(tmplen + 1);
      rand_str(tmp, tmplen + 5);  /* random string for host variable */

      host = (char *)safe_malloc(strlen(tmp) + 1);
      sprintf(host, "%s", tmp);

      hostlen = floor (log10 (abs (strlen(host)))) + 1;

      domainlen = floor (log10 (abs (strlen(domain_temp)))) + 1;

      tmplen2 = strlen(NTLMSSP_SIGNATURE) + 5 
                + 4 /* NTLM flags */ 
                + 2 + 2 + 2 + 2 /* domain */ 
                + 2 + 2 + 2 + 2 /* host */
                + strlen(host) + strlen(domain_temp) + 1;

      tmp2 = (char *)safe_malloc(tmplen2 + 1);


      snprintf((char *)tmp2, tmplen2,
               NTLMSSP_SIGNATURE "%c"
               "\x01%c%c%c" /* 32-bit type = 1 */
               "%c%c%c%c"//"\x37\x82\x08\xe0"   /* 32-bit NTLM flag field */
               "%c%c"       /* domain length */
               "%c%c"       /* domain allocated space */
               "\x20%c"   /* domain name offset offset 32*/
               "%c%c"       /* 2 zeroes */
               "%c%c"       /* host length */
               "%c%c"       /* host allocated space */
               "%c%c"   /* host name offset offset 32 (0x20) + domain length*/
               "%c%c"       /* 2 zeroes */
               "%s"         /* host name */
               "%s",        /* domain string */               
               0,0,0,0,
/* We need to send flags for all the available 
* authentication realms. This includes LM, NTLM 
* and NTLMv2. Usually the server-client should
* agree on the strongest common realm. We will 
* use the lightest bandwith-wise. 
* We will send LM_KEY, NTLM_KEY and NTLM2_KEY.
* In most cases all three realms will be available.
*/
               LONGQUARTET(NEGOTIATE_UNICODE |
                          NEGOTIATE_LM_KEY |
                          NEGOTIATE_NTLM_KEY |
                          NEGOTIATE_NTLM2_KEY),
               SHORTPAIR(strlen(domain_temp)),
               SHORTPAIR(strlen(domain_temp)), 0,
               0x0,0x0,
               SHORTPAIR(strlen(host)),
               SHORTPAIR(strlen(host)), 
               SHORTPAIR(32 + strlen(domain_temp)),
               0x0,0x0,
               domain_temp,  /*this is domain/workstation name */
               host /* hostname is empty, we don't need it */);

      /* Setting the domain or the host seems to be useless.
      * A Windows Server 2012 negotiate request does not contain 
      * those fields. It did contain OS version though. 
      * We should rely on the host and domain values heavily 
      * for type 1 messages.
      */
      b64 = (char *)safe_malloc(BASE64_LENGTH(tmplen2) + 1);
      base64_encode(tmp2, tmplen2, b64);

      con->outbuf->append(b64, strlen(b64));

      free(tmp);
      free(tmp2);
      free(b64);
      free(domain_temp);
      free(host);
      /* Content length should be last as the packet will not
      * be recognized by Wireshark as NTLM. 
      */
      con->outbuf->append("\r\nContent-Length: 0", 19);
      con->outbuf->append("\r\n\r\n", sizeof("\r\n\r\n")-1);

      delete con->inbuf;
      con->inbuf = NULL;

      nsock_write(nsp, nsi, ncrack_write_handler, WINRM_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      
      info->substate = NEGOTIATE_SEND;
      break;

    case NEGOTIATE_SEND:

      if (winrm_loop_read(nsp, con) < 0)
        break;

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();


      /* If the response has the code 401 and the header
      * WWW-Authenticate probably we have received the challenge 
      * reponse.
      */
      if (memsearch((const char *)con->inbuf->get_dataptr(),
            "401", con->inbuf->get_len()) 
          && (start = memsearch((const char *)con->inbuf->get_dataptr(),
            "WWW-Authenticate: Negotiate", con->inbuf->get_len()))) {
        //Extract the challenge, craft next request and send

          start += sizeof("WWW-Authenticate: Negotiate ") - 1;
          end = start;
          i = 0;
          while (*end != ' ' && i != con->inbuf->get_len()) {
            end++;
            i++;
          }

          challenge = Strndup(start, i);

          /* We calculate 4*(n/3) bytes as the length of the decoded
          * string.
          */

          type2 = (char *)safe_malloc(BASE64_LENGTH(strlen(challenge) + 1));
          /*  Base64 decode the type2 message (challenge)
          */
          // type2len = BASE64_LENGTH(strlen(challenge) + 1);
          
          // type2templen = size_t2int(type2len);
          // type2 = NULL;
          // type2_len = 0;
          tmplen2 = strlen(challenge);
          base64_decode(challenge, tmplen2, type2);

          if (!type2) {
            /* Type2 message decoding failed.
            */
            free(type2);
            serv->end.orly = true;
            tmpsize = sizeof("Invalid type2 message.\n");
            serv->end.reason = (char *)safe_malloc(tmpsize);
            snprintf(serv->end.reason, tmpsize,
                "Invalid type2 message.\n");

            return ncrack_module_end(nsp, con);
          }
          printf("%s\n", type2);
          for (i=0; i <tmplen2;i++){
            printf("%02x", type2[i]);
          }printf("\n");
  /* NTLM type-2 message structure:
          Index  Description            Content
            0    NTLMSSP Signature      Null-terminated ASCII "NTLMSSP"
                                        (0x4e544c4d53535000)
            8    NTLM Message Type      long (0x02000000)
           12    Target Name            security buffer
           20    Flags                  long
           24    Challenge              8 bytes
          (32)   Context                8 bytes (two consecutive longs) (*)
          (40)   Target Information     security buffer (*)
          (48)   OS Version Structure   8 bytes (*)
  32 (48) (56)   Start of data block    (*)
                                        (*) -> Optional
  */


          /* The first 7 bytes are the string NTLMSSP
          * followed by a null byte.
          */
          for (i = 0; i < strlen(NTLMSSP_SIGNATURE) + 1; i++) {
            ntlm_sig[i] = *type2++;
          }
          // strncpy(psql_code_ret, ntlm_sig, strlen(NTLMSSP));

          if (strncmp(ntlm_sig, NTLMSSP_SIGNATURE, strlen(NTLMSSP_SIGNATURE))) {
            /* In this case the NTLMSSP flag is not present.
            *  Exit gracefully.
            */
            //free(type2);
            serv->end.orly = true;
            tmpsize = sizeof("Invalid type2 message.\n");
            serv->end.reason = (char *)safe_malloc(tmpsize);
            snprintf(serv->end.reason, tmpsize,
                "Invalid type2 message.\n");

            return ncrack_module_end(nsp, con);
          }

          /* Checking for type 2 message flag
          *  The next four bytes should contain the value
          *  \x02\x00\x00\x00
          */
          char type2_marker_check[4];
          for (i = 0; i < 4; i++) {
            type2_marker_check[i] = *type2++;
          }

          if (strncmp(type2_marker_check, type2_marker, strlen(type2_marker))) {
            /* In this case the type2 message flag is not present.
            *  Exit gracefully.
            */
            free(type2);
            serv->end.orly = true;
            tmpsize = sizeof("Invalid type2 message.\n");
            serv->end.reason = (char *)safe_malloc(tmpsize);
            snprintf(serv->end.reason, tmpsize,
                "Invalid type2 message.\n");

            return ncrack_module_end(nsp, con);
          }

          /* Next 8 bytes are the target name. In case of NTLMv2
          * authentication we will need them.   
          * 2 bytes target name length
          * 2 bytes target name length (we skip that)
          * 4 bytes target name offset  
          */

          // for (i = 0; i < 2; i++) {
          //   // tmp_buf[i] =  (unsigned char) *type2++;
            

          // }
          snprintf(tmp_buf2, 4, "%d", *type2++);

          target_length = (int)strtol(tmp_buf2, NULL, 10);
          printf("Temp buf: %d", target_length);
          // target_length = (unsigned short)(((unsigned short)tmp_buf[0]) |
          //                 ((unsigned short)tmp_buf[1] << 8));

          for (i = 0; i < 3; i++) {
            *type2++;
          }
          /* We want to read 4 bytes and translate them as decimal
          * The values are literals. They are written as decimals
          * not as hex.
          */
          snprintf(tmp_buf3, 4, "%d", *type2++);
          for (i = 0; i < 3; i++) {
            // snprintf(tmp_buf3 + (i*2), 2, "%x", *type2++);
            // tmp_buf[i] =  (unsigned char) *type2++;
            *type2++;
          }

          target_offset = (int)strtol(tmp_buf3, NULL, 10);
          printf("offset!: %d", target_offset);
          // target_offset = ((unsigned int)tmp_buf[0]) | ((unsigned int)tmp_buf[1] << 8) |
          // ((unsigned int)tmp_buf[2] << 16) | ((unsigned int)tmp_buf[3] << 24);
          

          /* Next 4 bytes are the NTLM flags
          */
          for (i = 0; i < 4; i++) {
            tmp_buf[i] =  (unsigned char) *type2++;
          }

          /* Convert to big endian
          */
          ntlm_flags = ((unsigned int)tmp_buf[0]) | ((unsigned int)tmp_buf[1] << 8) |
          ((unsigned int)tmp_buf[2] << 16) | ((unsigned int)tmp_buf[3] << 24);
         
          if (ntlm_flags & ( 1 << 1)){
            //supports OEM
          }
          if (ntlm_flags & ( 1 << 0)){
            //supports unicode
          }
         

          // if (ntlm_flags & NEGOTIATE_NTLM2_KEY ){
          //   USE_NTLMv2 = 1;
          // }
          // else if (ntlm_flags & NEGOTIATE_NTLM_KEY ){
          //   USE_NTLM = 1;
          // }
          // else if (ntlm_flags & NEGOTIATE_LM_KEY ){
          //   USE_LM = 1;
          // }


          /* Next 8 bytes are the NTLM flags
          */
          for (i = 0; i < 8; i++) {
            tmp_challenge[i] =  (unsigned char) *type2++;
          }


          /* Reminder: challenge is signed.
          */
          printf("NTLM CHALLENGE: ");
          for (i=0; i <8;i++){
            printf("%x", tmp_challenge[i]);
          }printf("\n");

          /* Next 8 bytes are the Target info buffer  
          * 2 bytes target info length
          * 2 bytes target info length (we skip that)
          * 4 bytes target info offset  
          */

          // for (i = 0; i < 2; i++) {
          //   tmp_buf[i] =  (unsigned char) *type2++;
          // }
          // targetinfo_length = (unsigned short)(((unsigned short)tmp_buf[0]) |
          //                 ((unsigned short)tmp_buf[1] << 8));

          for (i = 0; i < 8; i++) {
            *type2++;
          }

          snprintf(tmp_buf3, 4, "%d", *type2++);
          for (i = 0; i < 3; i++) {
            *type2++;
          }

          targetinfo_length = (int)strtol(tmp_buf3, NULL, 10);
          printf("target info length: %d\n", targetinfo_length);

          snprintf(tmp_buf3, 4, "%d", *type2++);
          for (i = 0; i < 3; i++) {
            *type2++;
          }

          targetinfo_offset = (int)strtol(tmp_buf3, NULL, 10);
          printf(" target info offset: %d\n", targetinfo_offset);
          // for (i = 0; i < 4; i++) {
          //   tmp_buf[i] =  (unsigned char) *type2++;
          // }
          // targetinfo_offset = ((unsigned int)tmp_buf[0]) | ((unsigned int)tmp_buf[1] << 8) |
          // ((unsigned int)tmp_buf[2] << 16) | ((unsigned int)tmp_buf[3] << 24);
          


          target_info = (char *)safe_malloc(targetinfo_length + 1);
          target_name = (char *)safe_malloc(target_length + 1);

          if (ntlm_flags & NEGOTIATE_TARGET_INFO) {
            /* If the server sends target info we will need it
            * if we use NTLMv2 authentication. For this purpose
            * we read both Target Name and Target Information.
            */

            /* We read from type2 at offset - 40. 40 are the bytes
            * we have already read from the buffer.
            */
            type4 = (char *)safe_malloc(BASE64_LENGTH(strlen(challenge) + 1));

            tmplen4 = strlen(challenge);
            base64_decode(challenge, tmplen4, type4);

            memcpy(target_name, &type4[target_offset], target_length);
            memcpy(target_info, &type4[targetinfo_offset], targetinfo_length);
            printf("Target Name: ");
            for(i=0; i<target_length; i++){
              printf("%02x", target_name[i]);
            }printf("\n");

            printf("Target Info: ");
            for(i=0; i<targetinfo_length; i++){
              printf("%02x", target_info[i]);
            }printf("\n");
          }

          // target_info = "\x02\x00\x0c\x00\x44\x00\x4f\x00\x4d\x00\x41\x00\x49\x00\x4e\x00\x01\x00\x0c\x00\x53\x00\x45\x00\x52\x00\x56\x00\x45\x00\x52\x00\x04\x00\x14\x00\x64\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00\x2e\x00\x63\x00\x6f\x00\x6d\x00\x03\x00\x22\x00\x73\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x2e\x00\x64\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00\x2e\x00\x63\x00\x6f\x00\x6d\x00\x00\x00\x00\x00";
          // targetinfo_length = 98;


// 0000   02 00 08 00 54 00 45 00 53 00 54 00 01 00 08 00
// 0010   54 00 45 00 53 00 54 00 04 00 08 00 54 00 45 00
// 0020   53 00 54 00 03 00 08 00 54 00 45 00 53 00 54 00
// 0030   07 00 08 00 fd 11 60 12 65 00 d3 01 00 00 00 00

// target_info = "\x02\x00\x08\x00\x54\x00\x45\x00\x53\x00\x54\x00\x01\x00\x08\x00\x54\x00\x45\x00\x53\x00\x54\x00\x04\x00\x08\x00\x54\x00\x45\x00\x53\x00\x54\x00\x03\x00\x08\x00\x54\x00\x45\x00\x53\x00\x54\x00\x07\x00\x08\x00\xfd\x11\x60\x12\x65\x00\xd3\x01\x00\x00\x00\x00";
// targetinfo_length = 64;
          /* The challenge is extracted, we can now safely
          *  proceed in construction of type 3 message.
          */

          /*
          *
          * Description               Content
          * 0 NTLMSSP Signature       Null-terminated ASCII "NTLMSSP"
          * 8 NTLM Message Type       long (0x03000000)
          * 12  LM/LMv2 Response      security buffer
          * 20  NTLM/NTLMv2 Response  security buffer
          * 28  Target Name           security buffer
          * 36  User Name             security buffer
          * 44  Workstation Name      security buffer
          * (52)  Session Key (optional)  security buffer
          * (60)  Flags (optional)    long
          * (64)  OS Version Structure (Optional) 8 bytes
          * 52 (64) (72)  start of data block
          */   



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

          con->outbuf->append("Keep-Alive: 300\r\nConnection: keep-alive\r\n", 41);


          con->outbuf->append("Authorization: Negotiate ", 25);



          /* Let's create LM response
          */
          unsigned char lmbuffer[0x18];
          unsigned char lmresp[24]; /* fixed-size */
          int lmrespoff;
          int ntrespoff;
          unsigned int ntresplen = 24;
          size_t userlen; 
          size_t hostoff = 0;
          size_t useroff = 0;
          size_t domoff = 0;


          static const unsigned char magic[] = {
            0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 /* KGS!@#$% */
          };
          unsigned char pw_upper[14];
          size_t pw_len = 14;
          tmplen = strlen(con->pass) + 1;
          tmp = (char *)safe_zalloc(pw_len + 1);

          sprintf(tmp, "%s", con->pass);

          /* First convert password to uppercase and pad it 
          * to 14 characters with zeros.
          */
          char *s = tmp;
          while (*s) {
            *s = toupper((unsigned char) *s);
            s++;
          }

          for (i=0; i < pw_len; i++){
            pw_upper[i] = (unsigned char) tmp[i];
          } 
          
          free(tmp);

          DES_key_schedule ks;

//Testing
// tmp_challenge[0] = 0x01;
// tmp_challenge[1] = 0x23;
// tmp_challenge[2] = 0x45;
// tmp_challenge[3] = 0x67;
// tmp_challenge[4] = 0x89;
// tmp_challenge[5] = 0xab;
// tmp_challenge[6] = 0xcd;
// tmp_challenge[7] = 0xef;
 //         0000   db 30 c8 ef e1 ef ba 21
// tmp_challenge[0] = 0xdb;
// tmp_challenge[1] = 0x30;
// tmp_challenge[2] = 0xc8;
// tmp_challenge[3] = 0xef;
// tmp_challenge[4] = 0xe1;
// tmp_challenge[5] = 0xef;
// tmp_challenge[6] = 0xba;
// tmp_challenge[7] = 0x21;

          /* The "fixed" password at 14 bytes length must be split
          * in two equal length keys.
          */

          /* Two DES keys (one from each 7-byte half) are used to 
          * DES-encrypt  the constant ASCII string "KGS!@#$%" 
          * (resulting in two 8-byte ciphertext values).
          *
          * The two ciphertext valus are concatenated to form a 16
          * byte value - The LM hash.
          *
          * The LM hash is then padded with zeros to 21 bytes.
          */

          setup_des_key(pw_upper, &ks);
          DES_ecb_encrypt((DES_cblock *)magic, (DES_cblock *)lmbuffer,
                          &ks, DES_ENCRYPT);

          setup_des_key(pw_upper + 7, &ks);
          DES_ecb_encrypt((DES_cblock *)magic, (DES_cblock *)(lmbuffer + 8),
          &ks, DES_ENCRYPT);

          memset(lmbuffer + 16, 0, 21 - 16);


          DES_key_schedule ks2;

          setup_des_key(lmbuffer, &ks2);
          DES_ecb_encrypt((DES_cblock*) tmp_challenge, (DES_cblock*) lmresp,
                          &ks2, DES_ENCRYPT);

          setup_des_key(lmbuffer + 7, &ks2);
          DES_ecb_encrypt((DES_cblock*) tmp_challenge, (DES_cblock*) (lmresp + 8),
                          &ks2, DES_ENCRYPT);

          setup_des_key(lmbuffer + 14, &ks2);
          DES_ecb_encrypt((DES_cblock*) tmp_challenge, (DES_cblock*) (lmresp + 16),
                          &ks2, DES_ENCRYPT);

          tmplen = strlen("Workstation");
          domain_temp = (char *)safe_malloc(tmplen );
          sprintf(domain_temp, "Workstation");
          
          char domain_unicode[2*tmplen];
          domainlen = 2*tmplen;          
          /* Transform ascii to unicode
          */
          for(i = 0; i < tmplen; i++) {
            domain_unicode[2 * i] = (unsigned char)domain_temp[i];
            domain_unicode[2 * i + 1] = '\0';
          }

          char user_unicode[2*strlen(con->user)];
          userlen = 2*strlen(con->user);

          /* Transform ascii to unicode
          */
          for(i = 0; i < strlen(con->user); i++) {
            user_unicode[2 * i] = (unsigned char)con->user[i];
            user_unicode[2 * i + 1] = '\0';
          }

          hostlen = 0;
          lmrespoff = 64;
          ntrespoff = lmrespoff + 0x18;

          /* The following part is NM response. Currently it seems
          * that we are sending only the LM flag. Maybe we can get 
          * away with this and only do the LM part.
          */
          // if (ntlm_flags & NEGOTIATE_LM_KEY) {
            /* Let's craft the NM response.
            */

            size_t passlen = 0;
            unsigned char ntbuffer[0x18];
            unsigned char ntresp[24]; /* fixed-size */
            unsigned char *ptr_ntresp = &ntresp[0];

            char pass_unicode[2*strlen(con->pass)];
            passlen = 2*strlen(con->pass);          
            /* Transform ascii to unicode
            */
            for(i = 0; i < strlen(con->pass); i++) {
              pass_unicode[2 * i] = (unsigned char)con->pass[i];
              pass_unicode[2 * i + 1] = '\0';
            }
          // }

          // if (ntlm_flags & NEGOTIATE_NTLM_KEY) {
            /* Create NT hashed password. 
            */

            MD4_CTX MD4pw;

            MD4_Init(&MD4pw);
            MD4_Update(&MD4pw, pass_unicode, sizeof(pass_unicode));
            MD4_Final(ntbuffer, &MD4pw);
            memset(ntbuffer + 16, 0, 21 - 16);

            DES_key_schedule ks3;

            setup_des_key(ntbuffer, &ks2);
            DES_ecb_encrypt((DES_cblock*) tmp_challenge, (DES_cblock*) ntresp,
                            &ks2, DES_ENCRYPT);

            setup_des_key(ntbuffer + 7, &ks2);
            DES_ecb_encrypt((DES_cblock*) tmp_challenge, (DES_cblock*) (ntresp + 8),
                            &ks2, DES_ENCRYPT);

            setup_des_key(ntbuffer + 14, &ks2);
            DES_ecb_encrypt((DES_cblock*) tmp_challenge, (DES_cblock*) (ntresp + 16),
                            &ks2, DES_ENCRYPT);



            ptr_ntresp = ntresp;
          // }

          if (ntlm_flags & NEGOTIATE_NTLM2_KEY) {
            /* Let's craft NTLMv2 response if it is supported
            * by the server.
            */

            //unsigned char ntbuffer[0x18];
            char entropy[8];
            unsigned char ntlmv2hash[0x18];
            unsigned char tmphash[0x18];
            /* Generate 8 random characters for NTLMv2 and LMv2
            * hashes.
            */
            rand_str(entropy, 8);
//Testing 0xffffff0011223344
// entropy[0] = 0xff;
// entropy[1] = 0xff;
// entropy[2] = 0xff;
// entropy[3] = 0x00;
// entropy[4] = 0x11;
// entropy[5] = 0x22;
// entropy[6] = 0x33;
// entropy[7] = 0x44;
// 0000   fb 10 3f d3 5c fa 6b 79
// entropy[0] = 0xfb;
// entropy[1] = 0x10;
// entropy[2] = 0x3f;
// entropy[3] = 0xd3;
// entropy[4] = 0x5c;
// entropy[5] = 0xfa;
// entropy[6] = 0x6b;
// entropy[7] = 0x79;
            /* Calculate NTLM hash as we did before for v1.
            * After calculating the NTLM hash we concatenate
            * the unicode form of username and Target name 
            * (which is retrieved by type 2 message).
            * At this point we have the username and password
            * in unicode encoding from LM and NTLM v1 calculations.
            * If we change the current state of the script we need
            * to take care of that.
            */

            /* From the conducted tests if the server supports Unicode
            * it will send the Target Name in Unicode encoding.
            * I'll leave it as is for the moment but we might need
            * to check if the value is Unicode and if not, convert it
            * to Unicode.
            */

            /* Now we concatenate unicode uppercase username with 
            * unicode domain. 
            * Let's say we have username "user" and domain "TEST"
            * the result will be USERTEST. 
            */

            /* First we convert username to uppercase string.
            */
            unsigned char user_upper[strlen(con->user)];
            tmplen = strlen(con->user) + 1;
            tmp = (char *)safe_zalloc(strlen(con->user) + 1);

            sprintf(tmp, "%s", con->user);

            char *s = tmp;
            while (*s) {
              *s = toupper((unsigned char) *s);
              s++;
            }

            for (i=0; i < strlen(con->user); i++){
              user_upper[i] = (unsigned char) tmp[i];
            } 

            free(tmp);

            /* And then transform it into unicode.
            */
            char user_upper_unicode[2*strlen(con->user)];
            userlen = 2*strlen(con->user);

            for(i = 0; i < sizeof(user_upper); i++) {
              user_upper_unicode[2 * i] = (unsigned char)user_upper[i];
              user_upper_unicode[2 * i + 1] = '\0';
            }


            /* And then transform it into unicode.
            */
            char domain_temp_unicode[2*strlen(domain_temp)];

            for(i = 0; i < strlen(domain_temp); i++) {
              domain_temp_unicode[2 * i] = (unsigned char)domain_temp[i];
              domain_temp_unicode[2 * i + 1] = '\0';
            }
            /* Concatenate the two strings.
            */

            unsigned char target_name2[12];
            target_name2[0] = 0x44;
            target_name2[1] = 0x00;
            target_name2[2] = 0x4f;
            target_name2[3] = 0x00;
            target_name2[4] = 0x4d;
            target_name2[5] = 0x00;
            target_name2[6] = 0x41;
            target_name2[7] = 0x00;
            target_name2[8] = 0x49;
            target_name2[9] = 0x00;
            target_name2[10] = 0x4e;
            target_name2[11] = 0x00;



            char userdomain[sizeof(user_upper_unicode) + sizeof(domain_temp_unicode)];
            // snprintf(userdomain, sizeof(user_unicode), "%s", user_unicode);
            for (i=0; i <sizeof(user_upper_unicode); i++){
              userdomain[i] = user_upper_unicode[i];
            }
            for (i=sizeof(user_upper_unicode); i <sizeof(domain_temp_unicode)+sizeof(user_upper_unicode); i++){
              userdomain[i] = domain_temp_unicode[i-sizeof(user_upper_unicode)];
            }
            // strcat(userdomain, target_name);
            printf("Userdomain: ");
            for(i=0;i<sizeof(userdomain);i++){
              printf("%02x",userdomain[i] );
            }printf("\n");

            /* This string will then be hashed by HMAC_MD5 with NTLM 
            * hash as a key. We use the ntbuffer but not the zero-padded
            * version of it. This is why we use 16 bytes and not 22.
            * The result will also be 16 bytes. 
            */

            /* We might need to use 0x18
            * I don't know yet. Should test it.
            */

            HMAC(EVP_md5(), ntbuffer, 16, (unsigned const char*) userdomain, 
                  sizeof(userdomain), ntlmv2hash, NULL);
            printf("NTLM key : ");
            for(i=0;i<sizeof(ntbuffer);i++){
              printf("%02x",ntbuffer[i] );
            }printf("\n");


            printf("NTLMV2 hash: ");
            for(i=0;i<sizeof(ntlmv2hash);i++){
              printf("%02x",ntlmv2hash[i] );
            }printf("\n");
            /* NTLMv2 response 
            * We need to construct the NTLMv2 blob here.
            */

            /* Description Content
              0 Blob Signature  0x01010000
              4 Reserved  long (0x00000000)
              8 Timestamp Little-endian, 64-bit signed
              16  Client Nonce  8 bytes
              24  Unknown 4 bytes
              28  Target Information  Target Information block (from the Type 2 message).
              (variable)  Unknown 4 bytes
            */

            /* We add to the above 8 bytes at the beggining for the generated nonce.
            */

            tmplen3= 28 + 4 + targetinfo_length + 8;
            tmp3 = (char *)safe_malloc(tmplen3 + 1);


            /* Fill it with zeros. That's for the Unknown and Reserved fields.
            */
            memset(tmp3, 0, tmplen3);

            uint64_t t;
            t = unix2nttime(time(NULL));
            printf("%" PRIu64 "\n", t);
            printf("0x%" PRIx64 "\n", t);

            tmp3[8+8] = (char)(t & 0x000000FF);
            tmp3[9+8] = (char)((t & 0x0000FF00) >> 8);
            tmp3[10+8] = (char)((t & 0x00FF0000) >> 16);
            tmp3[11+8] = (char)((t & 0xFF000000) >> 24);
            tmp3[12+8] = (char)((t >> 32) & 0x000000FF);
            tmp3[13+8] = (char)(((t >> 32) & 0x0000FF00) >> 8);
            tmp3[14+8] = (char)(((t >> 32) & 0x00FF0000) >> 16);
            tmp3[15+8] = (char)(((t >> 32) & 0xFF000000) >> 24);


//Testing
//0x0090d336b734c301
// tmp3[8+8] = 0x00;
// tmp3[9+8] = 0x90;
// tmp3[10+8] = 0xd3;
// tmp3[11+8] = 0x36;
// tmp3[12+8] = 0xb7;
// tmp3[13+8] = 0x34;
// tmp3[14+8] = 0xc3;
// tmp3[15+8] = 0x01;
// 0000   00 2f 25 12 65 00 d3 01
// tmp3[8+8] = 0x00;
// tmp3[9+8] = 0x2f;
// tmp3[10+8] = 0x25;
// tmp3[11+8] = 0x12;
// tmp3[12+8] = 0x65;
// tmp3[13+8] = 0x00;
// tmp3[14+8] = 0xd3;
// tmp3[15+8] = 0x01;
            snprintf((char *)tmp3 + 8, 4,
             "\x01\x01%c%c",   /* Blob Signature */
             0, 0);


            memcpy(tmp3, tmp_challenge, 8);
            //memcpy(tmp3 + 8 + 8, t, 8);
            memcpy(tmp3 + 16 + 8, entropy, 8);
            memcpy(tmp3 + 28 + 8, target_info, targetinfo_length);

            printf("Blob: ");
            for(i=0;i<tmplen3;i++){
              printf("%02x",tmp3[i] );
            }printf("\n");

            HMAC(EVP_md5(), ntlmv2hash, 16, (unsigned const char*) tmp3, 
                  tmplen3, tmphash, NULL);

            /* Now we want the same blob but without the concatenated
            * nonce at the beggining. Instead the first 16 bytes will 
            * be the ntlmv2hash which was calculated just now.
            */

            ntresplen = 28 + 4 + targetinfo_length + 16;

            tmp4 = (char *)safe_malloc(ntresplen + 1);
            memcpy(tmp4, tmphash, 16);
            memcpy(tmp4 + 16, tmp3 + 8, tmplen3 - 8);
            ptr_ntresp = (unsigned char *) tmp4;

            /* LMv2 response 
            * 1. Calculate NTLM hash. 
            * 2. Unicode uppercase username and target name
            * HMAC-MD5 on the above string and NTLM hash as key (16 bytes)
            * 3. Random 8 byte nonce
            * 4. Concatenate challenge with nonce from #3
            * HMAC-MD5 the above string and NTLMv2 hash as key (16 bytes)
            * NTLMv2 hash is the output of step 2.
            * 5. Concatenate output of step 4 with nonce (24 bytes)
            *
            * At this point we have performed step 1, 2 and 3
            */

// LMv2 WORKS
            char chall_nonce [16];

            for (i=0; i <sizeof(tmp_challenge); i++){
              chall_nonce[i] = tmp_challenge[i];
            }
            for (i=sizeof(tmp_challenge); i <sizeof(tmp_challenge)+sizeof(entropy); i++){
              chall_nonce[i] = entropy[i-sizeof(tmp_challenge)];
            }

            // printf("Chall_nonce: ");
            // for(i=0;i<sizeof(chall_nonce);i++){
            //   printf("%02x",chall_nonce[i] );
            // }printf("\n");


            HMAC(EVP_md5(), ntlmv2hash, 16, (unsigned const char*) chall_nonce, 
                  sizeof(chall_nonce), lmresp, NULL);

            // printf("LM resp: ");
            // for(i=0;i<sizeof(lmresp);i++){
            //   printf("%02x",lmresp[i] );
            // }printf("\n");

            memcpy(&lmresp[16], entropy, sizeof(entropy));

            // printf("LM resp2: ");
            // for(i=0;i<sizeof(lmresp);i++){
            //   printf("%02x",lmresp[i] );
            // }printf("\n");

          }
          domoff = ntrespoff + ntresplen;
          //domoff = lmrespoff + 0x18;
          useroff = domoff + domainlen;
          hostoff = useroff + userlen;



          tmplen2 = strlen(NTLMSSP_SIGNATURE) + 1 + 4 
                    + 2 + 2 + 2 + 2 /* LM */
                    + 2 + 2 + 2 + 2 /* NT */
                    + 2 + 2 + 2 + 2 /* domain */
                    + 2 + 2 + 2 + 2 /* user */
                    + 2 + 2 + 2 + 2 /* host */
                    + 2 + 2 + 2 + 2 /* session key */
                    + 4 /* flag */
                    + sizeof(domain_unicode) + sizeof(user_unicode)
                    //+ strlen(host) 
                    + 0x18
                    + ntresplen
                    /* we skip NM response */
                    ;    

          tmp2 = (char *)safe_malloc(tmplen2 + 1);


          snprintf((char *)tmp2, tmplen2,
                  NTLMSSP_SIGNATURE "%c"
                  "\x03%c%c%c"  /* 32-bit type = 3 */

                  "%c%c"  /* LanManager length */
                  "%c%c"  /* LanManager allocated space */
                  "%c%c"  /* LanManager offset */
                  "%c%c"  /* 2 zeroes */

                  "%c%c"  /* NT-response length */
                  "%c%c"  /* NT-response allocated space */
                  "%c%c"  /* NT-response offset */
                  "%c%c"  /* 2 zeroes */

                  "%c%c"  /* domain length */
                  "%c%c"  /* domain allocated space */
                  "%c%c"  /* domain name offset */
                  "%c%c"  /* 2 zeroes */

                  "%c%c"  /* user length */
                  "%c%c"  /* user allocated space */
                  "%c%c"  /* user offset */
                  "%c%c"  /* 2 zeroes */

                  "%c%c"  /* host length */
                  "%c%c"  /* host allocated space */
                  "%c%c"  /* host offset */
                  "%c%c"  /* 2 zeroes */

                  "%c%c"  /* session key length (unknown purpose) */
                  "%c%c"  /* session key allocated space (unknown purpose) */
                  "%c%c"  /* session key offset (unknown purpose) */
                  "%c%c"  /* 2 zeroes */

                  "%c%c%c%c", 

                  0,                /* zero termination */
                  0, 0, 0,          /* type-3 long, the 24 upper bits */

                  SHORTPAIR(0x18),  /* LanManager response length, twice */
                  SHORTPAIR(0x18),
                  SHORTPAIR(lmrespoff),
                  0x0, 0x0,

                  0x0, 0x0, /* NTLM response length, twice */
                  0x0, 0x0, /* For now we set zeros and if supported */
                  0x0, 0x0, /* we will popoulated later. */
                  0x0, 0x0,

                  SHORTPAIR(domainlen),
                  SHORTPAIR(domainlen),
                  SHORTPAIR(domoff),
                  0x0, 0x0,

                  SHORTPAIR(userlen),
                  SHORTPAIR(userlen),
                  SHORTPAIR(useroff),
                  0x0, 0x0,

                  SHORTPAIR(hostlen),
                  SHORTPAIR(hostlen),
                  SHORTPAIR(hostoff),
                  0x0, 0x0,

                  0x0, 0x0,
                  0x0, 0x0,
                  0x0, 0x0,
                  0x0, 0x0,
                  LONGQUARTET(NEGOTIATE_UNICODE |
                          NEGOTIATE_LM_KEY |
                          NEGOTIATE_NTLM_KEY |
                          NEGOTIATE_NTLM2_KEY)
                  );

          if (ntlm_flags & NEGOTIATE_NTLM_KEY) {
            snprintf(&tmp2[20], 2, "%c%c", SHORTPAIR(ntresplen));
            snprintf(&tmp2[22], 2, "%c%c", SHORTPAIR(ntresplen));
            snprintf(&tmp2[24], 2, "%c%c", SHORTPAIR(ntrespoff));
          }

          memcpy(&tmp2[lmrespoff], lmresp, 0x18);
          memcpy(&tmp2[ntrespoff], ptr_ntresp, ntresplen);
          memcpy(&tmp2[domoff], domain_unicode, domainlen);
          memcpy(&tmp2[useroff], user_unicode, userlen);
          // memset(tmp2 + hostoff, host, hostlen);

          b64 = (char *)safe_malloc(BASE64_LENGTH(tmplen2) + 1);
          base64_encode(tmp2, tmplen2, b64);

          con->outbuf->append(b64, strlen(b64));
        /* Content length should be last as the packet will not
        * be recognized by Wireshark as NTLM. 
        */
          con->outbuf->append("\r\nContent-Length: 0", 19);

          free(tmp2);
          free(b64);
          con->outbuf->append("\r\n\r\n", sizeof("\r\n\r\n")-1);

          nsock_write(nsp, nsi, ncrack_write_handler, WINRM_TIMEOUT, con,
            (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
          
          delete con->inbuf;
          con->inbuf = NULL;

          info->substate = NEGOTIATE_RESULTS;
          break;
      }

      /* The in buffer has to be cleared out, because we are expecting
       * possibly new answers in the same connection.
       */
      delete con->inbuf;
      con->inbuf = NULL;

      ncrack_module_end(nsp, con);
      break;

    case NEGOTIATE_RESULTS:
      if (winrm_loop_read(nsp, con) < 0)
        break;

      info->substate = NEGOTIATE_CHALLENGE;

      //((winrm_state *) serv->module_data)->state = WINRM_NEGOTIATE_AUTH;
      // serv->end.orly = true;
      // tmpsize = sizeof("Test termination.\n");
      // serv->end.reason = (char *)safe_malloc(tmpsize);
      // snprintf(serv->end.reason, tmpsize,
      //     "Test termination.\n");

      // return ncrack_module_end(nsp, con);
      /* Successful login attempt results in empty 200 response.
      * Else a 401 response will appear containing the authentication
      * methods.
      */
      if (memsearch((const char *)con->inbuf->get_dataptr(),
            "200", con->inbuf->get_len())) {
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


static void 
rand_str(char *dest, size_t length) 
{
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    while (length-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        *dest++ = charset[index];
    }
    *dest = '\0';
}

/*
* Turns a 56-bit key into being 64-bit wide.
*/
static void extend_key_56_to_64(const unsigned char *key_56, char *key)
{
  key[0] = key_56[0];
  key[1] = (unsigned char)(((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1));
  key[2] = (unsigned char)(((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2));
  key[3] = (unsigned char)(((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3));
  key[4] = (unsigned char)(((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4));
  key[5] = (unsigned char)(((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5));
  key[6] = (unsigned char)(((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6));
  key[7] = (unsigned char) ((key_56[6] << 1) & 0xFF);
}

static void 
setup_des_key(const unsigned char *key_56,
                          DES_key_schedule *ks)
{
  DES_cblock key;

  /* Expand the 56-bit key to 64-bits */
  extend_key_56_to_64(key_56, (char *) &key);

  /* Set the key parity to odd */
  DES_set_odd_parity(&key);

  /* Set the key */
  DES_set_key(&key, ks);
}

static uint64_t
unix2nttime(time_t unix_time)
{
    long long wt;
    wt = unix_time * (uint64_t)10000000 + (uint64_t)NTTIME_EPOCH;
    return wt;
}
