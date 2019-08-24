/***************************************************************************
 * ncrack_mongodb.cc -- ncrack module for the MongoDB protocol                 *
 * Coded by edeirme                                                        *
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
#include <openssl/md5.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <time.h>

#define MONGODB_TIMEOUT 10000
#define LONGQUARTET(x) ((x) & 0xff), (((x) >> 8) & 0xff), \
  (((x) >> 16) & 0xff), (((x) >> 24) & 0xff)

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);
static int mongodb_loop_read(nsock_pool nsp, Connection *con);
static void mongodb_free(Connection *con);
static void mongodb_cr(nsock_pool nsp, Connection *con);
static void mongodb_scram_sha1(nsock_pool nsp, Connection *con);

static void rand_str(char *dest, size_t length);
static void xor_hashes(char *to, const u_char *s1, const u_char *s2, u_int len);
static char *enhex(char *dest, const unsigned char *src, size_t n);

enum states { MONGODB_INIT, MONGODB_RECEIVE, MONGODB_RECEIVE_VER, 
  MONGODB_CR, MONGODB_SCRAM_SHA1};

/* MongoDB CR substates */
enum { CR_INIT, CR_NONCE, CR_FINI }; 

/* MongoDB SCRAM_SHA_1 substates */
enum { SCRAM_INIT, SCRAM_NONCE, SCRAM_FINI }; 

static int
mongodb_loop_read(nsock_pool nsp, Connection *con)
{
  if (con->inbuf == NULL) {
    nsock_read(nsp, con->niod, ncrack_read_handler, MONGODB_TIMEOUT, con);
    return -1;
  }
  return 0;
}

typedef struct mongodb_info {
  char *auth_scheme;
  char *client_nonce;
  int substate;
} mongodb_info;

typedef struct mongodb_state {
  bool reconnaissance;
  char *auth_scheme;
  int state;
  int keep_alive;
} mongodb_state;

void
ncrack_mongodb(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  mongodb_info *info = NULL;
  mongodb_state *hstate = NULL;
  con->ops_free = &mongodb_free;

  int tmplen;
  char * tmp;
  size_t tmpsize;

  srand(time(NULL));

  char *start;
  char *challenge;
  char *full_collection_name;

  if (con->misc_info) {
    info = (mongodb_info *) con->misc_info;
    // printf("info substate: %d \n", info->substate);
  }

  if (serv->module_data && con->misc_info == NULL) {

    hstate = (mongodb_state *)serv->module_data;
    con->misc_info = (mongodb_info *)safe_zalloc(sizeof(mongodb_info));
    info = (mongodb_info *)con->misc_info;
    if (!strcmp(hstate->auth_scheme, "MONGODB_CR") 
       || !strcmp(hstate->auth_scheme, "MONGODB_SCRAM_SHA1")
      ) {
      // printf("setting connection state\n");
      con->state = hstate->state;
    }
    info->auth_scheme = Strndup(hstate->auth_scheme, 
            strlen(hstate->auth_scheme));
  } 
  switch (con->state) {
      case MONGODB_INIT:
      /* This step attempts to perform the list databases command. 
      * This will only work if the database does not have any authentication. 
      */
      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();    

      tmplen = 4 + 4  /* mesage length + request ID*/
         + 4 + 4 + 4  /* response to + opcode + queryflags */
         + strlen(serv->db) + strlen(".$cmd") + 1 /* full collection name + null byte */
         + 4 + 4 /* number to skip, number to return */
         + 4 /* query length */
         + 1 + strlen("listDatabases") + 1 + 4 + 4 /* element list database length */
         + 1 /* null byte */
         ;
      tmp = (char *)safe_malloc(tmplen + 1);    

      full_collection_name = (char *)safe_malloc(strlen(serv->db) + strlen(".$cmd") + 1);

      sprintf(full_collection_name, "%s%s", serv->db, ".$cmd");

      snprintf((char *)tmp, tmplen,
         "%c%c%c%c" /* message length */ 
         "%c%c%c%c" /* request ID, might have to be dynamic */
         "\xff\xff\xff\xff" /* response to */
         "\xd4\x07%c%c" /* OpCode: We use query 2004 */              
         "%c%c%c%c" /* Query Flags */
         "%s"  /* Full Collection Name */
         "%c" /* null byte */
         "%c%c%c%c" /* Number to Skip (0) */
         "\xff\xff\xff\xff" /* Number to return (-1) */
         "\x1c%c%c%c" /* query length, fixed length (28) */
         "\x01" /* query type (Double 0x01) */
         "%s" /* element (listDatabases) */              
         "%c"
         "%c%c%c%c" /* element value (1) */
         "%c%c\xf0\x3f" /* element value (1) cnt. */
         "%c", /* end of packet null byte */
         LONGQUARTET(tmplen),
         0x00,0x00,0x30,0x3a,
         0x00,0x00,
         0x00,0x00,0x00,0x00,
         full_collection_name, 0x00,
         0x00,0x00,0x00,0x00, /* Num to skip */
         0x00,0x00,0x00, /* query length */
         "listDatabases", 0x00,
         0x00,0x00,0x00,0x00,
         0x00,0x00,
         0x00
         );    

      con->outbuf->append(tmp, tmplen);
      free(tmp);
      free(full_collection_name);

      nsock_write(nsp, nsi, ncrack_write_handler, MONGODB_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());

      con->state = MONGODB_RECEIVE;
      break;

    case MONGODB_RECEIVE:
      if (mongodb_loop_read(nsp, con) < 0)
        break;

      if (!(memsearch((const char *)con->inbuf->get_dataptr(),
            "errmsg", con->inbuf->get_len()) 
          || memsearch((const char *)con->inbuf->get_dataptr(),
            "not authorized", con->inbuf->get_len()))) {
        /* In this case, the mongo database does not have authorization.
        * The module terminates with success. 
        */
        serv->end.orly = true;
        tmpsize = sizeof("Access to the database does not require authorization.\n");
        serv->end.reason = (char *)safe_malloc(tmpsize);
        snprintf(serv->end.reason, tmpsize,
            "Access to the database does not require authorization.\n");
        return ncrack_module_end(nsp, con);
      } 

      /* This step will try to find the server's version. According to the MongoDB
      * specification if the server is above version 3.0 it will not authenticate
      * via the MongoDB-CR method. It will accept those requests but the attempt 
      * will always fail. As such we need to extract the version and decide which 
      * method to use. Unless of course, the user forces an authentication method.
      *
      * The server's version is identified by extracting the isMaster object and 
      * checking the value of the maxWireVersion variable. This variable was introduced
      * in Mongo v 2.6. I haven't found yet a clear table listing the values of this 
      * variable. From various documentation articles, I could extract the following
      * information:
      * maxWireVersion=2 -> MongoDB 2.6.4
      * maxWireVersion=3 -> MongoDB 2.6
      * maxWireVersion=4 -> MongoDB 3.2 (?)
      * maxWireVersion=5 -> MongoDB 3.4
      * If we receive a maxWireVersion above 4 we should use SCRAM-SHA1 while
      * if we receive 3 or below, we should use MongoDB-CR.
      */
      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();    

      tmplen = 4 + 4  /* mesage length + request ID*/
         + 4 + 4 + 4  /* response to + opcode + queryflags */
         + strlen(serv->db) + strlen(".$cmd") + 1 /* full collection name + null byte */
         + 4 + 4 /* number to skip, number to return */
         + 4 /* query length */
         + 1 + strlen("isMaster") + 1 + 4 /* element list database length */
         + 1 /* null byte */
         ;

      tmp = (char *)safe_malloc(tmplen + 1);    

      full_collection_name = (char *)safe_malloc(strlen(serv->db) + strlen(".$cmd") + 1);

      sprintf(full_collection_name, "%s%s", serv->db, ".$cmd");

      snprintf((char *)tmp, tmplen,
         "%c%c%c%c" /* message length */ 
         "%c%c%c%c" /* request ID, might have to be dynamic */
         "\xff\xff\xff\xff" /* response to */
         "\xd4\x07%c%c" /* OpCode: We use query 2004 */              
         "%c%c%c%c" /* Query Flags */
         "%s" /* Full Collection Name */
         "%c" /* null byte */
         "%c%c%c%c" /* Number to Skip (0) */
         "\xff\xff\xff\xff" /* Number to return (-1) */
         "%c%c%c%c" /* query length, fixed length (28) */

         "\x10" /* query type (Int32 0x10) */
         "%s" /* element (listDatabases) */              
         "%c" /* null byte */
         "\x01%c%c%c" /* element value (1) */
         
         "%c", /* end of packet null byte */
         LONGQUARTET(tmplen),
         0x00,0x00,0x30,0x3a,
         0x00,0x00,
         0x00,0x00,0x00,0x00,
         full_collection_name,0x00,
         0x00,0x00,0x00,0x00, /* Num to skip */

         LONGQUARTET(4 + 1 + (int) strlen("isMaster") + 1 + 4 + 1),
         "isMaster", 0x00,
         0x00, 0x00, 0x00,

         0x00
         );     

      con->outbuf->append(tmp, tmplen);
      free(tmp);
      free(full_collection_name);

      nsock_write(nsp, nsi, ncrack_write_handler, MONGODB_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());

      con->state = MONGODB_RECEIVE_VER;
      delete con->inbuf;
      con->inbuf = NULL;
      break;

    case MONGODB_RECEIVE_VER:
      if (mongodb_loop_read(nsp, con) < 0)
        break;

      if ((start = memsearch((const char *)con->inbuf->get_dataptr(),
            "maxWireVersion", con->inbuf->get_len()))) {

          start += sizeof("maxWireVersion ") - 1;

          challenge = Strndup(start, 1);

          if (info == NULL) {
            con->misc_info = (mongodb_info *)safe_zalloc(sizeof(mongodb_info));
            info = (mongodb_info *)con->misc_info;
          }

          if ( (unsigned char) challenge[0] == 0x05 ||
              (unsigned char) challenge[0] == 0x04 ){

            info->auth_scheme = Strndup("MONGODB_SCRAM_SHA1", strlen("MONGODB_SCRAM_SHA1"));
            serv->module_data = (mongodb_state *)safe_zalloc(sizeof(mongodb_state));
            hstate = (mongodb_state *)serv->module_data;
            hstate->auth_scheme = Strndup(info->auth_scheme, 
                strlen(info->auth_scheme));            
            hstate->state = MONGODB_SCRAM_SHA1;
            mongodb_scram_sha1(nsp, con);

          } 
          else if ((unsigned char) challenge[0] == 0x03 ||
              (unsigned char) challenge[0] == 0x02 ||
              (unsigned char) challenge[0] == 0x01 )
          {
            info->auth_scheme = Strndup("MONGODB_CR", strlen("MONGODB_CR"));
            serv->module_data = (mongodb_state *)safe_zalloc(sizeof(mongodb_state));
            hstate = (mongodb_state *)serv->module_data;
            hstate->auth_scheme = Strndup(info->auth_scheme, 
                strlen(info->auth_scheme));
            hstate->state = MONGODB_CR;
            mongodb_cr(nsp, con);
          }
        }
      break;

    case MONGODB_CR:

      mongodb_cr(nsp, con);
      break;

    case MONGODB_SCRAM_SHA1:
      mongodb_scram_sha1(nsp, con);
      break;
  }
}

static void
mongodb_cr(nsock_pool nsp, Connection *con)
{
  char *tmp;
  size_t tmplen;  
  size_t querylen;  
  char *start, *end;
  size_t i;
  char *challenge;
  char *nonce;
  char *full_collection_name;

  unsigned char hashbuf[MD5_DIGEST_LENGTH];
  char HA1_hex[MD5_DIGEST_LENGTH * 2 + 1];
  char buf[MD5_DIGEST_LENGTH * 2 + 1];
  MD5_CTX md5;

  Service *serv = con->service;
  nsock_iod nsi = con->niod;
  mongodb_info *info = (mongodb_info *)con->misc_info;

  switch (info->substate) {
    case CR_INIT:
      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf(); 
      con->state = MONGODB_CR;

      full_collection_name = (char *)safe_malloc(strlen(serv->db) + 6 + 1);
      sprintf(full_collection_name, "%s%s", serv->db, ".$cmd");
   
      querylen =  4 /* query length */
         + 1 + strlen("getnonce") + 1 + 4 + 4 /* element getnonce length */
         + 1 /* null byte */
         ;
      tmplen = 4 + 4  /* mesage length + request ID*/
         + 4 + 4 + 4  /* response to + opcode + queryflags */
         + strlen(full_collection_name) + 1 /* full collection name + null byte */
         + 4 + 4 /* number to skip, number to return */
         + querylen
         ;         

      tmp = (char *)safe_malloc(tmplen + 1);


      snprintf((char *)tmp, tmplen,
         "%c%c%c%c" /* message length */ 
         "%c%c%c%c" /* request ID, might have to be dynamic */
         "\xff\xff\xff\xff" /* response to */
         "\xd4\x07%c%c" /* OpCode: We use query 2004 */              
         "%c%c%c%c" /* Query Flags */
         "%s"  /* Full Collection Name */
         "%c" /* nnull byte*/
         "%c%c%c%c" /* Number to Skip (0) */
         "\xff\xff\xff\xff" /* Number to return (-1) */
         "%c%c%c%c" /* query length, fixed 23 */

         "\x01" /* query type (Double 0x01) */
         "%s" /* element (getnonce) */              
         "%c" /* element null byte */
         "%c%c%c%c" /* element value (1) */
         "%c%c\xf0\x3f" /* element value (1) cnt. */

         "%c", /* end of packet null byte */

         LONGQUARTET((int) tmplen),
         0x00,0x00,0x30,0x3a,
         0x00,0x00,
         0x00,0x00,0x00,0x00,
         full_collection_name, 0x00,
         0x00,0x00,0x00,0x00, /* Num to skip */
         LONGQUARTET((int) querylen), 
         "getnonce", 0x00,
         0x00,0x00,0x00,0x00,
         0x00,0x00,        

         0x00
         );     

      con->outbuf->append(tmp, tmplen);
      free(full_collection_name);
      free(tmp);

      delete con->inbuf;
      con->inbuf = NULL;

      nsock_write(nsp, nsi, ncrack_write_handler, MONGODB_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());

      info->substate = CR_NONCE;
      break;

    case CR_NONCE:

      if (mongodb_loop_read(nsp, con) < 0)
          break;

      if ((start = memsearch((const char *)con->inbuf->get_dataptr(),
            "nonce", con->inbuf->get_len()))) {

        start += sizeof("nonce ") - 1;
        end = start;
        i = 0;
        while (i != 4) {
          end++;
          i++;
        }
        unsigned char tmp_buf[4];
        /* There is a nonce element. In CR mode the nonce has a length attribute.
        * Read the length and then read the nonce. The length is 4 bytes after
        * the 'nonce\0' string.
        */
        challenge = Strndup(start, i);
        tmp_buf[0] =  (int) (unsigned char) challenge[0];

        nonce = (char *)safe_malloc(((int) tmp_buf[0] + 1));
        for(i=0; i<tmp_buf[0];i++){
          nonce[i] = *end++;
        }

        if (con->outbuf)
          delete con->outbuf;
        con->outbuf = new Buf(); 


        /* Calculate MD5(Username:mongo:Password) */
        MD5_Init(&md5);
        MD5_Update(&md5, con->user, strlen(con->user));
        MD5_Update(&md5, ":mongo:", strlen(":mongo:"));
        MD5_Update(&md5, con->pass, strlen(con->pass));
        MD5_Final(hashbuf, &md5);
        enhex(HA1_hex, hashbuf, sizeof(hashbuf));

        /* Calculate MD5(nonce + username + digest). */
        MD5_Init(&md5);
        MD5_Update(&md5, nonce, strlen(nonce));
        MD5_Update(&md5, con->user, strlen(con->user));
        MD5_Update(&md5, HA1_hex, strlen(HA1_hex));
        MD5_Final(hashbuf, &md5);
        enhex(buf, hashbuf, sizeof(hashbuf));

        /* Now craft the response with the 4 elements:
        * authenticate, user, nonce, and key
        */
        char *full_collection_name;
        full_collection_name = (char *)safe_malloc(strlen(serv->db) + 6 + 1);
        sprintf(full_collection_name, "%s%s", serv->db, ".$cmd");

        querylen = 4 /* query length */
         + 1 + strlen("authenticate") + 1 + 4 + 4 /* element authenticate length */
         + 1 + strlen("nonce") + 1 + 4 + strlen(nonce) + 1 /* element nonce length */
         + 1 + strlen("key") + 1 + 4 + MD5_DIGEST_LENGTH * 2 + 1  /* element key length */
         + 1 + strlen("user") + 1 + 4 + strlen(con->user) + 1  /* element user length */
         + 1 /* null byte */
        ;

        tmplen = 4 + 4  /* mesage length + request ID*/
         + 4 + 4 + 4  /* response to + opcode + queryflags */
         + strlen(full_collection_name) + 1 /* full collection name + null byte */
         + 4 + 4 /* number to skip, number to return */
         + querylen
         ;

        tmp = (char *)safe_malloc(tmplen + 1);

        snprintf((char *)tmp, tmplen,
           "%c%c%c%c" /* message length */ 
           "%c%c%c%c" /* request ID, might have to be dynamic */
           "\xff\xff\xff\xff" /* response to */
           "\xd4\x07%c%c" /* OpCode: We use query 2004 */              
           "%c%c%c%c" /* Query Flags */
           "%s"  /* Full Collection Name */
           "%c" 
           "%c%c%c%c" /* Number to Skip (0) */
           "\xff\xff\xff\xff" /* Number to return (-1) */
           "%c%c%c%c" /* query length, dynamic */

           "\x01" /* query type (Double 0x01) */
           "%s" /* element (authenticate) */              
           "%c" /* element null byte */
           "%c%c%c%c" /* element value (1) */
           "%c%c\xf0\x3f" /* element value (1) cnt. */

           "\x02" /* query type (String 0x02) */
           "%s" /* element (nonce) */              
           "%c" /* element null byte */
           "%c%c%c%c" /* element value length (dynamic) */
           "%s" /* element value (nonce value) */
           "%c" /* element value null byte */

           "\x02" /* query type (String 0x02) */
           "%s" /* element (key) */              
           "%c" /* element null byte */
           "%c%c%c%c" /* element value length (md5hash length) */
           "%s" /* element value (nonce value) */
           "%c" /* element value null byte */

           "\x02" /* query type (String 0x02) */
           "%s" /* element (user) */              
           "%c" /* element null byte */
           "%c%c%c%c" /* element value length (username length) */
           "%s" /* element value (nonce value) */
           "%c" /* element value null byte */

           "%c", /* end of packet null byte */

           LONGQUARTET((int) tmplen),
           0x00,0x00,0x30,0x3a,
           0x00,0x00,
           0x00,0x00,0x00,0x00,
           full_collection_name, 0x00,
           0x00,0x00,0x00,0x00, /* Num to skip */
           LONGQUARTET((int) querylen),

           "authenticate", 0x00,
           0x00,0x00,0x00,0x00,
           0x00,0x00,   

           "nonce", 0x00,
           LONGQUARTET(((int) strlen(nonce) + 1)),
           nonce, 0x00,

           "key", 0x00,
           LONGQUARTET(((int) MD5_DIGEST_LENGTH * 2 + 1)),
           buf, 0x00,

           "user", 0x00,
           LONGQUARTET(((int) strlen(con->user) + 1)),
           con->user, 0x00,

           0x00
           );     
     
        con->outbuf->append(tmp, tmplen);
        free(full_collection_name);
        free(tmp);

        delete con->inbuf;
        con->inbuf = NULL;

        nsock_write(nsp, nsi, ncrack_write_handler, MONGODB_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());

        info->substate = CR_FINI;
        }
        break;  

    case CR_FINI:
      if (mongodb_loop_read(nsp, con) < 0)
        break;

      info->substate = CR_INIT;
    
      /* We only know the err mesage xD. FIXME*/
      if (!memsearch((const char *)con->inbuf->get_dataptr(),
            "errmsg", con->inbuf->get_len())) {
        con->auth_success = true;
      }

      delete con->inbuf;
      con->inbuf = NULL;

      ncrack_module_end(nsp, con);
      break;
  }
}

static void
mongodb_scram_sha1(nsock_pool nsp, Connection *con)
{
  char *tmp;
  size_t tmplen;  
  size_t querylen;  
  char * payload;
  char *start, *end;
  size_t i;
  char *challenge;
  unsigned char tmp_buf[4];
  unsigned char conversationId[4];
  size_t tmpsize;
  char *full_collection_name;
    
  unsigned char hashbuf[MD5_DIGEST_LENGTH];
  unsigned char hashbuf2[SHA_DIGEST_LENGTH];
  char HA1_hex[MD5_DIGEST_LENGTH * 2 + 1];
  MD5_CTX md5;
  SHA_CTX sha1;

  Service *serv = con->service;
  nsock_iod nsi = con->niod;

  mongodb_info *info = (mongodb_info *)con->misc_info;
  switch (info->substate) {
    case SCRAM_INIT:
      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf(); 
      con->state = MONGODB_SCRAM_SHA1;

      /* Generate client nonce.
      * We are using a 12 random character string.
      */
      info->client_nonce = (char *)safe_malloc(12 + 1);
      rand_str(info->client_nonce, 12);
      full_collection_name = (char *)safe_malloc(strlen(serv->db) + 6 + 1);
      sprintf(full_collection_name, "%s%s", serv->db, ".$cmd");

      /* Allocate 12 bytes for the client nonce, the length of the username
      * and 8 bytes for the following sequence "n,,n=,r="
      */
      payload = (char *)safe_malloc(strlen(info->client_nonce) + strlen(con->user) + 8 + 1);
      snprintf(payload, strlen(info->client_nonce) + 1 + strlen(con->user) + 8, 
        "n,,n=%s,r=%s", con->user, info->client_nonce);

      querylen = 4 /* query length */
         + 1 + strlen("saslStart") + 1 + 4  /* element saslStart length */
         + 1 + strlen("mechanism") + 1 + 4 + strlen("SCRAM-SHA-1") + 1 /* element SCRAM-SHA-1 length */
         + 1 + strlen("payload") + 1 + 4 + 1 + strlen(payload) + 1 /* element payload length */
         + 1 + strlen("autoAuthorize") + 1 + 4  /* element autoAuthorize length */
         + 1 /* null byte */
         ;
      tmplen = 0;
      tmplen = 4 + 4  /* mesage length + request ID*/
         + 4 + 4 + 4  /* response to + opcode + queryflags */
         + strlen(full_collection_name) + 1 /* full collection name + null byte */
         + 4 + 4 /* number to skip, number to return */
         + querylen
         ;

      tmp = (char *)safe_malloc(tmplen + 1);
      snprintf((char *)tmp, tmplen,
         "%c%c%c%c" /* message length */ 
         "%c%c%c%c" /* request ID, might have to be dynamic */
         "%c%c%c%c" /* response to*/
         "\xd4\x07%c%c" /* OpCode: We use query 2004 */              
         "%c%c%c%c" /* Query Flags */
         "%s" /* Full Collection Name */
         "%c" /* null byte */ 
         "%c%c%c%c" /* Number to Skip (0) */
         "\xff\xff\xff\xff" /* Number to return (-1) */
         "%c%c%c%c" /* query length, dynamic */

         "\x10" /* query type (Int32 0x10) */
         "%s" /* element (saslStart) */              
         "%c" /* element null byte */
         "\x01%c%c%c" /* element value (1) */

         "\x02" /* query type (String 0x02) */
         "%s" /* element (mechanism) */              
         "%c" /* element null byte */
         "\x0c%c%c%c" /* element value length (12) */
         "%s" /* element value (SCRAM-SHA-1) */
         "%c" /* element value null byte */

         "\x05" /* query type (Binary 0x05) */
         "%s" /* element (payload) */              
         "%c" /* element null byte */
         "%c%c%c%c" /* element value length (dynamic) */
         "%c" /* null byte */
         "%s" /* element value */
         "%c" /* null byte */
         "\x10" /* query type (Int32 0x10) */
         "%s" /* element (autoAuthorize) */              
         "%c" /* element null byte */
         "\x01%c%c%c" /* element value (1) */

         "%c", /* end of packet null byte */

         LONGQUARTET((int) tmplen),
         0x00,0x00,0x30,0x3a,
         0x00,0x00,0x00,0x00,
         0x00,0x00,
         0x00,0x00,0x00,0x00,
         full_collection_name, 0x00,
         0x00,0x00,0x00,0x00, /* Num to skip */
         LONGQUARTET((int) querylen), /* query length fix me   */
         "saslStart", 0x00,
         0x00,0x00,0x00,
         "mechanism", 0x00,
         0x00,0x00,0x00,
         "SCRAM-SHA-1", 0x00,

         "payload",0x00,
         LONGQUARTET(((int) strlen(payload) + 1)), 0x00,
         payload, 0x00,

         "autoAuthorize", 0x00,
         0x00,0x00,0x00,

         0x00
         );     

      con->outbuf->append(tmp, tmplen);
      free(full_collection_name);
      free(tmp);

      delete con->inbuf;
      con->inbuf = NULL;

      nsock_write(nsp, nsi, ncrack_write_handler, MONGODB_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());

      info->substate = SCRAM_NONCE;
      
      break;  
      
    case SCRAM_NONCE:
      if (mongodb_loop_read(nsp, con) < 0)
        break;
      if ((start = memsearch((const char *)con->inbuf->get_dataptr(),
          "conversationId", con->inbuf->get_len()))) {
        start += sizeof("conversationId ") - 1;
        end = start;
        i = 0;
        while (i != 4) {
          end++;
          i++;
        }
        /* There is a payload element. In SCRAM_SHA1 mode the payload has a length attribute.
        * Read the length and then read the payload. The length is 4 bytes after
        * the 'payload\0' string. After the length of the payload, there is a null byte. 
        */
        challenge = Strndup(start, i);
        conversationId[0] =  (int) (unsigned char) challenge[0];
      } else {
        /* Abort */
        // serv->end.orly = true;
        // tmpsize = sizeof("Response does not contain conversationId.\n");
        // serv->end.reason = (char *)safe_malloc(tmpsize);
        // snprintf(serv->end.reason, tmpsize,
        //     "Response does not contain conversationId.\n");
        //
        info->substate = SCRAM_INIT;
        if (o.debugging > 5)
          log_write(LOG_STDOUT, "%s skipping username: %s\n", serv->HostInfo(), con->user);
        serv->skip_username = true;
        return ncrack_module_end(nsp, con);
      }

      /* We search for the string 'payload' in the server's response.
      * We extract that value and proceed with step 3.
      */
      if ((start = memsearch((const char *)con->inbuf->get_dataptr(),
          "payload", con->inbuf->get_len()))) {

        start += sizeof("payload ") - 1;
        end = start;
        i = 0;
        while (i != 4) {
          end++;
          i++;
        }
        info->substate = SCRAM_FINI;

        /* There is a payload element. In SCRAM_SHA1 mode the payload has a length attribute.
        * Read the length and then read the payload. The length is 4 bytes after
        * the 'payload\0' string. After the length of the payload, there is a null byte. 
        */
        char * tmp_buffer;
        challenge = Strndup(start, i);
        tmp_buf[0] =  (int) (unsigned char) challenge[0];
        /* skip one null byte after the payload length. */
        end++;
        tmp = (char *)safe_malloc((int) tmp_buf[0]);
        tmp_buffer = (char *)safe_malloc((int) tmp_buf[0]);


        for(i=0; i<tmp_buf[0];i++){
          tmp[i] = *end++;
        }
        tmp[tmp_buf[0]] = '\0';
        snprintf(tmp_buffer, tmp_buf[0] + 1, "%s", tmp);

        /* The payload element contains the i, s and r values. */
        /* Search for value i (i=) for iterations, s (s=) for salt, 
        * and r (r=) for server nonce. The delimiter is comma (,).
        */
        /* The 'r' variable should begin with the nonce we sent above.
        * ClientNone + ServerNonce. If not we should abort.
        */
        char * pch;
        char * rnonce;
        char * salt;
        char * decoded_salt;
        char * iterations;
        salt = NULL;
        iterations = NULL;
        rnonce = NULL;

        pch = strtok (tmp,",");
        while (pch != NULL)
        {
          if (memsearch(pch,
              "r=", strlen(pch))) {
            rnonce = pch;
            } 
          else if (memsearch(pch,
              "i=", strlen(pch))) {
            iterations = pch;
            } 
          else if (memsearch(pch,
              "s=", strlen(pch))) {
            salt = pch;
            } 
            pch = strtok (NULL, ",");
        }
        if (salt == NULL || iterations == NULL || rnonce == NULL){
          /* Abort */
            serv->end.orly = true;
            tmpsize = sizeof("Invalid server response.\n");
            serv->end.reason = (char *)safe_malloc(tmpsize);
            snprintf(serv->end.reason, tmpsize,
                "Invalid server response.\n");
            return ncrack_module_end(nsp, con);
        }

        salt += 2; 
        iterations += 2;
        rnonce += 2;

        if(strncmp(info->client_nonce, rnonce, strlen(info->client_nonce))){
            /* Abort */
            /* TODO: FIX THIS, it works but no message 
            */
            serv->end.orly = true;
            tmpsize = sizeof("Server nonce does not contain client nonce.\n");
            serv->end.reason = (char *)safe_malloc(tmpsize);
            snprintf(serv->end.reason, tmpsize,
                "Server nonce does not contain client nonce.\n");
            return ncrack_module_end(nsp, con);
        }

        /* Calculate MD5(Username:mongo:Password) 
        */
        MD5_Init(&md5);
        MD5_Update(&md5, con->user, strlen(con->user));
        MD5_Update(&md5, ":mongo:", strlen(":mongo:"));
        MD5_Update(&md5, con->pass, strlen(con->pass));
        MD5_Final(hashbuf, &md5);
        enhex(HA1_hex, hashbuf, sizeof(hashbuf));

        /* PBKDF2 with data the MD5 hash of username:mongo:password, salt the
        * base64 decoded salt and iterations equal to the variable 'iterations'. 
        * The variable 'out' contains the salted password.
        */
        unsigned char * out;

        out = (unsigned char *)safe_malloc(20 + 1);
        decoded_salt = (char *)safe_malloc((strlen(salt) + 1));
        base64_decode(salt, strlen(salt), decoded_salt);

        PKCS5_PBKDF2_HMAC_SHA1(HA1_hex, strlen(HA1_hex),
          (unsigned char*) decoded_salt, strlen(decoded_salt), atoi(iterations),
          20, out);

        /* Next step is to perform an HMAC to the salted password (out).
        * Using HMAC-SHA1 with 'Client Key' as a key.
        */
        unsigned char client_key[20];
        char tmp_key[] = "Client Key";
        HMAC(EVP_sha1(), out, 20, (unsigned const char*) tmp_key, 
            10, client_key, NULL);

        /* SHA1 on the client_key variable.
        */
        SHA1_Init(&sha1);
        SHA1_Update(&sha1, client_key, 20);
        SHA1_Final(hashbuf2, &sha1);

        char * without_proof;
        without_proof = (char *)safe_malloc(strlen("c=biws,r=") + strlen(rnonce) + 1);
        snprintf(without_proof, strlen("c=biws,r=") + strlen(rnonce) + 1, 
          "c=biws,r=%s", rnonce);     

        char * auth_msg;
        size_t auth_msg_len;
    
        /* Auth_msg length is: 
        * 12 for the nonce 
        * 7 for the characters 'n=,r=,,'
        */      
        auth_msg_len = strlen(con->user) + 12 + strlen(tmp_buffer) + strlen(without_proof) + 7 + 1;

        auth_msg = (char *)safe_malloc(auth_msg_len + 1);
        snprintf(auth_msg, auth_msg_len, 
          "n=%s,r=%s,%s,%s", con->user, info->client_nonce, tmp_buffer, without_proof);
        free(tmp_buffer);
        unsigned char client_sig[20]; 
        /* We use auth_msg_len to avoid including the trailing null byte. 
        */   
        HMAC(EVP_sha1(), hashbuf2, sizeof(hashbuf2), (unsigned const char*) auth_msg, 
            auth_msg_len - 1, client_sig, NULL);
        /* Create the client proof by b64 encoding the XORed client_key and client_sig.
        * The length of the client_proof is set to SHA_DIGEST_LENGTH.
        */
        char client_proof[SHA_DIGEST_LENGTH];
        xor_hashes(client_proof, client_key, client_sig, SHA_DIGEST_LENGTH);
        char * tmp_b64;
        char * client_final;
        tmp_b64 = (char *)safe_malloc(BASE64_LENGTH(SHA_DIGEST_LENGTH) + 1);
        base64_encode(client_proof, SHA_DIGEST_LENGTH, tmp_b64);

        /* client_final length breakdown: 
        * 3 for string ',p=', 
        * length of tmp_b64
        * length of without_proof.
        */
        client_final = (char *)safe_malloc(3 + strlen(tmp_b64) + strlen(without_proof));
        snprintf(client_final, 3 + strlen(tmp_b64) + 1 + strlen(without_proof), 
          "%s,p=%s", without_proof, tmp_b64);
      
        if (con->outbuf)
          delete con->outbuf;
        con->outbuf = new Buf(); 

        full_collection_name = (char *)safe_malloc(strlen(serv->db) + 6 + 1);
        sprintf(full_collection_name, "%s%s", serv->db, ".$cmd");

        /* Craft the packet. */
        querylen = 4 /* query length */
         + 1 + strlen("saslContinue") + 1 + 4  /* element saslContinue length */
         + 1 + strlen("conversationId") + 1 + 4 /* element conversationId length */
         + 1 + strlen("payload") + 1 + 4 + 1 + strlen(client_final) /* element payload length */
         + 1 /* null byte */
         ;
      
        tmplen = 4 + 4  /* mesage length + request ID*/
           + 4 + 4 + 4  /* response to + opcode + queryflags */
           + strlen(full_collection_name) + 1 /* full collection name + null byte */
           + 4 + 4 /* number to skip, number to return */
           + querylen
           ;
        free(tmp);
        tmp = (char *)safe_malloc(tmplen + 1);

        snprintf((char *)tmp, tmplen,
           "%c%c%c%c" /* message length */ 
           "%c%c%c%c" /* request ID, might have to be dynamic */
           "%c%c%c%c" /* response to */
           "\xd4\x07%c%c" /* OpCode: We use query 2004 */              
           "%c%c%c%c" /* Query Flags */
           "%s" /* Full Collection Name */
           "%c" /* null byte */ 
           "%c%c%c%c" /* Number to Skip (0) */
           "\xff\xff\xff\xff" /* Number to return (-1) */
           "%c%c%c%c" /* query length, dynamic */

           "\x10" /* query type (Int32 0x10) */
           "%s" /* element (saslContinue) */              
           "%c" /* element null byte */
           "\x01%c%c%c" /* element value (1) */

           "\x10" /* query type (Int32 0x10) */
           "%s" /* element (conversationId) */              
           "%c" /* element null byte */
           "%c%c%c%c" /* element value */

           "\x05" /* query type (Binary 0x05) */
           "%s" /* element (payload) */              
           "%c" /* element null byte */
           "%c%c%c%c" /* element value length (dynamic) */
           "%c" /* null byte */
           "%s" /* element value */

           "%c", /* end of packet null byte */

           LONGQUARTET((int) tmplen),
           0x00,0x00,0x30,0x3b,
           0x00,0x00,0x00,0x00, /*testing 00 instead of ff*/
           0x00,0x00,
           0x00,0x00,0x00,0x00,
           full_collection_name, 0x00,
           0x00,0x00,0x00,0x00, /* Num to skip */
           LONGQUARTET((int) querylen), /* query length fix me   */
           "saslContinue", 0x00,
           0x00,0x00,0x00,

           "conversationId", 0x00,
           LONGQUARTET((int) conversationId[0]),

           "payload",0x00,
           LONGQUARTET(((int)strlen(client_final) )), 0x00,
           client_final,

           0x00
           );     

        con->outbuf->append(tmp, tmplen);
        delete con->inbuf;
        con->inbuf = NULL;

        free(tmp);
        free(full_collection_name);

        nsock_write(nsp, nsi, ncrack_write_handler, MONGODB_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());

      }

      break;
      
    case SCRAM_FINI:
      if (mongodb_loop_read(nsp, con) < 0)
        break;
      info->substate = SCRAM_INIT;

      if (memsearch((const char *)con->inbuf->get_dataptr(),
            "payload", con->inbuf->get_len())) {
        con->auth_success = true;
      }

      delete con->inbuf;
      con->inbuf = NULL;

      ncrack_module_end(nsp, con);
      break;     
  }
}

static void
mongodb_free(Connection *con)
{
  mongodb_info *p = NULL;
  if (con->misc_info == NULL)
    return;
  p = (mongodb_info *)con->misc_info;
  free(p->auth_scheme);
}

static void
xor_hashes(char *to, const u_char *s1, const u_char *s2, u_int len)
{
  const uint8_t *s1_end= s1 + len;
  while (s1 < s1_end)
    *to++= *s1++ ^ *s2++;
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

static char *enhex(char *dest, const unsigned char *src, size_t n)
{
    unsigned int i;
    for (i = 0; i < n; i++)
        Snprintf(dest + i * 2, 3, "%02x", src[i]);
    return dest;
}
