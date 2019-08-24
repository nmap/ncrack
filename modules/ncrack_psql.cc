/***************************************************************************
 * ncrack_psql.cc -- ncrack module for the PSQL protocol                   *
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

#define PSQL_TIMEOUT 20000
#define PSQL_DIGITS 1
#define PSQL_PACKET_LENGTH 4
#define PSQL_AUTH_TYPE 4
#define PSQL_SALT 4

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);
static int psql_loop_read(nsock_pool nsp, Connection *con, char *psql_code_ret, char *psql_salt_ret);

unsigned char charToHexDigit(char c);
enum states { PSQL_INIT, PSQL_AUTH, PSQL_FINI };



/* n is the size of src. dest must have at least n * 2 + 1 allocated bytes.
*/
static char *enhex(char *dest, const unsigned char *src, size_t n)
{
    unsigned int i;

    for (i = 0; i < n; i++)
        Snprintf(dest + i * 2, 3, "%02x", src[i]);

    return dest;
}


/* Arguments are assumed to be non-NULL, with the exception of nc and
   cnonce, which may be garbage only if qop == QOP_NONE. */
static void make_response(char buf[MD5_DIGEST_LENGTH * 2 + 3],
    const char *username, const char *password, const char *salt)
{
    char HA1_hex[MD5_DIGEST_LENGTH * 2 + 1];
    unsigned char hashbuf[MD5_DIGEST_LENGTH];
    char finalhash[MD5_DIGEST_LENGTH * 2 + 3 + 1];
    MD5_CTX md5;

    /* Calculate MD5(Password + Username) */
    MD5_Init(&md5);
    MD5_Update(&md5, password, strlen(password));
    MD5_Update(&md5, username, strlen(username));
    MD5_Final(hashbuf, &md5);
    enhex(HA1_hex, hashbuf, sizeof(hashbuf));

    /* Calculate response MD5(above + Salt). */
    MD5_Init(&md5);
    MD5_Update(&md5, HA1_hex, strlen(HA1_hex));
    MD5_Update(&md5, salt, strlen(salt));
    MD5_Final(hashbuf, &md5);
    enhex(buf, hashbuf, sizeof(hashbuf));

    /* Add the string md5 at the beggining. */
    memcpy(finalhash,"md5", sizeof("md5"));
    strncat(finalhash, buf, sizeof(finalhash) - 1);
    buf[0] = '\0';
    memcpy(buf, finalhash, MD5_DIGEST_LENGTH * 2 + 3);
    buf[MD5_DIGEST_LENGTH * 2 + 3] = '\0';
}

static int
psql_loop_read(nsock_pool nsp, Connection *con, char *psql_code_ret, char
*psql_salt_ret)
{
  int i = 0;
  char psql_code[PSQL_DIGITS + 1]; /* 1 char + '\0' */
  char psql_salt[PSQL_SALT + 1]; /* 4 + '\0' */
  char dig[PSQL_PACKET_LENGTH + 1]; /* temporary digit string */
  char *p;
  size_t packet_length;
  int authentication_type;

  if (con->inbuf == NULL || con->inbuf->get_len() < PSQL_DIGITS + 1) {
    nsock_read(nsp, con->niod, ncrack_read_handler, PSQL_TIMEOUT, con);
    return -1;
  }

  /* Get the first character */
  p = (char *)con->inbuf->get_dataptr();
  dig[1] = '\0';
  for (i = 0; i < PSQL_DIGITS; i++) {
    psql_code[i] = *p++;
  }
  psql_code[1] = '\0';
  memcpy(psql_code_ret, psql_code, PSQL_DIGITS);

  if (!strncmp(psql_code_ret, "R", PSQL_DIGITS)) {
    /* Read packet length only if it is of type R */

    /* Currently we care only for the last byte.
       The packet length will always be small enough
       to fit in one byte */
    for (i = 0; i < PSQL_PACKET_LENGTH; i++) {
     snprintf(dig, 3, "\n%x", *p++);
     packet_length = (int)strtol(dig, NULL, 16);
    }
    if (con->inbuf->get_len() < packet_length + 1) {
      nsock_read(nsp, con->niod, ncrack_read_handler, PSQL_TIMEOUT, con);
      return -1;
    }

    /* At this point we will need to know the authentication type.
      Possible values are 5 and 0. 5 stands for MD5 and 0 stands for
      successful authentication. If it is 5 we are at the second stage of
      the process PSQL_AUTH while if it is 0 we are at the third stage PSQL_FINI.
      This value consists of 4 bytes but only the fourth will have a value
      e.g. 00 00 00 05 for MD5 or 00 00 00 00 for successful authentication.
     */
    for (i = 0; i < PSQL_AUTH_TYPE; i++) {
      snprintf(dig, 3, "\n%x", *p++);
      authentication_type = (int)strtol(dig, NULL, 16);
    }


    /* If authentication type is 'MD5 password' (carries Salt) read salt */
    if (authentication_type == 5) {

      for (i = 0; i < 4; i++){
        psql_salt[i] = *p++;
      }
      psql_salt[4] = '\0';
      memcpy(psql_salt_ret, psql_salt, PSQL_SALT);

      return 0;

    }
    else if (authentication_type == 0)
      /* Successful authentication */
      return 1;

  } else if (!strncmp(psql_code_ret, "E", PSQL_DIGITS)) {

    /* Error packet. The login attempt has failed.
      Perhaps we could do some more validation on the packet.
      Currently any kind of packet with E as the first byte will
      be interpreted as a Error package. It is only a matter
      of concerns if the service is not a Postgres service.  */

    return 0;

  }

    /* Malformed packet. Exit safely. */
    return -2;
}

void
ncrack_psql(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;

  char packet_length;
  char psql_code[PSQL_DIGITS + 1];
  char psql_salt[PSQL_SALT + 1];
  memset(psql_code, 0, sizeof(psql_code));
  memset(psql_salt, 0, sizeof(psql_salt));

  char response_hex[MD5_DIGEST_LENGTH *2 + 3];
  switch (con->state)
  {
    case PSQL_INIT:

      con->state = PSQL_AUTH;
      delete con->inbuf;
      con->inbuf = NULL;

      if (con->outbuf)
        delete con->outbuf;

      con->outbuf = new Buf();
      packet_length = strlen(con->user) + 7 +
          strlen("\x03user  database postgres application_name psql client_encoding UTF8  ");

      con->outbuf->snprintf(packet_length, 
          "%c%c%c%c%c\x03%c%cuser%c%s%cdatabase%cpostgres%capplication_name%cpsql%cclient_encoding%cUTF8%c%c",
          0,0,0,packet_length,0,0,0,0,con->user,0,0,0,0,0,0,0,0);
      nsock_write(nsp, nsi, ncrack_write_handler, PSQL_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());

      break;

    case PSQL_AUTH:

      if (psql_loop_read(nsp, con, psql_code, psql_salt) < 0)
        break;

      if (!strncmp(psql_code, "E", PSQL_DIGITS))
        return ncrack_module_end(nsp, con);

      make_response(response_hex, con->user , con->pass, psql_salt);

      response_hex[MD5_DIGEST_LENGTH * 2 + 3] = '\0';

      con->state = PSQL_FINI;
      delete con->inbuf;
      con->inbuf = NULL;


      if (con->outbuf)
        delete con->outbuf;

      con->outbuf = new Buf();
      packet_length = strlen(response_hex) + 5 + strlen("p");

      /* This packet will not count the last null byte in packet length
        byte, that is why we remove one from snprintf. */
      con->outbuf->snprintf(packet_length, 
          "p%c%c%c%c%s%c",0,0,0,packet_length - 1,response_hex,0);

      nsock_write(nsp, nsi, ncrack_write_handler, PSQL_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case PSQL_FINI:

      if (psql_loop_read(nsp, con, psql_code, psql_salt) < 0)
        break;
      else if (psql_loop_read(nsp, con , psql_code, psql_salt) == 1)
        con->auth_success = true;

      con->state = PSQL_INIT;

      delete con->inbuf;
      con->inbuf = NULL;

      return ncrack_module_end(nsp, con);
  }
}
