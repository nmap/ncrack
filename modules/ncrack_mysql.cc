/***************************************************************************
 * ncrack_mysql.cc -- ncrack module for the MySQL protocol                 *
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
#include <openssl/sha.h>

#define MYSQL_TIMEOUT 20000
#define MYSQL_DIGITS 4
#define MYSQL_VERSION 3
#define MYSQL_SALT 20
#define SHA1_HASH_SIZE 20 

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);
static int mysql_loop_read(nsock_pool nsp, Connection *con, char *mysql_auth_method,
    char *mysql_salt_ret);

enum states { MYSQL_INIT, MYSQL_FINI, MYSQL_OTHER_AUTH };


static int
mysql_loop_read(nsock_pool nsp, Connection *con, char *mysql_auth_method, char *mysql_salt_ret)
{
  int i = 0;
  char mysql_salt[MYSQL_SALT + 1];
  char dig[5]; /* temporary digit string */
  char *p;
  size_t packet_length;
  int packet_number;
  char server_authentication_method[21 + 1];

  if (con->inbuf == NULL || con->inbuf->get_len() < MYSQL_DIGITS + 1) {
    nsock_read(nsp, con->niod, ncrack_read_handler, MYSQL_TIMEOUT, con);
    return -1;
  }
  /* Get the first character */
  p = (char *)con->inbuf->get_dataptr();
  dig[1] = '\0';
  for (i = 0; i < MYSQL_DIGITS - 3; i++) {
    snprintf(dig, 4, "\n%x", *p++);
    packet_length = (int)strtol(dig, NULL, 16);
  }

  if (con->inbuf->get_len() < packet_length + 4) {
    nsock_read(nsp, con->niod, ncrack_read_handler, MYSQL_TIMEOUT, con);
    return -1;
  }


  /* Procceed only if the first byte is the packet length. */
  if (packet_length > 0) {

    for (i = 0; i < MYSQL_DIGITS - 2; i++) {
      p++;
    }

    /* The fourth byte is the packet number which starts from 0.
      The packet with packet number 0 contains the SALT. */

    snprintf(dig, 4, "\n%x", *p++);
    packet_number = (int)strtol(dig, NULL, 16);

    if (packet_number == 0 && *p == '\xff') {
      if(o.debugging > 6)
        error("Anti-bruteforcing mechanism is triggered. Incoming connections are now blocked.");
      return -2;
    } else if (packet_number == 0) {
      /* We need to go through the whole packet to find the SALT. */
      /* The next byte is the protocol verion*/
      p++;
      /* The following series of bytes are a zero terminated server 
        version string. Perhaps we can figure out the version here. */
      while (*(p++) != '\00') {

      }
      /* The next four bytes are the internal MySQL ID of the thread
         handling the connection. */
      for (i = 0; i < 4; i++) {
        p++;
      }
      /* This part could be either the full SALT or just a part of it.
      In version 4.0 and earlier this part contains the full SALT while
      in 4.1 and later only the first 8 bytes can be found. We will start
      by reading the first 8 bytes and if the 9th byte is a zero byte \x00
      we will be facing a 4.1 or newer version of MySQL. In the other case we
      will read the full SALT and then we will exit. */
      mysql_salt[0] = *p++;
      for (i = 1; i < 8 + 1; i++) {
       mysql_salt[i] = *p++;
      }
      if (mysql_salt[8] == '\00') {
        /* The version of the sevice is 4.1 or later.
         We need to find the other half of the SALT.*/

        /* The next 18 bytes are the server capabilities (2),
         Default character set code (1), Sever status bit mask (2)
         and the rest (13) are zeroed out for future use. */
         
        for (i = 0; i < 18; i++)
          p++;

        /* Finally the next 13 bytes are the rest of the SALT terminated
        with a zero byte. */
        for (i = 0; i < 13; i++) {
          mysql_salt[i + 8] = *p++;
        }
        mysql_salt[20] = '\0'; 
        memcpy(mysql_salt_ret, mysql_salt, strlen(mysql_salt));

        /* The next bytes denotes the default authentication method of the server. 
          The string ends with a null byte. */
        /* Possible values: mysql_native_password, mysql_old_password, sha256_password*/
        for (i = 0; i < 21; i++) {
          if (*(p) != '\00') {
            server_authentication_method[i] = *p;
            p++;
          }
        }
        server_authentication_method[i] = '\0';
        server_authentication_method[strlen(server_authentication_method) + 1] = '\0';
        //printf("Server default authentication: %s\n", server_authentication_method);
        memcpy(mysql_auth_method, server_authentication_method, strlen(server_authentication_method));
        return 0;
      } else {
        /* Currently we don't support versions earlier than 4.1 */
        return -2;
      }
    } 
    else if ((packet_number == 2 || packet_number == 4)&& *p == '\xff')
      /* This is an error packet. Most probably wrong authentication. 
       We will consider it as a failed attempt. If we triggered anti-bruteforcing
       measures we will find out in the next packet. We are checking for that in
       the first 'if' statement. */
      return 0;
      
    else if ((packet_number == 2 || packet_number == 4)&& *p == '\x00')
      /* Successful authentication packet. */
      return 1;

    else if (packet_number == 2) {
      /* In this case the specific the user uses another authentication method than the default authentication
        of the server. */
      p++;
      for (i = 0; i < 21 ; i++) {
        server_authentication_method[i] = *p++;
      }
      server_authentication_method[i] = '\0';
      server_authentication_method[strlen(server_authentication_method) + 1] = '\0';
      memcpy(mysql_auth_method, server_authentication_method, strlen(server_authentication_method));

        /* The next 20 bytes are the SALT. */ 
        for(i = 0; i < MYSQL_SALT; i++) {
          mysql_salt[i] = *p++;
        }

        mysql_salt[20] = '\0'; 
        memcpy(mysql_salt_ret, mysql_salt, strlen(mysql_salt));
        return 2;
    }
      
  }
  /* Malformed packet. Exit safely. */ 
  return -2;  
}


static void
xor_hashes(char *to, const u_char *s1, const u_char *s2, u_int len)
{
  const uint8_t *s1_end= s1 + len;
  while (s1 < s1_end)
    *to++= *s1++ ^ *s2++;
}

static void hash_password(char *buf, const char *password, const char *salt)
{
  SHA_CTX sha1_ctx;

  uint8_t first_hash[SHA1_HASH_SIZE];
  uint8_t second_hash[SHA1_HASH_SIZE];


  /* First step is SHA1(pass). */
  SHA1_Init(&sha1_ctx);
  SHA1_Update(&sha1_ctx, (const uint8_t *) password, strlen(password));
  SHA1_Final(first_hash, &sha1_ctx);

  /* Second step is SHA1(first_hash). */
  SHA1_Init(&sha1_ctx);
  SHA1_Update(&sha1_ctx, first_hash, SHA1_HASH_SIZE);
  SHA1_Final(second_hash, &sha1_ctx);

  /* Third step is SHA1(SALT+second_hash). */
  SHA1_Init(&sha1_ctx);
  SHA1_Update(&sha1_ctx, (const uint8_t *) salt, SHA1_HASH_SIZE);
  SHA1_Update(&sha1_ctx, second_hash, SHA1_HASH_SIZE);
  SHA1_Final((uint8_t *) buf, &sha1_ctx);

  /* Fourth step is first_hash XOR third_hash. */
  xor_hashes(buf, (const u_char *) buf, (const u_char *) first_hash, SHA1_HASH_SIZE);

}



void
ncrack_mysql(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;
  size_t packet_length = 0;
  char mysql_auth_method[21 + 1];
  char mysql_salt[MYSQL_SALT + 1];
  memset(mysql_auth_method, 0, sizeof(mysql_auth_method));
  char response_hex[SHA_DIGEST_LENGTH];
  switch (con->state)
  {
    case MYSQL_INIT:
     
      if (mysql_loop_read(nsp, con, mysql_auth_method, mysql_salt) < 0)
        break;
      con->state = MYSQL_FINI;
      delete con->inbuf;
      con->inbuf = NULL;

      if (con->outbuf)
        delete con->outbuf;
      
      con->outbuf = new Buf();

      if (!strncmp(mysql_auth_method, "mysql_native_password", sizeof("mysql_native_password"))){

        hash_password(response_hex, con->pass, mysql_salt);

        packet_length = strlen(con->user) + 4 + 23 +
          strlen("\x01\x05\xa6\x0f\x01\x21\x14");

        con->outbuf->snprintf(packet_length + 4 + 20 + 21 + 1,
           "%c%c%c\x01\x05\xa6\x0f%c%c%c%c\x01\x21%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%s%c\x14", 
           (char)packet_length + 20 + 21 + 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,con->user,0);
        memcpy((char *)con->outbuf->get_dataptr() + packet_length + 4 , response_hex, sizeof response_hex);
        strncpy((char *)con->outbuf->get_dataptr() + packet_length  + 20 + 4, "mysql_native_password\x00", sizeof "mysql_native_password ");
        nsock_write(nsp, nsi, ncrack_write_handler, MYSQL_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len() );

      } else if(!strncmp(mysql_auth_method, "mysql_old_password", sizeof("mysql_old_password"))){

        // con->outbuf = new Buf();
        // packet_length = strlen(con->user) + 4 + 23 + sizeof("mysql_old_password") +
        //   strlen("\x01\x05\xa6\x0f\x01\x21");

        // con->outbuf->snprintf(packet_length + 4,
        //   "%c%c%c\x01\x05\xa6\x0f%c%c%c%c\x01\x21%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%s%c%cmysql_old_password%c", 
        //    packet_length + 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,con->user,0,0,0);
        // nsock_write(nsp, nsi, ncrack_write_handler, MYSQL_TIMEOUT, con,
        // (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len() );
        return ncrack_module_end(nsp, con);

      } else if(!strncmp(mysql_auth_method, "sha256_password", sizeof("sha256_password"))){

        /* Not yet implemented. This part includes sha256 auth over SSL or
          RSA encryption of the SHA256 hash if sent cleartext. Second option is available
          to enterprise only. */ 
        /* We are terminating the effort at the moment but this doesn't mean that the user uses SHA256 
          authentication. SHA256 is just the default authentication of the server.*/
        return ncrack_module_end(nsp, con);

      } else {
        /* Not yet implement. we're lacking Windows authentication. Enterprise MySQL. */
        /* We are terminating the effort at the moment but this doesn't mean that the user uses SHA256 
          authentication. SHA256 is just the default authentication of the server.*/
        return ncrack_module_end(nsp, con);
      }     
      

      break;

    case MYSQL_FINI:

      if (mysql_loop_read(nsp, con, mysql_auth_method, mysql_salt) < 0)
        break;
      else if (mysql_loop_read(nsp, con , mysql_auth_method, mysql_salt) == 1){
        con->auth_success = true;
        con->state = MYSQL_INIT;
      }
      else if (mysql_loop_read(nsp, con , mysql_auth_method, mysql_salt) == 2){
        con->state = MYSQL_OTHER_AUTH;
      }
      else if (mysql_loop_read(nsp, con , mysql_auth_method, mysql_salt) == 0){
        con->state = MYSQL_INIT;
      }

      

      delete con->inbuf;
      con->inbuf = NULL;

      if(con->state == MYSQL_OTHER_AUTH){
        //printf("Con state:\n");
        //printf("Con state: %s\n", mysql_auth_method);
        if (!strncmp(mysql_auth_method, "mysql_native_password", sizeof("mysql_native_password"))){

          hash_password(response_hex, con->pass, mysql_salt);

          con->outbuf->snprintf(4,
             "%c%c%c\x03", 
             (char)packet_length,0,0);

          memcpy((char *)con->outbuf->get_dataptr() + 4 , response_hex, sizeof response_hex);

          nsock_write(nsp, nsi, ncrack_write_handler, MYSQL_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len() );

          break;

        } else if(!strncmp(mysql_auth_method, "mysql_old_password", sizeof("mysql_old_password"))){

          // scramble_323(response_hex, con->pass, mysql_salt);
          // con->outbuf = new Buf();
          // packet_length = 9;

          // con->outbuf->snprintf(packet_length + 4,
          //    "%c%c%c\x03%s%c", 
          //    packet_length,0,0,response_hex,0);
          // nsock_write(nsp, nsi, ncrack_write_handler, MYSQL_TIMEOUT, con,
          // (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len() );

          // break;

          return ncrack_module_end(nsp, con);

        } else if(!strncmp(mysql_auth_method, "sha256_password", sizeof("sha256_password"))){

          /* Not yet implemented. This part includes sha256 auth over SSL or
            RSA encryption of the SHA256 hash if sent cleartext. Second option is available
            to enterprise only. */ 
          /* We are terminating the effort at the moment but this doesn't mean that the user uses SHA256 
            authentication. SHA256 is just the default authentication of the server.*/
          return ncrack_module_end(nsp, con);

        } else {
          /* Not yet implement. we're lacking Windows authentication. Enterprise MySQL. */
          /* We are terminating the effort at the moment but this doesn't mean that the user uses SHA256 
            authentication. SHA256 is just the default authentication of the server.*/
          return ncrack_module_end(nsp, con);
        }     

      } else

      return ncrack_module_end(nsp, con);

    case MYSQL_OTHER_AUTH:
      if (mysql_loop_read(nsp, con, mysql_auth_method, mysql_salt) < 0)
        break;
      else if (mysql_loop_read(nsp, con , mysql_auth_method, mysql_salt) == 1){
        con->auth_success = true;
      }

      con->state = MYSQL_INIT;

      delete con->inbuf;
      con->inbuf = NULL;

      return ncrack_module_end(nsp, con);
  }
  /* make sure that ncrack_module_end() is always called last or returned to
   * have tail recursion or else stack space overflow might occur */
}
