/***************************************************************************
 * ncrack_mssql.cc -- ncrack module for the MSSQL protocol                 *
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

#define MSSQL_TIMEOUT 10000

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);
static int mssql_loop_read(nsock_pool nsp, Connection *con);

enum states { MSSQL_ATTEMPT, MSSQL_INIT, MSSQL_GET_PORT, MSSQL_FINI };

static int
mssql_loop_read(nsock_pool nsp, Connection *con)
{
  if (con->inbuf == NULL) {
    nsock_read(nsp, con->niod, ncrack_read_handler, MSSQL_TIMEOUT, con);
    return -1;
  }
  return 0;
}

void
ncrack_mssql(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;
  unsigned char len_login, len_pass;
  int tmplen;
  char * tmp;
  int pklen;
  char *start, *end;
  size_t i;

  switch (con->state)
  {
    case MSSQL_INIT:

      con->state = MSSQL_GET_PORT;
      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      /* In case the server uses named instances the port assigned
      * to them is going to be dynamic. We won't be able to know which
      * port to target. In order to bypass this small problem, we will
      * have to ping the SQL Monitor server. The monitor is running
      * on port 1434 and is listening to UDP connections.
      *
      */

      /* Excerpt from [MC-SQLR]: SQL Server Resolution Protocol 
      *
      * The CLNT_BCAST_EX packet is a broadcast or multicast 
      * request that is generated by clients that are trying to 
      * identify the list of database instances on the network 
      * and their network protocol connection information.
      *
      * CLNT_BCAST_EX (1 byte): A single byte whose value MUST be 0x02.
      */

      /*
      * Could we instead use CLNT_UCAST_EX (0x03) ? Should test it.
      */
      break;

    case MSSQL_GET_PORT:

      if (mssql_loop_read(nsp, con) < 0)
        break;
      /* In this step, we are interested only in extracting the
      * port number of the SQL server. Once extracted, we set
      * as a service attribute and proceed to the actual bruteforcing.
      */


      /* SRV_RESP message structure:
      *   Index  Description       Content
      *     0    SRV_RESP          MUST be 0x05
      *     8    RESP_SIZE         unsigned int specifies length
      *    16    RESP_DATA         For packets CLNT_BCAST_EX or
      *                            CLNT_UCAST_EX max length is 65,535 bytes
      */
     
      /* RESP_DATA terminates on a double semicolon.
      * RESP_DATA contents
      * "ServerName" SEMICOLON SERVERNAME SEMICOLON "InstanceName" 
      * SEMICOLON INSTANCENAME SEMICOLON "IsClustered" SEMICOLON 
      * YES_OR_NO SEMICOLON "Version" SEMICOLON VERSION_STRING [NP_INFO] 
      * [TCP_INFO] [VIA_INFO] [RPC_INFO] [SPX_INFO] [ADSP_INFO] [BV_INFO] 
      * SEMICOLON SEMICOLON ;
      */

      /* We only care about the TCP_INFO segment which is:
      * SEMICOLON "tcp" SEMICOLON TCP_PORT
      * Identify the string ";tcp;" and extract the following
      * integer.
      */
      con->state = MSSQL_ATTEMPT;
      return ncrack_module_end(nsp, con);

    case MSSQL_ATTEMPT:
    {
      /* This step contains the actual brute-forcing.
      * The protocol used by MSSQL server is Tabular Data Stream Protocol
      * aka TDS.
      */

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      /* A simple solution that we will employ for the moment is 
      * to send a Pre-TDS 7 Login request.
      * 
      * Packet structure was found in:
      * http://www.freetds.org/tds.html#login
      */   

      /* A TDS packet that is longer than 512 bytes (without the 8-byte header) has 
      * to be split in more packets. 
      * 
      * That limit was increased to 4096 (default value) in TSD version 7.
      * 
      * TDS version 7 was introduced for Microsoft SQL server 7.0 (1998).
      * As such we can squeeze the whole (Pre-TDS 7 Login) packet in just one request
      * without having to worry about incompatibility with older servers 
      * (Unless of course, you encounter an SQL server running software older than 1998). 
      */
      
      /* 
      *         TDS PRELOGIN Packet Header
      *   Index     Description             Content
      *   0         PRELOGIN packet header  In our case 0x02 for Pre-TDS, 
      *                             0x12 or 0x04 for server tabular response 
      *   1         Status                0x00 for normal message or
      *                             0x01 for end of message
      *   2         Length                  Packet Length uint16
      *   4         SPID                    Server process ID, uint16
      *   6         PacketID                Packet ID, uint8
      *   7         Window                  SHOULD be 0x00
      *
      */

      /*
      *         TDS PRELOGIN Data Content
      *   Index         Description             Content
      *   8             host name               30 chars
      *   38            host name length        integer 8
      *   39            user name               30 chars
      *   69            user name length        integer 8
      *   70            password                30 chars
      *   100           password length         integer 8
      *   101           host process            30 chars
      *   131           host process length     integer 8
      *   132           magic number            6 bytes \x03\x01\x06\x0a\x09\x01 
      *   138           bulk copy               integer 0x01 
      *   139           magic number            9 bytes \x00\x00\x00\x00\x00\x00\x00\x00\x00
      *   148           app name                30 chars
      *   178           app name length         integer 8
      *   179           server name             30 chars
      *   209           server name length      integer 8
      *   210           magic number            1 byte \x00 
      *   211           password2 length        integer 8
      *   212           password2               30 chars
      *   242           magic number            223 null bytes
      *   465           password2 length + 2    integer 8
      *   466           TDS major version       integer 16
      *   468           TDS minor version       integer 16
      *   470           library name            10 chars  
      *   480           library name  length    integer 8
      *   481           program major version   integer 16
      *   483           program minor version   integer 16
      *   485           magic number            3 bytes \x00\x0d\x11
      *   488           language                30 chars e.g. "us-english" 
      *   518           language length         integer 8
      *   519           magic number            1 byte \x01 
      *   520           old_secure              integer 16 (we will use \x00\x00) 
      *   522           encrypter               integer (we will use 0 for no encryption) 
      *   523           magic number            1 byte 0x00 
      *   524           sec_spare               9 bytes (fill with zeros) 
      *   533           character set           30 chars e.g. iso_1 (fill with zeros) 
      *   563           character set length    integer (0x00)
      *   564           magic number            1 bytes 0x01
      *   565           block size              6 chars
      *   571           block size length       integer 8
      */

      /* 30 null bytes */
      unsigned char hostname[] =
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

      char *username;
      username = (char *)safe_malloc(30 + 1);
      snprintf(username, 31, "%s", con->user);
      char *password;
      password = (char *)safe_malloc(30 + 1);
      snprintf(password, 31, "%s", con->pass);

      /* Fill it up to 30 chars with zeros. */
      memset(username + strlen(con->user), 0, 30 - strlen(con->user));
      memset(password + strlen(con->pass), 0, 30 - strlen(con->pass));

      /* 30 null bytes */
      unsigned char host_process[] =
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

      unsigned char magic1[] =
        "\x03\x01\x06\x0a\x09\x01";  

      /* 9 null bytes */
      unsigned char magic2[] =
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00";

      /* 30 null bytes */
      unsigned char app_name[] =
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

      /* 30 null bytes */
      unsigned char server_name[] =
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

      /* 233 null bytes */
      unsigned char magic4[] =
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00";

      unsigned char tds_major_v[] =
       "\x04\x02";

      unsigned char tds_minor_v[] =
       "\x00\x00";

      unsigned char library_name[] =
       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

      unsigned char program_major_v[] =
       "\x06\x00";

      unsigned char program_minor_v[] =
       "\x00\x00";

      unsigned char magic5[] =
       "\x00\x0d\x11";

      /* 30 null bytes */
      unsigned char language[] =
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        ;

      unsigned char old_secure[] =
        "\x00\x00";

      unsigned char sec_spare[] =
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00";

      /* 30 null bytes */
      unsigned char character_set[] =
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

      /* SQL server 2016 does not check these values. 
      * Leaving them as zeros for the moment.
      */
      unsigned char block_size[] =
        "\x00\x00\x00\x00\x00\x00";

      pklen = 8; /* Packet header length */

      tmplen = 30 + 1 /* hostname + length */
        + 30 + 1 /* username + length */
        + 30 + 1 /* password + length */
        + 30 + 1 /* host process + length */
        + 6 + 1 + 9 /* magic number 1&2 + bulk copy */
        + 30 + 1 /* app name */
        + 30 + 1 /* server name */
        + 1 /* magic number 3 */
        + 30 + 1 /* password2  + length */
        + 233 /* magic nmber 4 */
        + 1 /* password length + 2*/
        + 2 + 2 /* TDS version min/maj*/
        + 10 + 1 /* lib name + length */
        + 2 + 2 /* program version min/maj */
        + 3 /* magic number 5 */
        + 30 + 1 /* language + length */
        + 1 /* magic number 6 */
        + 2 /* old secure */
        + 1 /* encryptor  */
        + 1 /* magic number 7 */
        + 9 /* sec_spare */
        + 30 + 1 /* character set + length */
        + 1 /* magic number 8 */
        + 6 + 1 /* block size + length */
        ;

      tmp = (char *)safe_malloc(tmplen + pklen + 1);

      /* added +1 to pklen to supress gcc warning - does not affect 
       * the program since later we write at this position using memcpy at
       * tmp + pklen
       */
      snprintf((char *)tmp, pklen + 1, 
               "%c" /* 0x02 Pre-TDS packet indicator */
               "%c" /* 0x01 end of message status indicator */
               "%c%c"  /* uint16 packet length */
               "%c%c"       /* uint16 SSID  */
               "%c"       /* uint8 packet ID */
               "%c",   /* window byte 0x00 */            
               0x02,
               0x01,
               0x02, 0x3e, /* fixed length for now 574 bytes*/
               0x00, 0x00, /* 0x00, 0x00 works for SSID */
               0x01, /* This is the first packet. */
               0x00
               );       

      len_login = (unsigned char)strlen(con->user);
      len_pass = (unsigned char)strlen(con->pass);
      memcpy(tmp + pklen, hostname, 30);

      memcpy(tmp + pklen + 30, "\x00", 1);

      memcpy(tmp + pklen + 30 + 1  , username, 30);

      memcpy(tmp + pklen + 30 + 1 + 30, &len_login, 1);
      memcpy(tmp + pklen + 30 + 1 + 30 + 1, password, 30);
      memcpy(tmp + pklen + 30 + 1 + 30 + 1 + 30, &len_pass, 1);
      /* This adds up to  8 + 1 + 30 + 1 + 30 + 1 + 30  = 101 */
      memcpy(tmp + 101, host_process, 30);
      memcpy(tmp + 101 + 30, "\x00", 1);
      memcpy(tmp + 101 + 30 + 1, magic1, 6);
      memcpy(tmp + 101 + 30 + 1 + 6, "\x01", 1);
      memcpy(tmp + 101 + 30 + 1 + 6 + 1, magic2, 9);
      memcpy(tmp + 101 + 30 + 1 + 6 + 1 + 9, app_name, 30);
      memcpy(tmp + 101 + 30 + 1 + 6 + 1 + 9 + 30, "\x00", 1);
      /* + 101 + 30 + 1 + 6 + 1 + 9 + 30 + 1= 179 */
      memcpy(tmp + 179, server_name, 30);
      memcpy(tmp + 179 + 30,"\x00", 1);
      memcpy(tmp + 179 + 30 + 1,"\x00", 1);
      memcpy(tmp + 179 + 30 + 1 + 1, &len_pass, 1);
      memcpy(tmp + 179 + 30 + 1 + 1 + 1, password, 30);
      memcpy(tmp + 179 + 30 + 1 + 1 + 1 + 30, magic4, 223);
      memcpy(tmp + 179 + 30 + 1 + 1 + 1 + 30 + 223, &len_pass + 2, 1);
      /* + 179 + 30 + 1 + 1 + 1 + 30 + 223 + 1 = 466 */
      memcpy(tmp + 466, tds_major_v, 2);
      memcpy(tmp + 466 + 2, tds_minor_v, 2);
      memcpy(tmp + 466 + 2 + 2, library_name, 10);
      memcpy(tmp + 466 + 2 + 2 + 10,"\x00", 1);
      memcpy(tmp + 466 + 2 + 2 + 10 + 1, program_major_v, 2);
      memcpy(tmp + 466 + 2 + 2 + 10 + 1 + 2, program_minor_v, 2);
      memcpy(tmp + 466 + 2 + 2 + 10 + 1 + 2 + 2, magic5, 3);
      memcpy(tmp + 466 + 2 + 2 + 10 + 1 + 2 + 2 + 3, language, 30);
      memcpy(tmp + 466 + 2 + 2 + 10 + 1 + 2 + 2 + 3 + 30,"\x00", 1);
      memcpy(tmp + 466 + 2 + 2 + 10 + 1 + 2 + 2 + 3 + 30 + 1,"\x01", 1);
      /* 466 + 2 + 2 + 10 + 1 + 2 + 2 + 3 + 30 + 1 + 1 = 520  */
      memcpy(tmp + 520, old_secure, 2);
      memcpy(tmp + 520 + 2, "\x00", 1);
      memcpy(tmp + 520 + 2 + 1, "\x00", 1);
      memcpy(tmp + 520 + 2 + 1 + 1, sec_spare, 9);
      memcpy(tmp + 520 + 2 + 1 + 1 + 9, character_set, 30);
      memcpy(tmp + 520 + 2 + 1 + 1 + 9 + 30, "\x00", 1);
      memcpy(tmp + 520 + 2 + 1 + 1 + 9 + 30 + 1, "\x01", 1);
      memcpy(tmp + 520 + 2 + 1 + 1 + 9 + 30 + 1 + 1, block_size, 6);
      memcpy(tmp + 520 + 2 + 1 + 1 + 9 + 30 + 1 + 1 + 6, "\x00", 1);

      con->outbuf->append(tmp, tmplen);

      nsock_write(nsp, nsi, ncrack_write_handler, MSSQL_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());

      con->state = MSSQL_FINI;
      break;
    }

    case MSSQL_FINI:
    {
      if (mssql_loop_read(nsp, con) < 0)
        break;
      con->state = MSSQL_ATTEMPT;

      start = (char *)con->inbuf->get_dataptr();
      end = start;
      i = 0;
      while (i != con->inbuf->get_len()) {
        end++;
        i++;
      }

      /* Parse the header and then verify that we have at least a 9-byte response
      * 8 bytes for the correct header and 1 byte for the code.
      * (It will never be just 9 bytes unless it is a different protocol)
      * Then check the first byte of the response, it should be 0x04.
      * This value denotes a TDS server response packet.
      * Then check the 1 packet of the data segment of the packet.
      * If the byte is 0xe3 then the authentication attempt was correct.
      */
      if (con->inbuf->get_len() > 9 
        && (unsigned char) start[0] == 0x04
        && (unsigned char) start[8] == 0xe3){
        con->auth_success = true;
      }

      ncrack_module_end(nsp, con);
      break;
    }
  }
}
