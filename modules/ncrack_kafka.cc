/***************************************************************************
 * ncrack_kafka.cc -- ncrack module for the Apache Kafka service           *
 * Created by Barrend                                                      *
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

#define KAFKA_TIMEOUT 20000

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

static int kafka_loop_read(nsock_pool nsp, Connection *con);

enum states { KAFKA_INIT, KAFKA_INIT_REPLY, KAFKA_SASL, KAFKA_SASL_REPLY, KAFKA_LOGIN, KAFKA_USER };

static int
kafka_loop_read(nsock_pool nsp, Connection *con)
{
  if (con->inbuf == NULL){ 
    nsock_read(nsp, con->niod, ncrack_read_handler, KAFKA_TIMEOUT, con);
    return -1;
  }
  if (memsearch((const char *)con->inbuf->get_dataptr(),"Authentication failed",con->inbuf->get_len())){
    return 1;
  }
  return 0;
}

struct kafka_apiversions {
  uint8_t length[4];
  uint16_t api_key[1];
  uint16_t api_version[1];
  uint32_t corr_id[1];
  uint16_t client_id_len[1];
  uint8_t client_id[14];
};

static void
kafka_encode_apiversions(Connection *con) {
  kafka_apiversions apiversions;
  apiversions.length[0] = 0;
  apiversions.length[1] = 0;
  apiversions.length[2] = 0;
  apiversions.length[3] = 22;//total length of the packet
  con->outbuf->append(&apiversions.length, sizeof(apiversions.length));
  apiversions.api_key[0] = 0x1200;
  con->outbuf->append(&apiversions.api_key, sizeof(apiversions.api_key));
  apiversions.api_version[0] = 0; 
  con->outbuf->append(&apiversions.api_version, sizeof(apiversions.api_version));
  apiversions.corr_id[0] = 0xf8ffff7f; //decimal from hex 7fffff8
  con->outbuf->append(&apiversions.corr_id, sizeof(apiversions.corr_id));
  apiversions.client_id_len[0] = 0x0c00; //length of consumer-1-1
  con->outbuf->append(&apiversions.client_id_len, sizeof(apiversions.client_id_len));
  con->outbuf->snprintf(12, "consumer-1-1");
}

struct kafka_saslhandshake {
  uint8_t length[4];
  uint16_t api_key[1];
  uint16_t api_version[1];
  uint32_t corr_id[1];
  uint16_t client_id_len[1];
  uint8_t client_id[14];
  uint16_t sasl_mech_len[1];
  uint8_t sasl_mech[14];
};

static void
kafka_encode_saslhandshake(Connection *con) {
  kafka_saslhandshake saslhandshake;
  saslhandshake.length[0] = 0;
  saslhandshake.length[1] = 0;
  saslhandshake.length[2] = 0;
  saslhandshake.length[3] = 29;//total length of the packet
  con->outbuf->append(&saslhandshake.length, sizeof(saslhandshake.length));
  saslhandshake.api_key[0] = 0x1100;
  con->outbuf->append(&saslhandshake.api_key, sizeof(saslhandshake.api_key));
  saslhandshake.api_version[0] = 0x0100; 
  con->outbuf->append(&saslhandshake.api_version, sizeof(saslhandshake.api_version));
  saslhandshake.corr_id[0] = 0xf9ffff7f; //decimal from hex 7fffff8
  con->outbuf->append(&saslhandshake.corr_id, sizeof(saslhandshake.corr_id));
  saslhandshake.client_id_len[0] = 0x0c00; //length of consumer-1-1
  con->outbuf->append(&saslhandshake.client_id_len, sizeof(saslhandshake.client_id_len));
  con->outbuf->snprintf(12, "consumer-1-1");
  saslhandshake.sasl_mech_len[0] = 0x0500; //length of plain
  con->outbuf->append(&saslhandshake.sasl_mech_len, sizeof(saslhandshake.sasl_mech_len));
  con->outbuf->snprintf(5, "PLAIN");
}

struct kafka_login {
  uint8_t length[4];
  uint16_t api_key[1];
  uint16_t api_version[1];
  uint32_t corr_id[1];
  uint16_t client_id_len[1];
  uint8_t client_id[14];
  uint8_t tagged_fields;
  uint8_t x[1];
};


static void
kafka_encode_login(Connection *con) {
  kafka_login login;
  login.length[0] = 0;
  login.length[1] = 0;
  login.length[2] = 0;
  login.length[3] = 27 + strlen(con->user) + strlen(con->pass);//total length of the packet
  con->outbuf->append(&login.length, sizeof(login.length));
  login.api_key[0] = 0x2400;
  con->outbuf->append(&login.api_key, sizeof(login.api_key));
  login.api_version[0] = 0x0200; 
  con->outbuf->append(&login.api_version, sizeof(login.api_version));
  login.corr_id[0] = 0xfaffff7f; //decimal from hex 7fffff8
  con->outbuf->append(&login.corr_id, sizeof(login.corr_id));
  login.client_id_len[0] = 0x0c00; //length of consumer-1-1
  con->outbuf->append(&login.client_id_len, sizeof(login.client_id_len));
  con->outbuf->snprintf(12, "consumer-1-1");
  login.tagged_fields = 0;
  con->outbuf->append(&login.tagged_fields, sizeof(login.tagged_fields));
  login.x[0] = strlen(con->user) + strlen(con->pass) + 3; //length of the remaining bytes
  con->outbuf->append(&login.x, sizeof(login.x));
  login.tagged_fields = 0;
  con->outbuf->append(&login.tagged_fields, sizeof(login.tagged_fields));
  con->outbuf->snprintf(strlen(con->user), "%s", con->user);
  login.tagged_fields = 0;
  con->outbuf->append(&login.tagged_fields, sizeof(login.tagged_fields));
  con->outbuf->snprintf(strlen(con->pass), "%s", con->pass);
  login.tagged_fields = 0;
  con->outbuf->append(&login.tagged_fields, sizeof(login.tagged_fields));
}

void
ncrack_kafka(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;

  switch(con->state)
  {
    case KAFKA_INIT:
      con->state = KAFKA_INIT_REPLY;    
      delete con->inbuf;
      con->inbuf = NULL;
      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();
      kafka_encode_apiversions(con);
      nsock_write(nsp, nsi, ncrack_write_handler, KAFKA_TIMEOUT, con, (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case KAFKA_INIT_REPLY:
      delete con->inbuf;
      con->inbuf = NULL;
      con->state = KAFKA_SASL;    
      nsock_read(nsp, con->niod, ncrack_read_handler, KAFKA_TIMEOUT, con);
    break;

    case KAFKA_SASL:
      con->state = KAFKA_SASL_REPLY;
      delete con->inbuf;
      con->inbuf=NULL;
      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();
      kafka_encode_saslhandshake(con);
      nsock_write(nsp, nsi, ncrack_write_handler, KAFKA_TIMEOUT, con, (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case KAFKA_SASL_REPLY:
      delete con->inbuf;
      con->inbuf = NULL;
      con->state = KAFKA_LOGIN;    
      nsock_read(nsp, con->niod, ncrack_read_handler, KAFKA_TIMEOUT, con);
    break;

    case KAFKA_LOGIN:
      con->state = KAFKA_USER;
      delete con->inbuf;
      con->inbuf=NULL;
      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();
      kafka_encode_login(con);
      nsock_write(nsp, nsi, ncrack_write_handler, KAFKA_TIMEOUT, con, (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case KAFKA_USER: 

      if (kafka_loop_read(nsp,con) < 0){
	break;
      }
      if (kafka_loop_read(nsp,con) == 0){
        con->auth_success = true;
      }
      con->state = KAFKA_INIT;

      return ncrack_module_end(nsp, con);
  }
}
