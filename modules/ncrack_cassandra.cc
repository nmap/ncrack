/***************************************************************************
 * ncrack_cassandra.cc -- ncrack module for the Cassandra DBMS Service     *
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

#define CASS_TIMEOUT 20000 //here

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

static int cass_loop_read(nsock_pool nsp, Connection *con);
static void cass_encode_CALL(Connection *con);
static void cass_encode_data(Connection *con);
    

enum states { CASS_INIT, CASS_USER };

struct cass_CALL {

  uint8_t len[4];
  uint16_t version[1];
  uint8_t zero;
  uint8_t call_id;
  uint8_t length[4];
  uint16_t sequence_id[2];
};

struct cass_data {

  uint8_t t_struct;
  u_char field_id[2];
  uint8_t t_stop;
  struct {
    uint8_t t_map;
    u_char field_id[2];
    uint8_t t_stop;
    struct {
      uint8_t t_utf7;
      uint8_t nomitems[4];
      uint8_t length1[4];
      u_char string1[8];
      uint8_t length2[4];
      uint8_t length3[4];
      u_char string3[8];
      uint8_t length4[4];
    } map;
  } Struct;
};


static int
cass_loop_read(nsock_pool nsp, Connection *con)
{
  if ((con->inbuf == NULL) || (con->inbuf->get_len()<22)) {
    nsock_read(nsp, con->niod, ncrack_read_handler, CASS_TIMEOUT, con);
    return -1;
  }
  return 0;
}


static void
cass_encode_CALL(Connection *con) {
  cass_CALL call;
  call.len[0] = 0;
  call.len[1] = 0;
  call.len[2] = 0;
  call.len[3] = 63 + strlen(con->user) + strlen(con->pass);//total length of the packet
  con->outbuf->append(&call.len, sizeof(call.len));
  call.version[0] = 0x0180; //2byte
  con->outbuf->append(&call.version, sizeof(call.version));
  call.zero = 0;
  con->outbuf->append(&call.zero, sizeof(call.zero));
  call.call_id = 1;
  con->outbuf->append(&call.call_id, sizeof(call.call_id));
  call.length[0] = 0;
  call.length[1] = 0;
  call.length[2] = 0;
  call.length[3] = 5;
  con->outbuf->append(&call.length, sizeof(call.length));
  con->outbuf->snprintf(5, "login");  
  call.sequence_id[0] = 0;
  call.sequence_id[1] = 0;
  //call.sequence_id[2] = 0;
  //call.sequence_id[3] = 0;
  con->outbuf->append(&call.sequence_id, sizeof(call.sequence_id));
}

static void
cass_encode_data(Connection *con) {
  cass_data data;

  data.t_struct = 12; //T_STRUCT (12)=1byte
  con->outbuf->append(&data.t_struct, sizeof(data.t_struct));  
  data.field_id[0] = 0;
  data.field_id[1] = 1; // Field Id: 1 =2byte
  con->outbuf->append(&data.field_id, sizeof(data.field_id));  
  data.Struct.t_map = 13; // T_MAP (13) =1byte
  con->outbuf->append(&data.Struct.t_map, sizeof(data.Struct.t_map));  
  data.Struct.field_id[0] = 0;
  data.Struct.field_id[1] = 1;
  con->outbuf->append(&data.Struct.field_id, sizeof(data.Struct.field_id));  
  data.Struct.map.t_utf7 = 11;
  con->outbuf->append(&data.Struct.map.t_utf7, sizeof(data.Struct.map.t_utf7));   con->outbuf->append(&data.Struct.map.t_utf7, sizeof(data.Struct.map.t_utf7));  
  data.Struct.map.nomitems[0] = 0;
  data.Struct.map.nomitems[1] = 0;
  data.Struct.map.nomitems[2] = 0;
  data.Struct.map.nomitems[3] = 2;
  con->outbuf->append(&data.Struct.map.nomitems, sizeof(data.Struct.map.nomitems));  
  data.Struct.map.length1[0] = 0; //4byte
  data.Struct.map.length1[1] = 0;
  data.Struct.map.length1[2] = 0;
  data.Struct.map.length1[3] = strlen("username");
  con->outbuf->append(&data.Struct.map.length1, sizeof(data.Struct.map.length1));  
  memcpy((char * )&data.Struct.map.string1[0], "username", 8);  
  con->outbuf->append(&data.Struct.map.string1, sizeof(data.Struct.map.string1));  
  data.Struct.map.length2[0] = 0;
  data.Struct.map.length2[1] = 0;
  data.Struct.map.length2[2] = 0;
  data.Struct.map.length2[3] = strlen(con->user);
  con->outbuf->append(&data.Struct.map.length2, sizeof(data.Struct.map.length2));  
  con->outbuf->snprintf(strlen(con->user), "%s", con->user);  

  data.Struct.map.length3[0] = 0; //4byte
  data.Struct.map.length3[1] = 0;
  data.Struct.map.length3[2] = 0;
  data.Struct.map.length3[3] = strlen("password");
  con->outbuf->append(&data.Struct.map.length3, sizeof(data.Struct.map.length3));  
  memcpy((char * )&data.Struct.map.string3[0], "password", 8);  
  con->outbuf->append(&data.Struct.map.string3, sizeof(data.Struct.map.string3));  
  data.Struct.map.length4[0] = 0; //4byte
  data.Struct.map.length4[1] = 0; //4byte
  data.Struct.map.length4[2] = 0; //4byte
  data.Struct.map.length4[3] = strlen(con->pass); //4byte
  con->outbuf->append(&data.Struct.map.length4, sizeof(data.Struct.map.length4));
  con->outbuf->snprintf(strlen(con->pass), "%s", con->pass);  
  data.Struct.t_stop = 0; //2->1byte
  con->outbuf->append(&data.Struct.t_stop, sizeof(data.Struct.t_stop));
  data.t_stop = 0;
  con->outbuf->append(&data.t_stop, sizeof(data.t_stop));

}

void
ncrack_cassandra(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;

  switch(con->state)
  {
    case CASS_INIT:

      con->state = CASS_USER;    
      delete con->inbuf;
      con->inbuf = NULL;
      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();
      cass_encode_CALL(con);
      cass_encode_data(con);
      nsock_write(nsp, nsi, ncrack_write_handler, CASS_TIMEOUT, con, (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case CASS_USER: 
      if (cass_loop_read(nsp,con) < 0){
        break;
      }
      //The difference of the successful and failed authentication resides on the 22th byte of the reply packet
      const char *p = (const char *)con->inbuf->get_dataptr();
      if (p[21] == '\x0c')//find the 22th byte and compare it to 0c
        ;//printf("%x", p[21]); 
      else if (p[21] == '\x00')//find the 22th byte and compare it to 00
        con->auth_success = true;
      con->state = CASS_INIT;

      return ncrack_module_end(nsp, con);
  }
}

