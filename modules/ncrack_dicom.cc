
/***************************************************************************
 * ncrack_dicom.cc -- ncrack module for the DICOM protocol                 *
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

#define DICOM_TIMEOUT 20000


#define DICOM_APP "1.2.840.10008.3.1.1.1"
#define DICOM_ABS "1.2.840.10008.5.1.4.1.1.7"
#define DICOM_TRX_EXP_L "1.2.840.10008.1.2.1"
#define DICOM_TRX_IMP_L "1.2.840.10008.1.2"
#define DICOM_TRX_EXP_B "1.2.840.10008.1.2.2"
#define DICOM_UID "1.2.826.0.1.3680043.2.1545.1"
#define DICOM_IMPL "Ncrack"

#define DICOM_ERROR "Received bogus pdu type"

typedef struct dicom_assoc {

  struct assoc_request {

    struct app_ctx {
      uint16_t item_type; // 0x10 = app context
      uint16_t item_length;
      u_char ctx[21];

      app_ctx() {
        item_type = 0x10;
        item_length = le_to_be16(21);
        memcpy(ctx, DICOM_APP, sizeof(ctx));
      }
    } __attribute__((__packed__));

    struct pres_context {

      struct abstract_syntax {
        uint16_t item_type; // 0x30 = abstract
        uint16_t item_length;
        u_char abs_syntax[25];
        
        abstract_syntax() {
          item_type = 0x30;
          item_length = le_to_be16(25);
          memcpy(abs_syntax, DICOM_ABS, sizeof(abs_syntax));
        }
      } __attribute__((__packed__));

#if 0
      struct transfer_syntax_explicit_l {
        uint16_t item_type; // 0x40 = transfer
        uint16_t item_length;
        u_char trx_syntax[19]; // explicit vr little endian

        transfer_syntax_explicit_l() {
          item_type = 0x40;
          item_length = le_to_be16(19);
          memcpy(trx_syntax, DICOM_TRX_EXP_L, sizeof(trx_syntax));
        }
      } __attribute__((__packed__));

      struct transfer_syntax_explicit_b {
        uint16_t item_type; // 0x40 = transfer
        uint16_t item_length;
        u_char trx_syntax[19]; // explicit vr big endian

        transfer_syntax_explicit_b() {
          item_type = 0x40;
          item_length = le_to_be16(19);
          memcpy(trx_syntax, DICOM_TRX_EXP_B, sizeof(trx_syntax));
        }
      } __attribute__((__packed__));
#endif

      struct transfer_syntax_implicit_l {
        uint16_t item_type; // 0x40 = transfer
        uint16_t item_length;
        u_char trx_syntax[17]; // implicit vr little endian

        transfer_syntax_implicit_l() {
          item_type = 0x40;
          item_length = le_to_be16(17);
          memcpy(trx_syntax, DICOM_TRX_IMP_L, sizeof(trx_syntax));
        }
      } __attribute__((__packed__));


      pres_context() {
        item_type = 0x20;
        item_length = le_to_be16(54);
        context_id = 0x01;
      }

      uint16_t item_type; // 0x20 = presentation
      uint16_t item_length;
      uint8_t context_id;  
      u_char pad0[3] = { 0x00, 0x00, 0x00 };
      abstract_syntax abs;
      //transfer_syntax_explicit_l trx_el;
      transfer_syntax_implicit_l trx_il;
      //transfer_syntax_explicit_b trx_eb;
    } __attribute__((__packed__));

    struct user_info {

      struct max_length {
        uint16_t item_type; // 0x51 = max-length
        uint16_t item_length;
        uint32_t max_len;

        max_length() {
          item_type = 0x51;
          item_length = le_to_be16(4);
          max_len = le_to_be32(16384);
        }
      } __attribute__((__packed__));
      struct implementation_id {
        uint16_t item_type; // 0x52 = class uid
        uint16_t item_length; 
        u_char class_uid[28]; 

        implementation_id() {
          item_type = 0x52;
          item_length = le_to_be16(28);
          memcpy(class_uid, DICOM_UID, sizeof(class_uid));
        }
      } __attribute__((__packed__));
      struct async_neg {
        uint16_t item_type; // 0x53 = async op
        uint16_t item_length;
        uint16_t max_num_ops_invoked;
        uint16_t max_num_ops_performed;

        async_neg() {
          item_type = 0x53;
          item_length = le_to_be16(4);
          max_num_ops_invoked = 0;
          max_num_ops_performed = 0;
        }
      } __attribute__((__packed__));
      struct implementation_version {
        uint16_t item_type; // 0x55 = impl version
        uint16_t item_length;
        u_char impl_version[6];

        implementation_version() {
          item_type = 0x55;
          item_length = le_to_be16(6);
          memcpy(impl_version, DICOM_IMPL, sizeof(impl_version));
        }
      } __attribute__((__packed__));

      user_info() {
        item_type = 0x50;
        item_length = le_to_be16(50);  // 26
      }

      uint16_t item_type; // 0x50 = user-info
      uint16_t item_length;
      max_length max;
      implementation_id uid;
      //async_neg async;
      implementation_version impl;

    } __attribute__((__packed__));

    assoc_request() {
      version = le_to_be16(1);
    }
    
    uint16_t version;
    u_char pad[2] = { 0x00, 0x00 };
    u_char called_ae[16] = { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                             0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };
    u_char calling_ae[16] = { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                              0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };
    u_char pad0[32] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    app_ctx app;
    pres_context pres;
    user_info user;
  } __attribute__((__packed__));

  dicom_assoc() {
    pdu_type = le_to_be16(0x100);
    pdu_length = le_to_be32(205);  // 231
  }

  uint16_t pdu_type;
  uint32_t pdu_length;
  assoc_request assoc;

} __attribute__((__packed__)) dicom_assoc;



extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);
static int dicom_loop_read(nsock_pool nsp, Connection *con);

enum states { DICOM_INIT, DICOM_FINI };


static int
dicom_loop_read(nsock_pool nsp, Connection *con)
{
  uint32_t *pdu_length;

  /* we need at least 6 bytes to read the whole PDU length */
  if (con->inbuf == NULL || con->inbuf->get_len() < 6) {
    nsock_read(nsp, con->niod, ncrack_read_handler, DICOM_TIMEOUT, con);
    return -1;
  }

  pdu_length = (uint32_t *)((u_char *)con->inbuf->get_dataptr() + 2);
  *pdu_length = le_to_be32(*pdu_length);

  if (o.debugging > 9)
    printf("pdu length: %d\n", *pdu_length);

  /* now read until we receive all bytes mentioned in length */
  if (con->inbuf->get_len() < *pdu_length) {
    nsock_read(nsp, con->niod, ncrack_read_handler, DICOM_TIMEOUT, con);
    return -1;
  }

  return 0;
}



void
ncrack_dicom(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  dicom_assoc da;
  uint8_t *pdu_type;

  switch (con->state)
  {
    case DICOM_INIT:

      con->state = DICOM_FINI;

      delete con->inbuf;
      con->inbuf = NULL;

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();

      memcpy(da.assoc.called_ae, con->user, strlen(con->user));
      memcpy(da.assoc.calling_ae, con->pass, strlen(con->pass));
      
      con->outbuf->append(&da, sizeof(da));

      nsock_write(nsp, nsi, ncrack_write_handler, DICOM_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case DICOM_FINI:

      if (dicom_loop_read(nsp, con) < 0)
        break;

      pdu_type = (uint8_t *)((u_char *)con->inbuf->get_dataptr());
      if (o.debugging > 9)
        printf("pdu_type: %d \n", *pdu_type);

      if (*pdu_type == 0x03) { // ASSOC REJECT 
        ;
      } else if (*pdu_type == 0x02) { // ASSOC ACCEPT
        con->auth_success = true; 
        con->force_close = true;      
      } else { 
        /* received weird pdu  
         * close connection and stop cracking
         */
        con->force_close = true;
        con->close_reason = MODULE_ERR;
        serv->end.orly = true;
        serv->end.reason = Strndup(DICOM_ERROR, sizeof(DICOM_ERROR));
      }
      con->state = DICOM_INIT;

      delete con->inbuf;
      con->inbuf = NULL;

      return ncrack_module_end(nsp, con);
  }
}
