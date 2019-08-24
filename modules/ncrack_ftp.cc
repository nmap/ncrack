
/***************************************************************************
 * ncrack_ftp.cc -- ncrack module for the FTP protocol                     *
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

#define FTP_TIMEOUT 20000
#define FTP_DIGITS 3


extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);
static int ftp_loop_read(nsock_pool nsp, Connection *con, char *ftp_code_ret);

enum states { FTP_INIT, FTP_USER, FTP_FINI };


static int
ftp_loop_read(nsock_pool nsp, Connection *con, char *ftp_code_ret)
{
  int i;
  int ftp_dig[FTP_DIGITS];
  char ftp_code[FTP_DIGITS + 2]; /* 3 digits + space + '\0' */
  char dig[2]; /* temporary digit string */
  char *p;

  if (con->inbuf == NULL || con->inbuf->get_len() < FTP_DIGITS + 1) {
    nsock_read(nsp, con->niod, ncrack_read_handler, FTP_TIMEOUT, con);
    return -1;
  }

  /* Make sure first 3 (FTP_DIGITS) bytes of each line are digits */
  p = (char *)con->inbuf->get_dataptr();
  dig[1] = '\0';
  for (i = 0; i < FTP_DIGITS; i++) {
    dig[0] = *p++;
    ftp_dig[i] = (int)Strtoul(dig, 0);
    if (errno) { /* It wasn't a number! */
      return -2;  /* Oops, malformed FTP packet */
    }
  }

  /* 
   * http://www.faqs.org/rfcs/rfc959.html
   * Thus the format for multi-line replies is that the first line
   * will begin with the exact required reply code, followed
   * immediately by a Hyphen, "-" (also known as Minus), followed by
   * text.  The last line will begin with the same code, followed
   * immediately by Space <SP>, optionally some text, and the Telnet
   * end-of-line code.
   *
   * For example:
   *   123-First line
   *   Second line
   *      234 A line beginning with numbers
   *   123 The last line
   */

  /* Convert digits to string code for parsing */
  snprintf(ftp_code, FTP_DIGITS + 1, "%d%d%d", ftp_dig[0], ftp_dig[1],
      ftp_dig[2]);
  ftp_code[FTP_DIGITS] = ' ';
  ftp_code[FTP_DIGITS + 1] = '\0';

  if (*p == '-') {
    /* FTP message is multiple lines, so first search for the 'ftp code' to
     * find the last line, according to the scheme proposed by RFC 959 */
    if (!(p = memsearch((const char *)con->inbuf->get_dataptr(), ftp_code,
          con->inbuf->get_len()))) {
      nsock_read(nsp, con->niod, ncrack_read_handler, FTP_TIMEOUT, con);
      return -1;
    }
    /* Now that we found the the last line, find that line's end */
    if (!memsearch((const char *)p, "\r\n", con->inbuf->get_len())) {
      nsock_read(nsp, con->niod, ncrack_read_handler, FTP_TIMEOUT, con);
      return -1;
    }
  } else {
    /* FTP message is one line only */
    if (!memsearch((const char *)con->inbuf->get_dataptr(), "\r\n",
          con->inbuf->get_len())) {
      nsock_read(nsp, con->niod, ncrack_read_handler, FTP_TIMEOUT, con);
      return -1;
    }
  }

  /* Return the ftp code to caller */
  memcpy(ftp_code_ret, ftp_code, FTP_DIGITS);

  return 0;

}



void
ncrack_ftp(nsock_pool nsp, Connection *con)
{
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  const char *hostinfo = serv->HostInfo();
  char ftp_code[FTP_DIGITS + 1];
  memset(ftp_code, 0, sizeof(ftp_code));

  switch (con->state)
  {
    case FTP_INIT:

      /* Wait to read banner only at the beginning of the connection */
      if (!con->login_attempts) {

        if (ftp_loop_read(nsp, con, ftp_code) < 0)
          break;

        /* ftp_loop_read already takes care so that the inbuf contains the
         * 3 first ftp digit code, so you can safely traverse it that much */
        if (strncmp(ftp_code, "220", FTP_DIGITS)) {

          if (o.debugging > 6)
            error("%s Not ftp or service was shutdown\n", hostinfo);
          return ncrack_module_end(nsp, con);
        }
      }

      con->state = FTP_USER;

      delete con->inbuf;
      con->inbuf = NULL;

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();
      con->outbuf->snprintf(7 + strlen(con->user), "USER %s\r\n", con->user);

      nsock_write(nsp, nsi, ncrack_write_handler, FTP_TIMEOUT, con,
          (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case FTP_USER:

      if (ftp_loop_read(nsp, con, ftp_code) < 0)
        break;

      if (!strncmp(ftp_code, "331", FTP_DIGITS)) {
        ;
      } else {
        return ncrack_module_end(nsp, con);
      }

      con->state = FTP_FINI;

      delete con->inbuf;
      con->inbuf = NULL;

      if (con->outbuf)
        delete con->outbuf;
      con->outbuf = new Buf();
      con->outbuf->snprintf(7 + strlen(con->pass), "PASS %s\r\n", con->pass);

      nsock_write(nsp, nsi, ncrack_write_handler, FTP_TIMEOUT, con,
        (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      break;

    case FTP_FINI:

      if (ftp_loop_read(nsp, con, ftp_code) < 0)
        break;

      if (!strncmp(ftp_code, "230", FTP_DIGITS)) 
        con->auth_success = true;

      con->state = FTP_INIT;

      delete con->inbuf;
      con->inbuf = NULL;

      return ncrack_module_end(nsp, con);
  }
  /* make sure that ncrack_module_end() is always called last or returned to
   * have tail recursion or else stack space overflow might occur */
}
