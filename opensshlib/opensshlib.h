
/***************************************************************************
 * opensshlib.h -- header file containing generic structure that is being  *
 * passed along all hooked OpenSSH functions to track Ncrack state for the *
 * SSH module.                                                             *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                *
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/



#ifndef OPENSSHLIB_H
#define OPENSSHLIB_H

#include "buffer.h"
#include "sshbuf.h"
#include "cipher.h"
#include "ssh1.h"

#ifdef __cplusplus
extern "C" {
#endif

struct kex;
struct newkeys;

typedef struct packet_state {
  u_int32_t seqnr;
  u_int32_t packets;
  u_int64_t blocks;
  u_int64_t bytes;
} packet_state;

/*
 * Every module invocation has its own Ncrack_state struct which holds every
 * bit of information needed to keep track of things. Most of the variables
 * found inside this object were usually static/global variables in the original
 * OpenSSH codebase.
 */
typedef struct ncrack_ssh_state {

  struct kex *kex;
  DH *dh;
  /* Session key information for Encryption and MAC */
  struct newkeys *newkeys[2];
  struct newkeys *current_keys[2];
  char *client_version_string;
  char *server_version_string;
  /* Encryption context for receiving data. This is only used for decryption. */
  struct sshcipher_ctx receive_context;
  /* Encryption context for sending data. This is only used for encryption. */
  struct sshcipher_ctx send_context;

  /* ***** IO Buffers ****** */
  //Buffer ncrack_buf;

  /* Buffer for raw input data from the socket. */
  struct sshbuf *input;
  /* Buffer for raw output data going to the socket. */
  struct sshbuf *output;
  /* Buffer for the incoming packet currently being processed. */
  struct sshbuf *incoming_packet;
  /* Buffer for the partial outgoing packet being constructed. */
  struct sshbuf *outgoing_packet;

  u_int64_t max_blocks_in;
  u_int64_t max_blocks_out;
  packet_state p_read;
  packet_state p_send;

  /* Used in packet_read_poll2() */
  u_int packlen;

	int compat20;	/* boolean -> true if SSHv2 compatible */

  /* Compatibility mode for different bugs of various older sshd
   * versions. It holds a list of these bug types in a binary OR list
   */
  int datafellows;
  int compat;
  int type;   /* type of packet returned */
  u_char extra_pad; /* extra padding that might be needed */

  /*
   * Reason that this connection was ended. It might be that we got a
   * disconnnect packet from the server due to many authentication attempts
   * or some other exotic reason.
   */
  char *disc_reason;

	u_int packet_length; // TODO check this

  int 	rekeying;
  u_int32_t 	rekey_limit;
  u_int32_t 	rekey_interval;
  time_t 	rekey_time;
  int 	cipher_warning_done;

  int keep_alive_timeouts;
  int 	dispatch_skip_packets;

  u_int packet_discard;
  struct sshmac *packet_discard_mac;

  char *prev_user;


} ncrack_ssh_state;


#ifdef __cplusplus
} /* End of 'extern "C"' */
#endif



#endif
