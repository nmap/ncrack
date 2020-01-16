/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/***************************************************************************
 * ntlmssp.cc -- ntlmssp auth method                                       *
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

/*
   Proudly stolen and adapted from libsmb2 -- https://github.com/sahlberg/libsmb2
   - lazily converted original C code to C++ (mostly casted malloc)
   - replaced custom crypto with openssl (hmac md5)
   - replaced custom unicode conv to ncrack routine (unicode_alloc)
   - replaced custom ntlmv1 routine to ncrack routine (ntlm_create_hash)

   Copyright (C) 2018 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include "portable_endian.h"

#include "ncrack.h"
#include "ntlmssp.h"

#if HAVE_OPENSSL 

#include <openssl/hmac.h>
#include <openssl/md4.h>
#include <openssl/md5.h>


#include "crypto.h" // ntlm_create_hash
#include "utils.h" // unicode_alloc

#define SMB2_KEY_SIZE 16

struct auth_data {
   unsigned char *buf;
   size_t len;
   size_t allocated;

   int neg_result;
   unsigned char *ntlm_buf;
   size_t ntlm_len;

   const char *user;
   const char *password;
   const char *domain;
   const char *workstation;
   const char *client_challenge;

   uint8_t exported_session_key[SMB2_KEY_SIZE];
 };

#define NEGOTIATE_MESSAGE      0x00000001
#define CHALLENGE_MESSAGE      0x00000002
#define AUTHENTICATION_MESSAGE 0x00000003

#define NTLMSSP_NEGOTIATE_56                               0x80000000
#define NTLMSSP_NEGOTIATE_128                              0x20000000
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY         0x00080000
#define NTLMSSP_TARGET_TYPE_SERVER                         0x00020000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN                      0x00008000
#define NTLMSSP_NEGOTIATE_NTLM                             0x00000200
#define NTLMSSP_NEGOTIATE_SIGN                             0x00000010
#define NTLMSSP_REQUEST_TARGET                             0x00000004
#define NTLMSSP_NEGOTIATE_OEM                              0x00000002
#define NTLMSSP_NEGOTIATE_UNICODE                          0x00000001
#define NTLMSSP_NEGOTIATE_KEY_EXCH                         0x40000000

static uint64_t
timeval_to_win(struct timeval *tv)
{
  return ((uint64_t)tv->tv_sec * 10000000) +
    116444736000000000 + tv->tv_usec * 10;
}

void
ntlmssp_destroy_context(struct auth_data *auth)
{
  free(auth->ntlm_buf);
  free(auth->buf);
  free(auth);
}

struct auth_data *
ntlmssp_init_context(const char *user,
    const char *password,
    const char *domain,
    const char *workstation,
    const char *client_challenge)
{
  struct auth_data *auth_data = NULL;

  auth_data = (struct auth_data*)malloc(sizeof(struct auth_data));
  if (auth_data == NULL) {
    return NULL;
  }
  memset(auth_data, 0, sizeof(struct auth_data));

  auth_data->user        = user;
  auth_data->password    = password;
  auth_data->domain      = domain;
  auth_data->workstation = workstation;
  auth_data->client_challenge = client_challenge;

  memset(auth_data->exported_session_key, 0, SMB2_KEY_SIZE);

  return auth_data;
}

static int
encoder(const void *buffer, size_t size, void *ptr)
{
  struct auth_data *auth_data = (struct auth_data*)ptr;

  if (size + auth_data->len > auth_data->allocated) {
    unsigned char *tmp = auth_data->buf;

    auth_data->allocated = 2 * ((size + auth_data->allocated + 256) & ~0xff);
    auth_data->buf = (unsigned char*)malloc(auth_data->allocated);
    if (auth_data->buf == NULL) {
      free(tmp);
      return -1;
    }
    memcpy(auth_data->buf, tmp, auth_data->len);
    free(tmp);
  }

  memcpy(auth_data->buf + auth_data->len, buffer, size);
  auth_data->len += size;

  return 0;
}

static int
ntlm_negotiate_message(struct auth_data *auth_data)
{
  unsigned char ntlm[32];
  uint32_t u32;

  memset(ntlm, 0, 32);
  memcpy(ntlm, "NTLMSSP", 8);

  u32 = htole32(NEGOTIATE_MESSAGE);
  memcpy(&ntlm[8], &u32, 4);

  u32 = htole32(NTLMSSP_NEGOTIATE_56|NTLMSSP_NEGOTIATE_128|
      NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY|
      //NTLMSSP_NEGOTIATE_ALWAYS_SIGN|
      NTLMSSP_NEGOTIATE_NTLM|
      //NTLMSSP_NEGOTIATE_SIGN|
      NTLMSSP_REQUEST_TARGET|NTLMSSP_NEGOTIATE_OEM|
      NTLMSSP_NEGOTIATE_UNICODE);
  memcpy(&ntlm[12], &u32, 4);

  if (encoder(&ntlm[0], 32, auth_data) < 0) {
    return -1;
  }

  return 0;
}

static int
ntlm_challenge_message(struct auth_data *auth_data, unsigned char *buf,
    int len)
{
  free(auth_data->ntlm_buf);
  auth_data->ntlm_len = len;
  auth_data->ntlm_buf = (unsigned char*)malloc(auth_data->ntlm_len);
  if (auth_data->ntlm_buf == NULL) {
    return -1;
  }
  memcpy(auth_data->ntlm_buf, buf, auth_data->ntlm_len);

  return 0;
}

static int
NTOWFv2(const char *user, const char *password, const char *domain,
    unsigned char ntlmv2_hash[16])
{
  size_t i, len, userdomain_len;
  char *userdomain;
  char *ucs2_userdomain = NULL;
  unsigned char ntlm_hash[16];

  ntlm_create_hash(password, ntlm_hash);

  len = strlen(user) + 1;
  if (domain) {
    len += strlen(domain);
  }
  userdomain = (char*)malloc(len);
  if (userdomain == NULL) {
    return -1;
  }

  strcpy(userdomain, user);
  for (i = strlen(userdomain) - 1; i > 0; i--) {
    if (islower(userdomain[i])) {
      userdomain[i] = toupper(userdomain[i]);
    }
  }
  if (domain) {
    strcat(userdomain, domain);
  }

  ucs2_userdomain = unicode_alloc(userdomain);
  if (ucs2_userdomain == NULL) {
    return -1;
  }

  userdomain_len = strlen(userdomain);
  HMAC(EVP_md5(), ntlm_hash, 16,
      (unsigned char *)ucs2_userdomain, userdomain_len * 2,
      ntlmv2_hash, NULL);
  free(userdomain);
  free(ucs2_userdomain);

  return 0;
}

/* This is not the same temp as in MS-NLMP. This temp has an additional
 * 16 bytes at the start of the buffer.
 * Use &auth_data->val[16] if you want the temp from MS-NLMP
 */
static int
encode_temp(struct auth_data *auth_data, uint64_t t, char *client_challenge,
    char *server_challenge, char *server_name, int server_name_len)
{
  unsigned char sign[8] = {0x01, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};
  unsigned char zero[8] = {0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

  if (encoder(&zero, 8, auth_data) < 0) {
    return -1;
  }
  if (encoder(server_challenge, 8, auth_data) < 0) {
    return -1;
  }
  if (encoder(sign, 8, auth_data) < 0) {
    return -1;
  }
  if (encoder(&t, 8, auth_data) < 0) {
    return -1;
  }
  if (encoder(client_challenge, 8, auth_data) < 0) {
    return -1;
  }
  if (encoder(&zero, 4, auth_data) < 0) {
    return -1;
  }
  if (encoder(server_name, server_name_len, auth_data) < 0) {
    return -1;
  }
  if (encoder(&zero, 4, auth_data) < 0) {
    return -1;
  }

  return 0;
}

static int
encode_ntlm_auth(struct auth_data *auth_data,
    char *server_challenge)
{
  int ret = -1;
  unsigned char lm_buf[16];
  unsigned char *NTChallengeResponse_buf = NULL;
  unsigned char ResponseKeyNT[16];
  char *ucs2_domain = NULL;
  int domain_len;
  char *ucs2_user = NULL;
  int user_len;
  char *ucs2_workstation = NULL;
  int workstation_len;
  int NTChallengeResponse_len;
  unsigned char NTProofStr[16];
  unsigned char LMStr[16];
  uint64_t t;
  struct timeval tv;
  char *server_name_buf;
  int server_name_len;
  uint32_t u32;
  uint32_t server_neg_flags;
  unsigned char key_exch[SMB2_KEY_SIZE];

  tv.tv_sec = time(NULL);
  tv.tv_usec = 0;
  t = timeval_to_win(&tv);

  /*
     if (auth_data->password == NULL) {
     goto finished;
     }
     */

  /*
   * Generate Concatenation of(NTProofStr, temp)
   */
  if (NTOWFv2(auth_data->user, auth_data->password,
        auth_data->domain, ResponseKeyNT)
      < 0) {
    goto finished;
  }

  /* get the server neg flags */
  memcpy(&server_neg_flags, &auth_data->ntlm_buf[20], 4);
  server_neg_flags = le32toh(server_neg_flags);

  memcpy(&u32, &auth_data->ntlm_buf[40], 4);
  u32 = le32toh(u32);
  server_name_len = u32 >> 16;

  memcpy(&u32, &auth_data->ntlm_buf[44], 4);
  u32 = le32toh(u32);
  server_name_buf = (char *)&auth_data->ntlm_buf[u32];

  if (encode_temp(auth_data, t, (char *)auth_data->client_challenge,
        server_challenge, server_name_buf,
        server_name_len) < 0) {
    return -1;
  }

  HMAC(EVP_md5(), ResponseKeyNT, 16, &auth_data->buf[8], auth_data->len-8, NTProofStr, NULL);
  memcpy(auth_data->buf, NTProofStr, 16);

  NTChallengeResponse_buf = auth_data->buf;
  NTChallengeResponse_len = auth_data->len;
  auth_data->buf = NULL;
  auth_data->len = 0;
  auth_data->allocated = 0;

  /* get the NTLMv2 Key-Exchange Key
     For NTLMv2 - Key Exchange Key is the Session Base Key
     */
  HMAC(EVP_md5(), ResponseKeyNT, 16, NTProofStr, 16, key_exch, NULL);
  memcpy(auth_data->exported_session_key, key_exch, 16);

  /*
   * Generate AUTHENTICATE_MESSAGE
   */
  encoder("NTLMSSP", 8, auth_data);

  /* message type */
  u32 = htole32(AUTHENTICATION_MESSAGE);
  encoder(&u32, 4, auth_data);

  /* lm challenge response fields */
  memcpy(&lm_buf[0], server_challenge, 8);
  memcpy(&lm_buf[8], auth_data->client_challenge, 8);
  HMAC(EVP_md5(), ResponseKeyNT, 16, &lm_buf[0], 16, LMStr, NULL);
  u32 = htole32(0x00180018);
  encoder(&u32, 4, auth_data);
  u32 = 0;
  encoder(&u32, 4, auth_data);

  /* nt challenge response fields */
  u32 = htole32((NTChallengeResponse_len<<16)|
      NTChallengeResponse_len);
  encoder(&u32, 4, auth_data);
  u32 = 0;
  encoder(&u32, 4, auth_data);

  /* domain name fields */
  if (auth_data->domain) {
    domain_len = strlen(auth_data->domain);
    ucs2_domain = unicode_alloc(auth_data->domain);
    if (ucs2_domain == NULL) {
      goto finished;
    }
    u32 = domain_len * 2;
    u32 = htole32((u32 << 16) | u32);
    encoder(&u32, 4, auth_data);
    u32 = 0;
    encoder(&u32, 4, auth_data);
  } else {
    u32 = 0;
    encoder(&u32, 4, auth_data);
    encoder(&u32, 4, auth_data);
  }

  /* user name fields */
  user_len = strlen(auth_data->user);
  ucs2_user = unicode_alloc(auth_data->user);
  if (ucs2_user == NULL) {
    goto finished;
  }
  u32 = user_len * 2;
  u32 = htole32((u32 << 16) | u32);
  encoder(&u32, 4, auth_data);
  u32 = 0;
  encoder(&u32, 4, auth_data);

  /* workstation name fields */
  if (auth_data->workstation) {
    workstation_len = strlen(auth_data->workstation);
    ucs2_workstation = unicode_alloc(auth_data->workstation);
    if (ucs2_workstation == NULL) {
      goto finished;
    }
    u32 = workstation_len * 2;
    u32 = htole32((u32 << 16) | u32);
    encoder(&u32, 4, auth_data);
    u32 = 0;
    encoder(&u32, 4, auth_data);
  } else {
    u32 = 0;
    encoder(&u32, 4, auth_data);
    encoder(&u32, 4, auth_data);
  }

  /* encrypted random session key */
  u32 = 0;
  encoder(&u32, 4, auth_data);
  encoder(&u32, 4, auth_data);

  /* negotiate flags */
  u32 = htole32(NTLMSSP_NEGOTIATE_56|NTLMSSP_NEGOTIATE_128|
      NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY|
      //NTLMSSP_NEGOTIATE_ALWAYS_SIGN|
      NTLMSSP_NEGOTIATE_NTLM|
      //NTLMSSP_NEGOTIATE_SIGN|
      NTLMSSP_REQUEST_TARGET|NTLMSSP_NEGOTIATE_OEM|
      NTLMSSP_NEGOTIATE_UNICODE);
  encoder(&u32, 4, auth_data);

  /* append domain */
  u32 = htole32(auth_data->len);
  memcpy(&auth_data->buf[32], &u32, 4);
  if (ucs2_domain) {
    encoder(ucs2_domain, domain_len * 2, auth_data);
  }

  /* append user */
  u32 = htole32(auth_data->len);
  memcpy(&auth_data->buf[40], &u32, 4);
  encoder(ucs2_user, user_len * 2, auth_data);

  /* append workstation */
  u32 = htole32(auth_data->len);
  memcpy(&auth_data->buf[48], &u32, 4);
  if (ucs2_workstation) {
    encoder(ucs2_workstation, workstation_len * 2, auth_data);
  }

  /* append LMChallengeResponse */
  u32 = htole32(auth_data->len);
  memcpy(&auth_data->buf[16], &u32, 4);
  encoder(LMStr, 16, auth_data);
  encoder(auth_data->client_challenge, 8, auth_data);

  /* append NTChallengeResponse */
  u32 = htole32(auth_data->len);
  memcpy(&auth_data->buf[24], &u32, 4);
  encoder(NTChallengeResponse_buf, NTChallengeResponse_len, auth_data);

  ret = 0;
finished:
  free(ucs2_domain);
  free(ucs2_user);
  free(ucs2_workstation);
  free(NTChallengeResponse_buf);

  return ret;
}

int
ntlmssp_generate_blob(struct auth_data *auth_data,
    unsigned char *input_buf, int input_len,
    unsigned char **output_buf, uint16_t *output_len)
{
  free(auth_data->buf);
  auth_data->buf = NULL;
  auth_data->len = 0;
  auth_data->allocated = 0;

  if (input_buf == NULL) {
    ntlm_negotiate_message(auth_data);
  } else {
    if (ntlm_challenge_message(auth_data, input_buf,
          input_len) < 0) {
      return -1;
    }
    if (encode_ntlm_auth(auth_data,
          (char *)&auth_data->ntlm_buf[24]) < 0) {
      return -1;
    }
  }

  *output_buf = auth_data->buf;
  *output_len = auth_data->len;

  return 0;
}

int
ntlmssp_get_session_key(struct auth_data *auth,
    uint8_t **key,
    uint8_t *key_size)
{
  uint8_t *mkey = NULL;

  if (auth == NULL || key == NULL || key_size == NULL) {
    return -1;
  }

  mkey = (uint8_t *) malloc(SMB2_KEY_SIZE);
  if (mkey == NULL) {
    return -1;
  }
  memcpy(mkey, auth->exported_session_key, SMB2_KEY_SIZE);

  *key = mkey;
  *key_size = SMB2_KEY_SIZE;

  return 0;
}

#endif /* if HAVE_OPENSSL */
