
/***************************************************************************
 * crypto.cc -- crypto functions like LM, NTLM etc reside here             *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2010 Insecure.Com LLC. Nmap is    *
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
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
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

//#if HAVE_OPENSSL

#include <openssl/des.h>
#include <openssl/hmac.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#ifndef WIN32
  #include <stdint.h>
#endif
#include "crypto.h"
#include "ncrack_error.h"
#include "utils.h"


static void password_to_key(const uint8_t password[7], uint8_t key[8])
{
  /* make room for parity bits */
  key[0] =                        (password[0] >> 0);
  key[1] = ((password[0]) << 7) | (password[1] >> 1);
  key[2] = ((password[1]) << 6) | (password[2] >> 2);
  key[3] = ((password[2]) << 5) | (password[3] >> 3);
  key[4] = ((password[3]) << 4) | (password[4] >> 4);
  key[5] = ((password[4]) << 3) | (password[5] >> 5);
  key[6] = ((password[5]) << 2) | (password[6] >> 6);
  key[7] = ((password[6]) << 1);
}


static void
des(const uint8_t password[7], const uint8_t data[8], uint8_t result[])
{
  DES_cblock key;
  DES_key_schedule schedule;

  password_to_key(password, key);

  DES_set_odd_parity(&key);
  DES_set_key_unchecked(&key, &schedule);
  DES_ecb_encrypt((DES_cblock*)data, (DES_cblock*)result, &schedule, DES_ENCRYPT);
}



/* Generate the Lanman v1 hash (LMv1). The generated hash is incredibly easy to
 * reverse, because the input is padded or truncated to 14 characters, then 
 * split into two 7-character strings. Each of these strings are used as a key
 * to encrypt the string, "KGS!@#$%" in DES. Because the keys are no longer
 * than 7-characters long, it's pretty trivial to bruteforce them.
 */
void
lm_create_hash(const char *password, uint8_t result[16])
{
  size_t           i;
  uint8_t          password1[7];
  uint8_t          password2[7];
  uint8_t          kgs[] = "KGS!@#$%";
  uint8_t          hash1[8];
  uint8_t          hash2[8];

  /* Initialize passwords to NULLs. */
  memset(password1, 0, 7);
  memset(password2, 0, 7);

  /* Copy passwords over, convert to uppercase, they're automatically padded with NULLs. */
  for (i = 0; i < 7; i++) {
    if (i < strlen(password))
      password1[i] = toupper(password[i]);
    if (i + 7 < strlen(password))
      password2[i] = toupper(password[i + 7]);
  }

  /* Do the encryption. */
  des(password1, kgs, hash1);
  des(password2, kgs, hash2);

  /* Copy the result to the return parameter. */
  memcpy(result + 0, hash1, 8);
  memcpy(result + 8, hash2, 8);
}


/* Create the Lanman response to send back to the server. To do this, the
 * Lanman password is padded to 21 characters and split into three
 * 7-character strings. Each of those strings is used as a key to encrypt
 * the server challenge. The three encrypted strings are concatenated and
 * returned.
 */
void
lm_create_response(const uint8_t lanman[16], const uint8_t challenge[8], uint8_t result[24])
{
  size_t i;

  uint8_t password1[7];
  uint8_t password2[7];
  uint8_t password3[7];

  uint8_t hash1[8];
  uint8_t hash2[8];
  uint8_t hash3[8];

  /* Initialize passwords. */
  memset(password1, 0, 7);
  memset(password2, 0, 7);
  memset(password3, 0, 7);

  /* Copy data over. */
  for (i = 0; i < 7; i++) {
    password1[i] = lanman[i];
    password2[i] = lanman[i + 7];
    password3[i] = (i + 14 < 16) ? lanman[i + 14] : 0;
  }

  /* do the encryption. */
  des(password1, challenge, hash1);
  des(password2, challenge, hash2);
  des(password3, challenge, hash3);

  /* Copy the result to the return parameter. */
  memcpy(result + 0,  hash1, 8);
  memcpy(result + 8,  hash2, 8);
  memcpy(result + 16, hash3, 8);
}



/* Generate the NTLMv1 hash. This hash is quite a bit better than LMv1, and is
 * far easier to generate. Basically, it's the MD4 of the Unicode password.
 */
void
ntlm_create_hash(const char *password, uint8_t result[16])
{
  char *unicode = unicode_alloc(password);
  MD4_CTX ntlm;

  if(!unicode)
    fatal("%s non unicode", __func__);

  MD4_Init(&ntlm);
  MD4_Update(&ntlm, unicode, strlen(password) * 2);
  MD4_Final(result, &ntlm);
}



/* Create the NTLM response to send back to the server. This is actually done
 * the exact same way as the Lanman hash, so we call the Lanman function.
 */
void
ntlm_create_response(const uint8_t ntlm[16], const uint8_t challenge[8],
    uint8_t result[24])
{
  lm_create_response(ntlm, challenge, result);
}



/* Create the NTLMv2 hash, which is based on the NTLMv1 hash (for easy
 * upgrading), the username, and the domain. Essentially, the NTLM hash
 * is used as a HMAC-MD5 key, which is used to hash the unicode domain
 * concatenated with the unicode username. 
 */
void
ntlmv2_create_hash(const uint8_t ntlm[16], const char *username,
    const char *domain, uint8_t hash[16])
{
  /* Convert username to unicode. */
  size_t username_length = strlen(username);
  size_t domain_length   = strlen(domain);
  char    *combined;
  uint8_t *combined_unicode;

  /* Probably shouldn't do this, but this is all prototype so eh? */
  if (username_length > 256 || domain_length > 256)
    fatal("username or domain too long.");

  /* Combine the username and domain into one string. */
  combined = (char *)safe_malloc(username_length + domain_length + 1);
  memset(combined, 0, username_length + domain_length + 1);

  memcpy(combined,                   username, username_length);
  memcpy(combined + username_length, domain,   domain_length);

  /* Convert to Unicode. */
  combined_unicode = (uint8_t*)unicode_alloc_upper(combined);
  if (!combined_unicode)
    fatal("Out of memory");

  /* Perform the Hmac-MD5. */
  HMAC(EVP_md5(), ntlm, 16, combined_unicode, (username_length + domain_length) * 2, hash, NULL);

  free(combined_unicode);
  free(combined);
}



/* Create the LMv2 response, which can be sent back to the server. This is
 * identical to the NTLMv2 function, except that it uses an 8-byte client
 * challenge. The reason for LMv2 is a long and twisted story. Well,
 * not really. The reason is basically that the v1 hashes are always 24-bytes,
 * and some servers expect 24 bytes, but the NTLMv2 hash is more than 24 bytes.
 * So, the only way to keep pass-through compatibility was to have a v2-hash
 * that was guaranteed to be 24 bytes. So LMv1 was born: it has a 16-byte hash
 * followed by the 8-byte client challenge, for a total of 24 bytes. 
 */
void
lmv2_create_response(const uint8_t ntlm[16], const char *username,
    const char *domain, const uint8_t challenge[8], uint8_t *result,
    uint8_t *result_size)
{
  ntlmv2_create_response(ntlm, username, domain, challenge, result, result_size);
}



/* Create the NTLMv2 response, which can be sent back to the server. This is
 * done by using the HMAC-MD5 algorithm with the NTLMv2 hash as a key, and
 * the server challenge concatenated with the client challenge for the data.
 * The resulting hash is concatenated with the client challenge and returned.
 */
void
ntlmv2_create_response(const uint8_t ntlm[16], const char *username,
    const char *domain, const uint8_t challenge[8], uint8_t *result,
    uint8_t *result_size)
{
  size_t  i;
  uint8_t v2hash[16];
  uint8_t *data;

  uint8_t blip[8];
  uint8_t *blob = NULL;
  uint8_t blob_length = 0;


  /* Create the 'blip'. TODO: Do I care if this is random? */
  for (i = 0; i < 8; i++)
    blip[i] = i;

  if (*result_size < 24)
  {
    /* Result can't be less than 24 bytes. */
    fatal("Result size is too low!");
  } else if (*result_size == 24) {
    /* If they're looking for 24 bytes, then it's just the raw blob. */
    blob = (uint8_t *)safe_malloc(8);
    memcpy(blob, blip, 8);
    blob_length = 8;
  } else {
    blob = (uint8_t *)safe_malloc(24);
    for (i = 0; i < 24; i++)
      blob[i] = i;
    blob_length = 24;
  }

  /* Allocate room enough for the server challenge and the client blob. */
  data = (uint8_t *)safe_malloc(8 + blob_length);

  /* Copy the challenge into the memory. */
  memcpy(data, challenge, 8);
  /* Copy the blob into the memory. */
  memcpy(data + 8, blob, blob_length);

  /* Get the v2 hash. */
  ntlmv2_create_hash(ntlm, username, domain, v2hash);

  /* Generate the v2 response. */
  HMAC(EVP_md5(), v2hash, 16, data, 8 + blob_length, result, NULL);

  /* Copy the blob onto the end of the v2 response. */
  memcpy(result + 16, blob, blob_length);

  /* Store the result size. */
  *result_size = blob_length + 16;

  /* Finally, free up some memory. */
  free(data);
  free(blob);
}

//#endif /* HAVE_OPENSSL */
