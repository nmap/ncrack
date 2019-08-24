
/***************************************************************************
 * crypto.cc -- crypto functions like LM, NTLM etc reside here             *
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
#include "crypto.h"

#if HAVE_OPENSSL

#include <openssl/des.h>
#include <openssl/hmac.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#ifndef WIN32
  #include <stdint.h>
#endif
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
  free(unicode);
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



/*
 * Uses the RSA algorithm to encrypt the input into the output.
 */
void rsa_encrypt(uint8_t *input, uint8_t *output, int length,
    uint8_t *mod_bin, uint32_t mod_size, uint8_t *exp_bin)
{
  uint8_t input_temp[256];
  BIGNUM *val1 = BN_new(), *val2 = BN_new(), *bn_mod = BN_new(), *bn_exp = BN_new();

  BN_CTX *bn_ctx = BN_CTX_new();
  memcpy(input_temp, input, length);
  mem_reverse(input_temp, length);
  mem_reverse(mod_bin, mod_size);
  mem_reverse(exp_bin, 4);
  BN_bin2bn(input_temp, length, val1);
  BN_bin2bn(exp_bin, 4, bn_exp);
  BN_bin2bn(mod_bin, mod_size, bn_mod);
  BN_mod_exp(val2, val1, bn_exp, bn_mod, bn_ctx);
  int output_length = BN_bn2bin(val2, output);
  mem_reverse(output, output_length);
  if (output_length < (int) mod_size)
    memset(output + output_length, 0, mod_size - output_length);

  BN_CTX_free(bn_ctx);
  BN_clear_free(val1);
  BN_free(val2);
  BN_free(bn_mod);
  BN_free(bn_exp);

}


/* 
 * Uses MD5 and SHA1 hash functions, using 3 salts to compute a message
 * digest (saved into 'output')
 */
void
hash48(uint8_t *output, uint8_t *input, uint8_t salt, uint8_t *sha_salt1,
    uint8_t *sha_salt2)
{
  SHA_CTX sha1_ctx;
  MD5_CTX md5_ctx;
  u_char padding[4];
  u_char sig[20];

  for (int i = 0; i < 3; i++) {
    memset(padding, salt + i, i +1);

    SHA1_Init(&sha1_ctx);
    MD5_Init(&md5_ctx);

    SHA1_Update(&sha1_ctx, padding, i + 1);
    SHA1_Update(&sha1_ctx, input, 48);
    SHA1_Update(&sha1_ctx, sha_salt1, 32);
    SHA1_Update(&sha1_ctx, sha_salt2, 32);
    SHA1_Final(sig, &sha1_ctx);

    MD5_Update(&md5_ctx, input, 48);
    MD5_Update(&md5_ctx, sig, 20);
    MD5_Final(&output[i*16], &md5_ctx);
  }

}

/* 
 * MD5 crypt 'input' into 'output' by using 2 salts
 */
void
hash16(uint8_t *output, uint8_t *input, uint8_t *md5_salt1, uint8_t *md5_salt2)
{
  MD5_CTX md5_ctx;
  MD5_Init(&md5_ctx);
  MD5_Update(&md5_ctx, input, 16);
  MD5_Update(&md5_ctx, md5_salt1, 32);
  MD5_Update(&md5_ctx, md5_salt2, 32);
  MD5_Final(output, &md5_ctx);
}


#endif /* HAVE_OPENSSL */


/*
 * This is D3DES (V5.09) by Richard Outerbridge with the double and
 * triple-length support removed for use in VNC.  Also the bytebit[] array
 * has been reversed so that the most significant bit in each byte of the
 * key is ignored, not the least significant.
 *
 * These changes are:
 *  Copyright (C) 1999 AT&T Laboratories Cambridge.  All Rights Reserved.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

/* D3DES (V5.09) -
 *
 * A portable, public domain, version of the Data Encryption Standard.
 *
 * Written with Symantec's THINK (Lightspeed) C by Richard Outerbridge.
 * Thanks to: Dan Hoey for his excellent Initial and Inverse permutation
 * code;  Jim Gillogly & Phil Karn for the DES key schedule code; Dennis
 * Ferguson, Eric Young and Dana How for comparing notes; and Ray Lau,
 * for humouring me on.
 *
 * Copyright (c) 1988,1989,1990,1991,1992 by Richard Outerbridge.
 * (GEnie : OUTER; CIS : [71755,204]) Graven Imagery, 1992.
 */

static void scrunch(unsigned char *, unsigned long *);
static void unscrun(unsigned long *, unsigned char *);
static void desfunc(unsigned long *, unsigned long *);
static void cookey(unsigned long *);

static unsigned long KnL[32] = { 0L };
//static unsigned long KnR[32] = { 0L };
//static unsigned long Kn3[32] = { 0L };
/*static unsigned char Df_Key[24] = {
	0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
	0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
	0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67 };
*/

static unsigned short bytebit[8]	= {
	01, 02, 04, 010, 020, 040, 0100, 0200 };

static unsigned long bigbyte[24] = {
	0x800000L,	0x400000L,	0x200000L,	0x100000L,
	0x80000L,	0x40000L,	0x20000L,	0x10000L,
	0x8000L,	0x4000L,	0x2000L,	0x1000L,
	0x800L, 	0x400L, 	0x200L, 	0x100L,
	0x80L,		0x40L,		0x20L,		0x10L,
	0x8L,		0x4L,		0x2L,		0x1L	};

/* Use the key schedule specified in the Standard (ANSI X3.92-1981). */

static unsigned char pc1[56] = {
	56, 48, 40, 32, 24, 16,  8,	 0, 57, 49, 41, 33, 25, 17,
	 9,  1, 58, 50, 42, 34, 26,	18, 10,  2, 59, 51, 43, 35,
	62, 54, 46, 38, 30, 22, 14,	 6, 61, 53, 45, 37, 29, 21,
	13,  5, 60, 52, 44, 36, 28,	20, 12,  4, 27, 19, 11,  3 };

static unsigned char totrot[16] = {
	1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28 };

static unsigned char pc2[48] = {
	13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
	22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
	40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
	43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31 };

//void deskey(key, edf)	/* Thanks to James Gillogly & Phil Karn! */
//unsigned char *key;
//int edf;
void deskey(		/* Thanks to James Gillogly & Phil Karn! */
unsigned char *key,
int edf
)
{
	register int i, j, l, m, n;
	unsigned char pc1m[56], pcr[56];
	unsigned long kn[32];

	for ( j = 0; j < 56; j++ ) {
		l = pc1[j];
		m = l & 07;
		pc1m[j] = (key[l >> 3] & bytebit[m]) ? 1 : 0;
		}
	for( i = 0; i < 16; i++ ) {
		if( edf == DE1 ) m = (15 - i) << 1;
		else m = i << 1;
		n = m + 1;
		kn[m] = kn[n] = 0L;
		for( j = 0; j < 28; j++ ) {
			l = j + totrot[i];
			if( l < 28 ) pcr[j] = pc1m[l];
			else pcr[j] = pc1m[l - 28];
			}
		for( j = 28; j < 56; j++ ) {
		    l = j + totrot[i];
		    if( l < 56 ) pcr[j] = pc1m[l];
		    else pcr[j] = pc1m[l - 28];
		    }
		for( j = 0; j < 24; j++ ) {
			if( pcr[pc2[j]] ) kn[m] |= bigbyte[j];
			if( pcr[pc2[j+24]] ) kn[n] |= bigbyte[j];
			}
		}
	cookey(kn);
	return;
	}

//static void cookey(raw1)
//register unsigned long *raw1;
static void cookey(
register unsigned long *raw1
)
{
	register unsigned long *cook, *raw0;
	unsigned long dough[32];
	register int i;

	cook = dough;
	for( i = 0; i < 16; i++, raw1++ ) {
		raw0 = raw1++;
		*cook	 = (*raw0 & 0x00fc0000L) << 6;
		*cook	|= (*raw0 & 0x00000fc0L) << 10;
		*cook	|= (*raw1 & 0x00fc0000L) >> 10;
		*cook++ |= (*raw1 & 0x00000fc0L) >> 6;
		*cook	 = (*raw0 & 0x0003f000L) << 12;
		*cook	|= (*raw0 & 0x0000003fL) << 16;
		*cook	|= (*raw1 & 0x0003f000L) >> 4;
		*cook++ |= (*raw1 & 0x0000003fL);
		}
	usekey(dough);
	return;
	}

//void cpkey(into)
//register unsigned long *into;
void cpkey(
register unsigned long *into
)
{
	register unsigned long *from, *endp;

	from = KnL, endp = &KnL[32];
	while( from < endp ) *into++ = *from++;
	return;
	}

//void usekey(from)
//register unsigned long *from;
void usekey(
register unsigned long *from
)
{
	register unsigned long *to, *endp;

	to = KnL, endp = &KnL[32];
	while( to < endp ) *to++ = *from++;
	return;
	}

//void des(inblock, outblock)
//unsigned char *inblock, *outblock;
void des(
unsigned char *inblock, unsigned char *outblock
)
{
	unsigned long work[2];

	scrunch(inblock, work);
	desfunc(work, KnL);
	unscrun(work, outblock);
	return;
	}

//static void scrunch(outof, into)
//register unsigned char *outof;
//register unsigned long *into;
static void scrunch(
register unsigned char *outof,
register unsigned long *into
)
{
	*into	 = (*outof++ & 0xffL) << 24;
	*into	|= (*outof++ & 0xffL) << 16;
	*into	|= (*outof++ & 0xffL) << 8;
	*into++ |= (*outof++ & 0xffL);
	*into	 = (*outof++ & 0xffL) << 24;
	*into	|= (*outof++ & 0xffL) << 16;
	*into	|= (*outof++ & 0xffL) << 8;
	*into	|= (*outof   & 0xffL);
	return;
	}

//static void unscrun(outof, into)
//register unsigned long *outof;
//register unsigned char *into;
static void unscrun(
register unsigned long *outof,
register unsigned char *into
)
{
	*into++ = (*outof >> 24) & 0xffL;
	*into++ = (*outof >> 16) & 0xffL;
	*into++ = (*outof >>  8) & 0xffL;
	*into++ =  *outof++	 & 0xffL;
	*into++ = (*outof >> 24) & 0xffL;
	*into++ = (*outof >> 16) & 0xffL;
	*into++ = (*outof >>  8) & 0xffL;
	*into	=  *outof	 & 0xffL;
	return;
	}

static unsigned long SP1[64] = {
	0x01010400L, 0x00000000L, 0x00010000L, 0x01010404L,
	0x01010004L, 0x00010404L, 0x00000004L, 0x00010000L,
	0x00000400L, 0x01010400L, 0x01010404L, 0x00000400L,
	0x01000404L, 0x01010004L, 0x01000000L, 0x00000004L,
	0x00000404L, 0x01000400L, 0x01000400L, 0x00010400L,
	0x00010400L, 0x01010000L, 0x01010000L, 0x01000404L,
	0x00010004L, 0x01000004L, 0x01000004L, 0x00010004L,
	0x00000000L, 0x00000404L, 0x00010404L, 0x01000000L,
	0x00010000L, 0x01010404L, 0x00000004L, 0x01010000L,
	0x01010400L, 0x01000000L, 0x01000000L, 0x00000400L,
	0x01010004L, 0x00010000L, 0x00010400L, 0x01000004L,
	0x00000400L, 0x00000004L, 0x01000404L, 0x00010404L,
	0x01010404L, 0x00010004L, 0x01010000L, 0x01000404L,
	0x01000004L, 0x00000404L, 0x00010404L, 0x01010400L,
	0x00000404L, 0x01000400L, 0x01000400L, 0x00000000L,
	0x00010004L, 0x00010400L, 0x00000000L, 0x01010004L };

static unsigned long SP2[64] = {
	0x80108020L, 0x80008000L, 0x00008000L, 0x00108020L,
	0x00100000L, 0x00000020L, 0x80100020L, 0x80008020L,
	0x80000020L, 0x80108020L, 0x80108000L, 0x80000000L,
	0x80008000L, 0x00100000L, 0x00000020L, 0x80100020L,
	0x00108000L, 0x00100020L, 0x80008020L, 0x00000000L,
	0x80000000L, 0x00008000L, 0x00108020L, 0x80100000L,
	0x00100020L, 0x80000020L, 0x00000000L, 0x00108000L,
	0x00008020L, 0x80108000L, 0x80100000L, 0x00008020L,
	0x00000000L, 0x00108020L, 0x80100020L, 0x00100000L,
	0x80008020L, 0x80100000L, 0x80108000L, 0x00008000L,
	0x80100000L, 0x80008000L, 0x00000020L, 0x80108020L,
	0x00108020L, 0x00000020L, 0x00008000L, 0x80000000L,
	0x00008020L, 0x80108000L, 0x00100000L, 0x80000020L,
	0x00100020L, 0x80008020L, 0x80000020L, 0x00100020L,
	0x00108000L, 0x00000000L, 0x80008000L, 0x00008020L,
	0x80000000L, 0x80100020L, 0x80108020L, 0x00108000L };

static unsigned long SP3[64] = {
	0x00000208L, 0x08020200L, 0x00000000L, 0x08020008L,
	0x08000200L, 0x00000000L, 0x00020208L, 0x08000200L,
	0x00020008L, 0x08000008L, 0x08000008L, 0x00020000L,
	0x08020208L, 0x00020008L, 0x08020000L, 0x00000208L,
	0x08000000L, 0x00000008L, 0x08020200L, 0x00000200L,
	0x00020200L, 0x08020000L, 0x08020008L, 0x00020208L,
	0x08000208L, 0x00020200L, 0x00020000L, 0x08000208L,
	0x00000008L, 0x08020208L, 0x00000200L, 0x08000000L,
	0x08020200L, 0x08000000L, 0x00020008L, 0x00000208L,
	0x00020000L, 0x08020200L, 0x08000200L, 0x00000000L,
	0x00000200L, 0x00020008L, 0x08020208L, 0x08000200L,
	0x08000008L, 0x00000200L, 0x00000000L, 0x08020008L,
	0x08000208L, 0x00020000L, 0x08000000L, 0x08020208L,
	0x00000008L, 0x00020208L, 0x00020200L, 0x08000008L,
	0x08020000L, 0x08000208L, 0x00000208L, 0x08020000L,
	0x00020208L, 0x00000008L, 0x08020008L, 0x00020200L };

static unsigned long SP4[64] = {
	0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
	0x00802080L, 0x00800081L, 0x00800001L, 0x00002001L,
	0x00000000L, 0x00802000L, 0x00802000L, 0x00802081L,
	0x00000081L, 0x00000000L, 0x00800080L, 0x00800001L,
	0x00000001L, 0x00002000L, 0x00800000L, 0x00802001L,
	0x00000080L, 0x00800000L, 0x00002001L, 0x00002080L,
	0x00800081L, 0x00000001L, 0x00002080L, 0x00800080L,
	0x00002000L, 0x00802080L, 0x00802081L, 0x00000081L,
	0x00800080L, 0x00800001L, 0x00802000L, 0x00802081L,
	0x00000081L, 0x00000000L, 0x00000000L, 0x00802000L,
	0x00002080L, 0x00800080L, 0x00800081L, 0x00000001L,
	0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
	0x00802081L, 0x00000081L, 0x00000001L, 0x00002000L,
	0x00800001L, 0x00002001L, 0x00802080L, 0x00800081L,
	0x00002001L, 0x00002080L, 0x00800000L, 0x00802001L,
	0x00000080L, 0x00800000L, 0x00002000L, 0x00802080L };

static unsigned long SP5[64] = {
	0x00000100L, 0x02080100L, 0x02080000L, 0x42000100L,
	0x00080000L, 0x00000100L, 0x40000000L, 0x02080000L,
	0x40080100L, 0x00080000L, 0x02000100L, 0x40080100L,
	0x42000100L, 0x42080000L, 0x00080100L, 0x40000000L,
	0x02000000L, 0x40080000L, 0x40080000L, 0x00000000L,
	0x40000100L, 0x42080100L, 0x42080100L, 0x02000100L,
	0x42080000L, 0x40000100L, 0x00000000L, 0x42000000L,
	0x02080100L, 0x02000000L, 0x42000000L, 0x00080100L,
	0x00080000L, 0x42000100L, 0x00000100L, 0x02000000L,
	0x40000000L, 0x02080000L, 0x42000100L, 0x40080100L,
	0x02000100L, 0x40000000L, 0x42080000L, 0x02080100L,
	0x40080100L, 0x00000100L, 0x02000000L, 0x42080000L,
	0x42080100L, 0x00080100L, 0x42000000L, 0x42080100L,
	0x02080000L, 0x00000000L, 0x40080000L, 0x42000000L,
	0x00080100L, 0x02000100L, 0x40000100L, 0x00080000L,
	0x00000000L, 0x40080000L, 0x02080100L, 0x40000100L };

static unsigned long SP6[64] = {
	0x20000010L, 0x20400000L, 0x00004000L, 0x20404010L,
	0x20400000L, 0x00000010L, 0x20404010L, 0x00400000L,
	0x20004000L, 0x00404010L, 0x00400000L, 0x20000010L,
	0x00400010L, 0x20004000L, 0x20000000L, 0x00004010L,
	0x00000000L, 0x00400010L, 0x20004010L, 0x00004000L,
	0x00404000L, 0x20004010L, 0x00000010L, 0x20400010L,
	0x20400010L, 0x00000000L, 0x00404010L, 0x20404000L,
	0x00004010L, 0x00404000L, 0x20404000L, 0x20000000L,
	0x20004000L, 0x00000010L, 0x20400010L, 0x00404000L,
	0x20404010L, 0x00400000L, 0x00004010L, 0x20000010L,
	0x00400000L, 0x20004000L, 0x20000000L, 0x00004010L,
	0x20000010L, 0x20404010L, 0x00404000L, 0x20400000L,
	0x00404010L, 0x20404000L, 0x00000000L, 0x20400010L,
	0x00000010L, 0x00004000L, 0x20400000L, 0x00404010L,
	0x00004000L, 0x00400010L, 0x20004010L, 0x00000000L,
	0x20404000L, 0x20000000L, 0x00400010L, 0x20004010L };

static unsigned long SP7[64] = {
	0x00200000L, 0x04200002L, 0x04000802L, 0x00000000L,
	0x00000800L, 0x04000802L, 0x00200802L, 0x04200800L,
	0x04200802L, 0x00200000L, 0x00000000L, 0x04000002L,
	0x00000002L, 0x04000000L, 0x04200002L, 0x00000802L,
	0x04000800L, 0x00200802L, 0x00200002L, 0x04000800L,
	0x04000002L, 0x04200000L, 0x04200800L, 0x00200002L,
	0x04200000L, 0x00000800L, 0x00000802L, 0x04200802L,
	0x00200800L, 0x00000002L, 0x04000000L, 0x00200800L,
	0x04000000L, 0x00200800L, 0x00200000L, 0x04000802L,
	0x04000802L, 0x04200002L, 0x04200002L, 0x00000002L,
	0x00200002L, 0x04000000L, 0x04000800L, 0x00200000L,
	0x04200800L, 0x00000802L, 0x00200802L, 0x04200800L,
	0x00000802L, 0x04000002L, 0x04200802L, 0x04200000L,
	0x00200800L, 0x00000000L, 0x00000002L, 0x04200802L,
	0x00000000L, 0x00200802L, 0x04200000L, 0x00000800L,
	0x04000002L, 0x04000800L, 0x00000800L, 0x00200002L };

static unsigned long SP8[64] = {
	0x10001040L, 0x00001000L, 0x00040000L, 0x10041040L,
	0x10000000L, 0x10001040L, 0x00000040L, 0x10000000L,
	0x00040040L, 0x10040000L, 0x10041040L, 0x00041000L,
	0x10041000L, 0x00041040L, 0x00001000L, 0x00000040L,
	0x10040000L, 0x10000040L, 0x10001000L, 0x00001040L,
	0x00041000L, 0x00040040L, 0x10040040L, 0x10041000L,
	0x00001040L, 0x00000000L, 0x00000000L, 0x10040040L,
	0x10000040L, 0x10001000L, 0x00041040L, 0x00040000L,
	0x00041040L, 0x00040000L, 0x10041000L, 0x00001000L,
	0x00000040L, 0x10040040L, 0x00001000L, 0x00041040L,
	0x10001000L, 0x00000040L, 0x10000040L, 0x10040000L,
	0x10040040L, 0x10000000L, 0x00040000L, 0x10001040L,
	0x00000000L, 0x10041040L, 0x00040040L, 0x10000040L,
	0x10040000L, 0x10001000L, 0x10001040L, 0x00000000L,
	0x10041040L, 0x00041000L, 0x00041000L, 0x00001040L,
	0x00001040L, 0x00040040L, 0x10000000L, 0x10041000L };

//static void desfunc(block, keys)
//register unsigned long *block, *keys;
static void desfunc(
register unsigned long *block, register unsigned long *keys
)
{
	register unsigned long fval, work, right, leftt;
	register int round;

	leftt = block[0];
	right = block[1];
	work = ((leftt >> 4) ^ right) & 0x0f0f0f0fL;
	right ^= work;
	leftt ^= (work << 4);
	work = ((leftt >> 16) ^ right) & 0x0000ffffL;
	right ^= work;
	leftt ^= (work << 16);
	work = ((right >> 2) ^ leftt) & 0x33333333L;
	leftt ^= work;
	right ^= (work << 2);
	work = ((right >> 8) ^ leftt) & 0x00ff00ffL;
	leftt ^= work;
	right ^= (work << 8);
	right = ((right << 1) | ((right >> 31) & 1L)) & 0xffffffffL;
	work = (leftt ^ right) & 0xaaaaaaaaL;
	leftt ^= work;
	right ^= work;
	leftt = ((leftt << 1) | ((leftt >> 31) & 1L)) & 0xffffffffL;

	for( round = 0; round < 8; round++ ) {
		work  = (right << 28) | (right >> 4);
		work ^= *keys++;
		fval  = SP7[ work		 & 0x3fL];
		fval |= SP5[(work >>  8) & 0x3fL];
		fval |= SP3[(work >> 16) & 0x3fL];
		fval |= SP1[(work >> 24) & 0x3fL];
		work  = right ^ *keys++;
		fval |= SP8[ work		 & 0x3fL];
		fval |= SP6[(work >>  8) & 0x3fL];
		fval |= SP4[(work >> 16) & 0x3fL];
		fval |= SP2[(work >> 24) & 0x3fL];
		leftt ^= fval;
		work  = (leftt << 28) | (leftt >> 4);
		work ^= *keys++;
		fval  = SP7[ work		 & 0x3fL];
		fval |= SP5[(work >>  8) & 0x3fL];
		fval |= SP3[(work >> 16) & 0x3fL];
		fval |= SP1[(work >> 24) & 0x3fL];
		work  = leftt ^ *keys++;
		fval |= SP8[ work		 & 0x3fL];
		fval |= SP6[(work >>  8) & 0x3fL];
		fval |= SP4[(work >> 16) & 0x3fL];
		fval |= SP2[(work >> 24) & 0x3fL];
		right ^= fval;
		}

	right = (right << 31) | (right >> 1);
	work = (leftt ^ right) & 0xaaaaaaaaL;
	leftt ^= work;
	right ^= work;
	leftt = (leftt << 31) | (leftt >> 1);
	work = ((leftt >> 8) ^ right) & 0x00ff00ffL;
	right ^= work;
	leftt ^= (work << 8);
	work = ((leftt >> 2) ^ right) & 0x33333333L;
	right ^= work;
	leftt ^= (work << 2);
	work = ((right >> 16) ^ leftt) & 0x0000ffffL;
	leftt ^= work;
	right ^= (work << 16);
	work = ((right >> 4) ^ leftt) & 0x0f0f0f0fL;
	leftt ^= work;
	right ^= (work << 4);
	*block++ = right;
	*block = leftt;
	return;
	}

/* Validation sets:
 *
 * Single-length key, single-length plaintext -
 * Key	  : 0123 4567 89ab cdef
 * Plain  : 0123 4567 89ab cde7
 * Cipher : c957 4425 6a5e d31d
 *
 * Double-length key, single-length plaintext -
 * Key	  : 0123 4567 89ab cdef fedc ba98 7654 3210
 * Plain  : 0123 4567 89ab cde7
 * Cipher : 7f1d 0a77 826b 8aff
 *
 * Double-length key, double-length plaintext -
 * Key	  : 0123 4567 89ab cdef fedc ba98 7654 3210
 * Plain  : 0123 4567 89ab cdef 0123 4567 89ab cdff
 * Cipher : 27a0 8440 406a df60 278f 47cf 42d6 15d7
 *
 * Triple-length key, single-length plaintext -
 * Key	  : 0123 4567 89ab cdef fedc ba98 7654 3210 89ab cdef 0123 4567
 * Plain  : 0123 4567 89ab cde7
 * Cipher : de0b 7c06 ae5e 0ed5
 *
 * Triple-length key, double-length plaintext -
 * Key	  : 0123 4567 89ab cdef fedc ba98 7654 3210 89ab cdef 0123 4567
 * Plain  : 0123 4567 89ab cdef 0123 4567 89ab cdff
 * Cipher : ad0d 1b30 ac17 cf07 0ed1 1c63 81e4 4de5
 *
 * d3des V5.0a rwo 9208.07 18:44 Graven Imagery
 **********************************************************************/

