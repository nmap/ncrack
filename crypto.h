
/***************************************************************************
 * crypto.h -- crypto functions like LM, NTLM etc reside here              *
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

#ifndef CRYPTO_H
#define CRYPTO_H

#ifdef WIN32
  #include "winfix.h"
#endif


/* Generate the Lanman v1 hash (LMv1). The generated hash is incredibly easy to
 * reverse, because the input is padded or truncated to 14 characters, then 
 * split into two 7-character strings. Each of these strings are used as a key
 * to encrypt the string, "KGS!@#$%" in DES. Because the keys are no longer
 * than 7-characters long, it's pretty trivial to bruteforce them.
 */
void lm_create_hash(const char *password, uint8_t result[16]);


/* Create the Lanman response to send back to the server. To do this, the
 * Lanman password is padded to 21 characters and split into three
 * 7-character strings. Each of those strings is used as a key to encrypt
 * the server challenge. The three encrypted strings are concatenated and
 * returned.
 */
void lm_create_response(const uint8_t lanman[16], const uint8_t challenge[8],
    uint8_t result[24]);


/* Generate the NTLMv1 hash. This hash is quite a bit better than LMv1, and is
 * far easier to generate. Basically, it's the MD4 of the Unicode password.
 */
void ntlm_create_hash(const char *password, uint8_t result[16]);


/* Create the NTLM response to send back to the server. This is actually done
 * the exact same way as the Lanman hash, so we call the Lanman function.
 */
void ntlm_create_response(const uint8_t ntlm[16], const uint8_t challenge[8],
    uint8_t result[24]);


/* Create the LMv2 response, which can be sent back to the server. This is
 * identical to the NTLMv2 function, except that it uses an 8-byte client
 * challenge. The reason for LMv2 is a long and twisted story. Well,
 * not really. The reason is basically that the v1 hashes are always 24-bytes,
 * and some servers expect 24 bytes, but the NTLMv2 hash is more than 24 bytes.
 * So, the only way to keep pass-through compatibility was to have a v2-hash
 * that was guaranteed to be 24 bytes. So LMv1 was born: it has a 16-byte hash
 * followed by the 8-byte client challenge, for a total of 24 bytes. 
 */
void lmv2_create_response(const uint8_t ntlm[16],   const char *username,
    const char *domain, const uint8_t challenge[8], uint8_t *result,
    uint8_t *result_size);


/* Create the NTLMv2 hash, which is based on the NTLMv1 hash (for easy
 * upgrading), the username, and the domain. Essentially, the NTLM hash
 * is used as a HMAC-MD5 key, which is used to hash the unicode domain
 * concatenated with the unicode username. 
 */
void ntlmv2_create_hash(const uint8_t ntlm[16], const char *username,
    const char *domain, uint8_t hash[16]);


/* Create the NTLMv2 response, which can be sent back to the server. This is
 * done by using the HMAC-MD5 algorithm with the NTLMv2 hash as a key, and
 * the server challenge concatenated with the client challenge for the data.
 * The resulting hash is concatenated with the client challenge and returned.
 */
void ntlmv2_create_response(const uint8_t ntlm[16], const char *username,
    const char *domain, const uint8_t challenge[8], uint8_t *result,
    uint8_t *result_size);


/*
 * Uses the RSA algorithm to encrypt the input into the output.
 */
void rsa_encrypt(uint8_t *input, uint8_t *output, int length,
    uint8_t *mod_bin, uint32_t mod_size, uint8_t *exp_bin);


/* 
 * Uses MD5 and SHA1 hash functions, using 3 salts to compute a message
 * digest (saved into 'output')
 */
void hash48(uint8_t *output, uint8_t *input, uint8_t salt, uint8_t *sha_salt1,
    uint8_t *sha_salt2);

/* 
 * MD5 crypt 'input' into 'output' by using 2 salts
 */
void hash16(uint8_t *output, uint8_t *input, uint8_t *md5_salt1,
    uint8_t *md5_salt2);


/*
 * This is D3DES (V5.09) by Richard Outerbridge with the double and
 * triple-length support removed for use in VNC.
 *
 * These changes are:
 *  Copyright (C) 1999 AT&T Laboratories Cambridge.  All Rights Reserved.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

/* d3des.h -
 *
 *	Headers and defines for d3des.c
 *	Graven Imagery, 1992.
 *
 * Copyright (c) 1988,1989,1990,1991,1992 by Richard Outerbridge
 *	(GEnie : OUTER; CIS : [71755,204])
 */

#define EN0	0	/* MODE == encrypt */
#define DE1	1	/* MODE == decrypt */

extern void deskey(unsigned char *, int);
/*		      hexkey[8]     MODE
 * Sets the internal key register according to the hexadecimal
 * key contained in the 8 bytes of hexkey, according to the DES,
 * for encryption or decryption according to MODE.
 */

extern void usekey(unsigned long *);
/*		    cookedkey[32]
 * Loads the internal key register with the data in cookedkey.
 */

extern void cpkey(unsigned long *);
/*		   cookedkey[32]
 * Copies the contents of the internal key register into the storage
 * located at &cookedkey[0].
 */

extern void des(unsigned char *, unsigned char *);
/*		    from[8]	      to[8]
 * Encrypts/Decrypts (according to the key currently loaded in the
 * internal key register) one block of eight bytes at address 'from'
 * into the block at address 'to'.  They can be the same.
 */

/* d3des.h V5.09 rwo 9208.04 15:06 Graven Imagery
 ********************************************************************/

#endif
