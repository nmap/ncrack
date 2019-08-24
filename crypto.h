
/***************************************************************************
 * crypto.h -- crypto functions like LM, NTLM etc reside here              *
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
