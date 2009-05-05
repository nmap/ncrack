
/***************************************************************************
 * nbase_rnd.c -- Some simple routines for obtaining random numbers for    *
 * casual use.  These are pretty secure on systems with /dev/urandom, but  *
 * falls back to poor entropy for seeding on systems without such support. *
 *                                                                         *
 *                   Based on DNET / OpenBSD arc4random().                 *
 *                                                                         *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>                        *
 * Copyright (c) 1996 David Mazieres <dm@lcs.mit.edu>                      *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
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

/* $Id: nbase_rnd.c 12956 2009-04-15 00:37:23Z fyodor $ */

#include "nbase.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAV_SYS_TIME_H */
#ifdef WIN32
#include <wincrypt.h>
#endif /* WIN32 */

/* data for our random state */
struct nrand_handle {
  u8	 i, j, s[256], *tmp;
  int	 tmplen;
};
typedef struct nrand_handle nrand_h;

static void nrand_addrandom(nrand_h *rand, u8 *buf, int len) {
  int i;
  u8 si;
	
  /* Mix entropy in buf with s[]...
   * 
   * This is the ARC4 key-schedule.  It is rather poor and doesn't mix
   * the key in very well.  This causes a bias at the start of the stream.
   * To eliminate most of this bias, the first N bytes of the stream should
   * be dropped.
   */
  rand->i--;
  for (i = 0; i < 256; i++) {
    rand->i = (rand->i + 1);
    si = rand->s[rand->i];
    rand->j = (rand->j + si + buf[i % len]);
    rand->s[rand->i] = rand->s[rand->j];
    rand->s[rand->j] = si;
  }
  rand->j = rand->i;
}

static u8 nrand_getbyte(nrand_h *r) {
  u8 si, sj;
  
  /* This is the core of ARC4 and provides the pseudo-randomness */
  r->i = (r->i + 1);
  si = r->s[r->i];
  r->j = (r->j + si);
  sj = r->s[r->j];
  r->s[r->i] = sj; /* The start of the the swap */
  r->s[r->j] = si; /* The other half of the swap */
  return (r->s[(si + sj) & 0xff]);
}

int nrand_get(nrand_h *r, void *buf, size_t len) {
  u8 *p;
  size_t i;

  /* Hand out however many bytes were asked for */
  for (p = buf, i = 0; i < len; i++) {
    p[i] = nrand_getbyte(r);
  }
  return (0);
}

void nrand_init(nrand_h *r) {
  u8 seed[256]; /* Starts out with "random" stack data */
  int i;

  /* Gather seed entropy with best the OS has to offer */
#ifdef WIN32
  HCRYPTPROV hcrypt = 0;

  CryptAcquireContext(&hcrypt, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
  CryptGenRandom(hcrypt, sizeof(seed), seed);
  CryptReleaseContext(hcrypt, 0);
#else
  struct timeval *tv = (struct timeval *)seed;
  int *pid = (int *)(seed + sizeof(*tv));
  int fd;

  gettimeofday(tv, NULL); /* fill lowest seed[] with time */
  *pid = getpid();        /* fill next lowest seed[] with pid */

  /* Try to fill the rest of the state with OS provided entropy */
  if ((fd = open("/dev/urandom", O_RDONLY)) != -1 ||
      (fd = open("/dev/arandom", O_RDONLY)) != -1) {
    ssize_t n;
    do {
      errno = 0;
      n = read(fd, seed + sizeof(*tv) + sizeof(*pid),
               sizeof(seed) - sizeof(*tv) - sizeof(*pid));
    } while (n < 0 && errno == EINTR);
    close(fd);
  }
#endif

  /* Fill up our handle with starter values */
  for (i = 0; i < 256; i++) { r->s[i] = i; };
  r->i = r->j = 0;

  nrand_addrandom(r, seed, 128); /* lower half of seed data for entropy */
  nrand_addrandom(r, seed + 128, 128); /* Now use upper half */
  r->tmp = NULL;
  r->tmplen = 0;

  /* This stream will start biased.  Get rid of 1K of the stream */
  nrand_get(r, seed, 256); nrand_get(r, seed, 256);
  nrand_get(r, seed, 256); nrand_get(r, seed, 256);
}

int get_random_bytes(void *buf, int numbytes) {
  static nrand_h state;
  static int state_init = 0;
  
  /* Initialize if we need to */
  if (!state_init) {
    nrand_init(&state);
    state_init = 1;
  }

  /* Now fill our buffer */
  nrand_get(&state, buf, numbytes);

  return 0;
}

int get_random_int() {
  int i;
  get_random_bytes(&i, sizeof(int));
  return i;
}

unsigned int get_random_uint() {
  unsigned int i;
  get_random_bytes(&i, sizeof(unsigned int));
  return i;
}

u32 get_random_u32() {
  u32 i;
  get_random_bytes(&i, sizeof(i));
  return i;
}

u16 get_random_u16() {
  u16 i;
  get_random_bytes(&i, sizeof(i));
  return i;
}

u8 get_random_u8() {
  u8 i;
  get_random_bytes(&i, sizeof(i));
  return i;
}

unsigned short get_random_ushort() {
  unsigned short s;
  get_random_bytes(&s, sizeof(unsigned short));
  return s;
}
