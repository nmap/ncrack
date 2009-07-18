
/***************************************************************************
 * utils.cc -- Various miscellaneous utility functions which defy          *
 * categorization :)                                                       *
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


#include "utils.h"
#include "Service.h"


/* 
 * Case insensitive memory search - a combination of memmem and strcasestr
 * Will search for a particular string 'pneedle' in the first 'bytes' of
 * memory starting at 'haystack'
 */
char *
memsearch(const char *haystack, const char *pneedle, size_t bytes) {
  char buf[512];
  unsigned int needlelen;
  const char *p;
  char *needle, *q, *foundto;
  size_t i;

  /* Should crash if !pneedle -- this is OK */
  if (!*pneedle) return (char *) haystack;
  if (!haystack) return NULL;

  needlelen = (unsigned int) strlen(pneedle);
  if (needlelen >= sizeof(buf)) {
    needle = (char *) safe_malloc(needlelen + 1);
  } else needle = buf;
  p = pneedle; q = needle;
  while((*q++ = tolower(*p++)))
    ;
  p = haystack - 1; foundto = needle;

  i = 0;
  while(i < bytes) {
    ++p;
    if(tolower(*p) == *foundto) {
      if(!*++foundto) {
        /* Yeah, we found it */
        if (needlelen >= sizeof(buf))
          free(needle);
        return (char *) (p - needlelen + 1);
      }
    } else
      foundto = needle;
    i++;
  }
  if (needlelen >= sizeof(buf))
    free(needle);
  return NULL;
}



/* strtoul with error checking */
unsigned long int
Strtoul(const char *nptr)
{
  unsigned long value;
  char *endp = NULL;

  value = strtoul(nptr, &endp, 0);
  if (errno != 0 || *endp != '\0')
    fatal("Invalid value for number: %s", nptr);

  return value;
}

/* 
 * Return a copy of 'size' characters from 'src' string.
 * Will always null terminate by allocating 1 additional char.
 */
char *
Strndup(const char *src, size_t size)
{
  char *ret;
  ret = (char *)safe_malloc(size + 1);
  strncpy(ret, src, size);
  ret[size] = '\0';
  return ret;
}

/* 
 * Convert string to port (in host-byte order)
 */
u16
str2port(char *exp)
{
  unsigned long pvalue;
  char *endp = NULL;

  errno = 0;
  pvalue = strtoul(exp, &endp, 0);
  if (errno != 0 || *endp != '\0') 
    fatal("Invalid port number: %s", exp);
  if (pvalue > 65535) 
    fatal("Port number too large: %s", exp);

  return (u16)pvalue;
}



/* Compare a canonical option name (e.g. "max-scan-delay") with a
   user-generated option such as "max_scan_delay" and returns 0 if the
   two values are considered equivalant (for example, - and _ are
   considered to be the same), nonzero otherwise. */
int
optcmp(const char *a, const char *b) {
  while(*a && *b) {
    if (*a == '_' || *a == '-') {
      if (*b != '_' && *b != '-')
        return 1;
    }
    else if (*a != *b)
      return 1;
    a++; b++;
  }
  if (*a || *b)
    return 1;
  return 0;
}


/* convert string to protocol number */
u8
str2proto(char *str)
{
  if (!strcasecmp(str, "tcp"))
    return IPPROTO_TCP;
  else if (!strcasecmp(str, "udp"))
    return IPPROTO_UDP;
  else 
    return 0;
}


/* convert protocol number to string */
const char *
proto2str(u8 proto)
{
  if (proto == IPPROTO_TCP)
    return "tcp";
  else if (proto == IPPROTO_UDP)
    return "udp";
  else
    return NULL;
}


/* 
 * This is an update from the old macro TIMEVAL_MSEC_SUBTRACT
 * which now uses a long long variable which can hold all the intermediate
 * operations. This was made after a wrap-around bug was born due to the
 * fact that gettimeofday() can return a pretty large number of seconds
 * and microseconds today and usually one of the two arguments are timeval
 * structs returned by gettimeofday(). Add to that the fact that we are making
 * a multiplication with 1000 and the chances of a wrap-around increase.
 */
long long
timeval_msec_subtract(struct timeval x, struct timeval y)
{
  long long ret;
  struct timeval result;

  /* Perform the carry for the later subtraction by updating y. */
  if (x.tv_usec < y.tv_usec) {
    int nsec = (y.tv_usec - x.tv_usec) / 1000000 + 1;
    y.tv_usec -= 1000000 * nsec;
    y.tv_sec += nsec;
  }
  if (x.tv_usec - y.tv_usec > 1000000) {
    int nsec = (x.tv_usec - y.tv_usec) / 1000000;
    y.tv_usec += 1000000 * nsec;
    y.tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result.tv_sec = x.tv_sec - y.tv_sec;
  result.tv_usec = x.tv_usec - y.tv_usec;

  ret = (long long)result.tv_sec * 1000;
  ret += (long long)result.tv_usec / 1000;

  return ret;
}

