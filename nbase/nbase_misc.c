
/***************************************************************************
 * nbase_misc.c -- Some small miscelaneous utility/compatability           *
 * functions.                                                              *
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

/* $Id: nbase_misc.c 13660 2009-06-10 18:45:47Z david $ */

#include "nbase.h"

#ifndef WIN32
#include <errno.h>
#ifndef errno
extern int errno;
#endif
#else
#include <winsock2.h>
#endif

#include "nbase_ipv6.h"
#include "nbase_crc32ct.h"

#include <assert.h>
#include <fcntl.h>

#ifdef WIN32
#include <conio.h>
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

/* Returns the UNIX/Windows errno-equivalent.  Note that the Windows
   call is socket/networking specific.  The windows error number
   returned is like WSAMSGSIZE, but nbase.h includes #defines to
   correlate many of the common UNIX errors with their closest Windows
   equivalents.  So you can use EMSGSIZE or EINTR. */
int socket_errno() {
#ifdef WIN32
	return WSAGetLastError();
#else
	return errno;
#endif
}

/* We can't just use strerror to get socket errors on Windows because it has
   its own set of error codes: WSACONNRESET not ECONNRESET for example. This
   function will do the right thing on Windows. Call it like
     socket_strerror(socket_errno())
*/
char *socket_strerror(int errnum) {
#ifdef WIN32
	static char buffer[128];

	FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		0, errnum, 0, buffer, sizeof(buffer), NULL);

	return buffer;
#else
	return strerror(errnum);
#endif
}

/* This function is an easier version of inet_ntop because you don't
   need to pass a dest buffer.  Instead, it returns a static buffer that
   you can use until the function is called again (by the same or another
   thread in the process).  If there is a wierd error (like sslen being
   too short) then NULL will be returned. */
const char *inet_ntop_ez(struct sockaddr_storage *ss, size_t sslen) {

  struct sockaddr_in *sin = (struct sockaddr_in *) ss;
  static char str[INET6_ADDRSTRLEN];
#if HAVE_IPV6
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) ss;
#endif

  str[0] = '\0';

  if (sin->sin_family == AF_INET) {
    if (sslen < sizeof(struct sockaddr_in))
      return NULL;
    return inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str));
  } 
#if HAVE_IPV6
  else if(sin->sin_family == AF_INET6) {
    if (sslen < sizeof(struct sockaddr_in6))
      return NULL;
    return inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str));
  } 
#endif
  //Some laptops report the ip and address family of disabled wifi cards as null
  //so yes, we will hit this sometimes.
  return NULL;
}

/* Create a new socket inheritable by subprocesses. On non-Windows systems it's
   just a normal socket. */
int inheritable_socket(int af, int style, int protocol) {
#ifdef WIN32
  /* WSASocket is just like socket, except that the sockets it creates are
     inheritable by subprocesses (such as are created by CreateProcess), while
     those created by socket are not. */
  return WSASocket(af, style, protocol, NULL, 0, 0);
#else
  return socket(af, style, protocol);
#endif
}

int unblock_socket(int sd) {
#ifdef WIN32
u_long one = 1;
if(sd != 501) // Hack related to WinIP Raw Socket support
  ioctlsocket (sd, FIONBIO, &one);
#else
int options;
/*Unblock our socket to prevent recvfrom from blocking forever
  on certain target ports. */
options = O_NONBLOCK | fcntl(sd, F_GETFL);
fcntl(sd, F_SETFL, options);
#endif //WIN32
return 1;
}

/* Convert a socket to blocking mode */
int block_socket(int sd) {
#ifdef WIN32
  unsigned long options=0;
  if(sd == 501) return 1;
  ioctlsocket(sd, FIONBIO, &options);
#else
  int options;
  options = (~O_NONBLOCK) & fcntl(sd, F_GETFL);
  fcntl(sd, F_SETFL, options);
#endif

  return 1;
}

/* Converts a time specification string into milliseconds.  If the string
 * is a plain non-negative number, it is considered to already be in
 * milliseconds and is returned.  If it is a number followed by 's' (for
 * seconds), 'm' (minutes), or 'h' (hours), the number is converted to
 * milliseconds and returned.  If it cannot parse the string, -1 is
 * returned instead.
 */
long tval2msecs(char *tspec) {
  long l;
  char *endptr = NULL;
  l = strtol(tspec, &endptr, 10);
  if (l < 0 || !endptr) return -1;
  if (*endptr == '\0') return l;
  if (*endptr == 's' || *endptr == 'S') return l * 1000;
  if ((*endptr == 'm' || *endptr == 'M')) {
    if (*(endptr + 1) == 's' || *(endptr + 1) == 'S') 
      return l;
    return l * 60000;
  }
  if (*endptr == 'h' || *endptr == 'H') return l * 3600000;
  return -1;
}

/* A replacement for select on Windows that allows selecting on stdin
 * (file descriptor 0) and selecting on zero file descriptors (just for
 * the timeout). Plain Windows select doesn't work on non-sockets like
 * stdin and returns an error if no file descriptors were given, because
 * they were NULL or empty.  This only works for sockets and stdin; if
 * you have a descriptor referring to a normal open file in the set,
 * Windows will return WSAENOTSOCK. */
int fselect(int s, fd_set *rmaster, fd_set *wmaster, fd_set *emaster, struct timeval *tv)
{
#ifdef WIN32
    static int stdin_thread_started = 0;
    int fds_ready = 0;
    int iter = -1, i;
    struct timeval stv;
    fd_set rset, wset, eset;

    /* Figure out whether there are any FDs in the sets, as @$@!$# Windows
       returns WSAINVAL (10022) if you call a select() with no FDs, even though
       the Linux man page says that doing so is a good, reasonably portable way
       to sleep with subsecond precision.  Sigh. */
    for(i = s; i > STDIN_FILENO; i--) {
        if ((rmaster != NULL && FD_ISSET(i, rmaster))
            || (wmaster != NULL && FD_ISSET(i, wmaster))
            || (emaster != NULL && FD_ISSET(i, emaster)))
            break;
        s--;
    }

    /* Handle the case where stdin is not being read from. */
    if (rmaster == NULL || !FD_ISSET(STDIN_FILENO, rmaster)) {
        if (s > 0) {
            /* Do a normal select. */
            return select(s, rmaster, wmaster, emaster, tv);
        } else {
            /* No file descriptors given. Just sleep. */
            if (tv == NULL) {
                /* Sleep forever. */
                while (1)
                    sleep(10000);
            } else {
                usleep(tv->tv_sec * 1000000UL + tv->tv_usec);
                return 0;
            }
        }
    }

    /* This is a hack for Windows, which doesn't allow select()ing on
     * non-sockets (like stdin).  We remove stdin from the fd_set and
     * loop while select()ing on everything else, with a timeout of
     * 125ms.  Then we check if stdin is ready and increment fds_ready
     * and set stdin in rmaster if it looks good.  We just keep looping
     * until we have something or it times out.
     */

    /* nbase_winunix.c has all the nasty details behind checking if
     * stdin has input. It involves a background thread, which we start
     * now if necessary. */
    if (!stdin_thread_started) {
        assert(win_stdin_start_thread() != 0);
        stdin_thread_started = 1;
    }

    FD_CLR(STDIN_FILENO, rmaster);

    if (tv) {
        int usecs = (tv->tv_sec * 1000000) + tv->tv_usec;

        iter = usecs / 125000;

        if (usecs % 125000)
            iter++;
    }

    FD_ZERO(&rset);
    FD_ZERO(&wset);
    FD_ZERO(&eset);

    while (!fds_ready && iter) {
        stv.tv_sec = 0;
        stv.tv_usec = 125000;

        if (rmaster)
            rset = *rmaster;
        if (wmaster)
            wset = *wmaster;
        if (emaster)
            eset = *emaster;

        fds_ready = 0;
        /* selecting on anything other than stdin? */
        if (s > 1)
            fds_ready = select(s, &rset, &wset, &eset, &stv);

        if (fds_ready > -1 && win_stdin_ready()) {
            FD_SET(STDIN_FILENO, &rset);
            fds_ready++;
        }

        if (tv)
            iter--;
    }

    if (rmaster)
        *rmaster = rset;
    if (wmaster)
        *wmaster = wset;
    if (emaster)
        *emaster = eset;

    return fds_ready;
#else
    return select(s, rmaster, wmaster, emaster, tv);
#endif
}


/*
 * CRC32 Cyclic Redundancy Check
 * simply copied from http://www.ptb.de/de/org/1/11/112/infos/crc16.htm
 * (I don't know why he calls it crc16 there, as it returns a 32-bit result)
 */

/* Table of CRCs of all 8-bit messages. */
static unsigned long crc_table[256];

/* Flag: has the table been computed? Initially false. */
static int crc_table_computed = 0;

/* Make the table for a fast CRC. */
static void make_crc_table(void)
{
  unsigned long c;
  int n, k;

  for (n = 0; n < 256; n++) {
    c = (unsigned long) n;
    for (k = 0; k < 8; k++) {
      if (c & 1) {
        c = 0xedb88320L ^ (c >> 1);
      } else {
        c = c >> 1;
      }
    }
    crc_table[n] = c;
  }
  crc_table_computed = 1;
}

/*
   Update a running crc with the bytes buf[0..len-1] and return
 the updated crc. The crc should be initialized to zero. Pre- and
 post-conditioning (one's complement) is performed within this
 function so it shouldn't be done by the caller. Usage example:

   unsigned long crc = 0L;

   while (read_buffer(buffer, length) != EOF) {
     crc = update_crc(crc, buffer, length);
   }
   if (crc != original_crc) error();
*/
static unsigned long update_crc(unsigned long crc,
                unsigned char *buf, int len)
{
  unsigned long c = crc ^ 0xffffffffL;
  int n;

  if (!crc_table_computed)
    make_crc_table();
  for (n = 0; n < len; n++) {
    c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
  }
  return c ^ 0xffffffffL;
}

/* Return the CRC of the bytes buf[0..len-1]. */
unsigned long nbase_crc32(unsigned char *buf, int len)
{
  return update_crc(0L, buf, len);
}


/*
 * CRC-32C (Castagnoli) Cyclic Redundancy Check.
 * Taken straight from RFC 4960 (SCTP).
 */

/* Return the CRC-32C of the bytes buf[0..len-1] */
unsigned long nbase_crc32c(unsigned char *buf, int len)
{
  int i;
  unsigned long crc32 = ~0L;
  unsigned long result;
  unsigned char byte0, byte1, byte2, byte3;

  for (i = 0; i < len; i++) {
    CRC32C(crc32, buf[i]);
  }

  result = ~crc32;

  /*  result now holds the negated polynomial remainder;
   *  since the table and algorithm is "reflected" [williams95].
   *  That is, result has the same value as if we mapped the message
   *  to a polynomial, computed the host-bit-order polynomial
   *  remainder, performed final negation, then did an end-for-end
   *  bit-reversal.
   *  Note that a 32-bit bit-reversal is identical to four inplace
   *  8-bit reversals followed by an end-for-end byteswap.
   *  In other words, the bytes of each bit are in the right order,
   *  but the bytes have been byteswapped.  So we now do an explicit
   *  byteswap.  On a little-endian machine, this byteswap and
   *  the final ntohl cancel out and could be elided.
   */

  byte0 =  result        & 0xff;
  byte1 = (result >>  8) & 0xff;
  byte2 = (result >> 16) & 0xff;
  byte3 = (result >> 24) & 0xff;
  crc32 = ((byte0 << 24) | (byte1 << 16) | (byte2 <<  8) | byte3);
  return crc32;
}


/*
 * Adler32 Checksum Calculation.
 * Taken straight from RFC 2960 (SCTP).
 */

#define ADLER32_BASE 65521 /* largest prime smaller than 65536 */

/*
 * Update a running Adler-32 checksum with the bytes buf[0..len-1]
 * and return the updated checksum.  The Adler-32 checksum should
 * be initialized to 1.
 */
static unsigned long update_adler32(unsigned long adler,
                                    unsigned char *buf, int len)
{
  unsigned long s1 = adler & 0xffff;
  unsigned long s2 = (adler >> 16) & 0xffff;
  int n;

  for (n = 0; n < len; n++) {
    s1 = (s1 + buf[n]) % ADLER32_BASE;
    s2 = (s2 + s1)     % ADLER32_BASE;
  }
  return (s2 << 16) + s1;
}

/* Return the Adler32 of the bytes buf[0..len-1] */
unsigned long nbase_adler32(unsigned char *buf, int len)
{
  return update_adler32(1L, buf, len);
}

#undef ADLER32_BASE

