
/***************************************************************************
 * utils.cc -- Various miscellaneous utility functions which defy          *
 * categorization :)                                                       *
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
 


#include "utils.h"
#include "Service.h"
#include "NcrackOps.h"

extern NcrackOps o;

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


/* Like the perl equivalent -- It removes the terminating newline from string
   IF one exists.  It then returns the POSSIBLY MODIFIED string */
char *
chomp(char *string) {

  int len = strlen(string);
  if (len && string[len - 1] == '\n') {
    if (len > 1 && string[len - 2] == '\r')
      string[len - 2] = '\0';
    else
      string[len - 1] = '\0';
  }
  return string;
}


/* strtoul with error checking:
 * fatality should be 0 if error will be handled by caller, or else Strtoul
 * will exit
 */
unsigned long int
Strtoul(const char *nptr, int fatality)
{
  unsigned long value;
  char *endp = NULL;

  errno = 0;
  value = strtoul(nptr, &endp, 0);
  if (errno != 0 || *endp != '\0') {
    if (fatality)
      fatal("Invalid value for number: %s", nptr);
    else {
      if (o.debugging)
        error("Invalid value for number: %s", nptr);
    }
  }

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



/* Take in plain text and encode into base64. */
char *
b64enc(const unsigned char *data, int len)
{
    char *dest, *buf;
    /* base64 alphabet, taken from rfc3548 */
    const char *b64alpha = 
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /* malloc enough space to do something useful */
    dest = (char*)safe_malloc(4 * len / 3 + 4);
    dest[0] = '\0';

    buf = dest;

    /* Encode three bytes per iteration ala rfc3548. */
    while (len >= 3) {
        buf[0] = b64alpha[(data[0] >> 2) & 0x3f];
        buf[1] = b64alpha[((data[0] << 4) & 0x30) | ((data[1] >> 4) & 0xf)];
        buf[2] = b64alpha[((data[1] << 2) & 0x3c) | ((data[2] >> 6) & 0x3)];
        buf[3] = b64alpha[data[2] & 0x3f];
        data += 3;
        buf += 4;
        len -= 3;
    }

    /* Pad the remaining bytes. len is 0, 1, or 2 here. */
    if (len > 0) {
        buf[0] = b64alpha[(data[0] >> 2) & 0x3f];
        if (len > 1) {
            buf[1] = b64alpha[((data[0] << 4) & 0x30) | ((data[1] >> 4) & 0xf)];
            buf[2] = b64alpha[(data[1] << 2) & 0x3c];
        } else {
            buf[1] = b64alpha[(data[0] << 4) & 0x30];
            buf[2] = '=';
        }
        buf[3] = '=';
        buf += 4;
    }

    /*
     * As mentioned in rfc3548, we need to be careful about
     * how we null terminate and handle embedded null-termination.
     */
    *buf = '\0';

    return (dest);
}

int base64_encode(const char *str, int length, char *b64store)
{
  /* Conversion table.  */
  static char tbl[64] = {
    'A','B','C','D','E','F','G','H',
    'I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X',
    'Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n',
    'o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3',
    '4','5','6','7','8','9','+','/'
  };
  int i;
  const unsigned char *s = (const unsigned char *) str;
  char *p = b64store;

  /* Transform the 3x8 bits to 4x6 bits, as required by base64.  */
  for (i = 0; i < length; i += 3)
    {
      *p++ = tbl[s[0] >> 2];
      *p++ = tbl[((s[0] & 3) << 4) + (s[1] >> 4)];
      *p++ = tbl[((s[1] & 0xf) << 2) + (s[2] >> 6)];
      *p++ = tbl[s[2] & 0x3f];
      s += 3;
    }

  /* Pad the result if necessary...  */
  if (i == length + 1)
    *(p - 1) = '=';
  else if (i == length + 2)
    *(p - 1) = *(p - 2) = '=';

  /* ...and zero-terminate it.  */
  *p = '\0';

  return p - b64store;
}


/* mmap() an entire file into the address space.  Returns a pointer
   to the beginning of the file.  The mmap'ed length is returned
   inside the length parameter.  If there is a problem, NULL is
   returned, the value of length is undefined, and errno is set to
   something appropriate.  The user is responsible for doing
   an munmap(ptr, length) when finished with it.  openflags should 
   be O_RDONLY or O_RDWR, or O_WRONLY
*/
#ifndef WIN32
char *mmapfile(char *fname, int *length, int openflags) {
  struct stat st;
  int fd;
  char *fileptr;

  if (!length || !fname) {
    errno = EINVAL;
    return NULL;
  }

  *length = -1;

  if (stat(fname, &st) == -1) {
    errno = ENOENT;
    return NULL;
  }

  fd = open(fname, openflags);
  if (fd == -1) {
    return NULL;
  }

  fileptr = (char *)mmap(0, st.st_size, (openflags == O_RDONLY)? PROT_READ :
      (openflags == O_RDWR)? (PROT_READ|PROT_WRITE) 
      : PROT_WRITE, MAP_SHARED, fd, 0);

  close(fd);

#ifdef MAP_FAILED
  if (fileptr == (void *)MAP_FAILED) return NULL;
#else
  if (fileptr == (char *) -1) return NULL;
#endif

  *length = st.st_size;
  return fileptr;
}
#else /* WIN32 */
/* FIXME:  From the looks of it, this function can only handle one mmaped 
   file at a time (note how gmap is used).*/
/* I believe this was written by Ryan Permeh ( ryan@eeye.com) */

static HANDLE gmap = NULL;

char *mmapfile(char *fname, int *length, int openflags)
{
  HANDLE fd;
  DWORD mflags, oflags;
  char *fileptr;

  if (!length || !fname) {
    WSASetLastError(EINVAL);
    return NULL;
  }

  if (openflags == O_RDONLY) {
    oflags = GENERIC_READ;
    mflags = PAGE_READONLY;
  }
  else {
    oflags = GENERIC_READ | GENERIC_WRITE;
    mflags = PAGE_READWRITE;
  }

  fd = CreateFile (
      fname,
      oflags,                       // open flags
      0,                            // do not share
      NULL,                         // no security
      OPEN_EXISTING,                // open existing
      FILE_ATTRIBUTE_NORMAL,
      NULL);                        // no attr. template
  if (!fd)
    pfatal ("%s(%u): CreateFile()", __FILE__, __LINE__);

  *length = (int) GetFileSize (fd, NULL);

  gmap = CreateFileMapping (fd, NULL, mflags, 0, 0, NULL);
  if (!gmap)
    pfatal ("%s(%u): CreateFileMapping(), file '%s', length %d, mflags %08lX",
        __FILE__, __LINE__, fname, *length, mflags);

  fileptr = (char*) MapViewOfFile (gmap, oflags == GENERIC_READ ? FILE_MAP_READ : FILE_MAP_WRITE,
      0, 0, 0);
  if (!fileptr)
    pfatal ("%s(%u): MapViewOfFile()", __FILE__, __LINE__);

  if (o.debugging > 2)
    log_write(LOG_PLAIN, "%s(): fd %08lX, gmap %08lX, fileptr %08lX, length %d\n",
        __func__, (DWORD)fd, (DWORD)gmap, (DWORD)fileptr, *length);

  CloseHandle (fd);

  return fileptr;
}


/* FIXME:  This only works if the file was mapped by mmapfile (and only
   works if the file is the most recently mapped one */
int win32_munmap(char *filestr, int filelen)
{
  if (gmap == 0)
    fatal("%s: no current mapping !\n", __func__);

  FlushViewOfFile(filestr, filelen);
  UnmapViewOfFile(filestr);
  CloseHandle(gmap);
  gmap = NULL;
  return 0;
}

#endif


/* Create a UNICODE string based on an ASCII one. Be sure to free the memory! */
char *
unicode_alloc(const char *string)
{
	size_t i;
	char *unicode;
	size_t unicode_length = (strlen(string) + 1) * 2;

	if(unicode_length < strlen(string))
		fatal("%s Overflow.", __func__);

	unicode = (char *)safe_malloc(unicode_length);

	memset(unicode, 0, unicode_length);
	for(i = 0; i < strlen(string); i++)
	{
		unicode[(i * 2)] = string[i];
	}

	return unicode;
}


/* Same as unicode_alloc(), except convert the string to uppercase first. */
char *
unicode_alloc_upper(const char *string)
{
	size_t i;
	char *unicode;
	size_t unicode_length = (strlen(string) + 1) * 2;

	if(unicode_length < strlen(string))
		fatal("%s Overflow.", __func__);

	unicode = (char *)safe_malloc(unicode_length);

	memset(unicode, 0, unicode_length);
	for(i = 0; i < strlen(string); i++)
	{
		unicode[(i * 2)] = toupper(string[i]);
	}

	return unicode;
}


/* Reverses the order of the bytes in the memory pointed for the designated
 * length. 
 */
void
mem_reverse(uint8_t *p, unsigned int len)
{
  unsigned int i, j;
  uint8_t temp;

  if (len < 1)
    return;

  for (i = 0, j = len - 1; i < j; i++, j--) {
    temp = p[i];
    p[i] = p[j];
    p[j] = temp;
  }

}

/* Ncat's buffering functions */

/* Append n bytes starting at s to a malloc-allocated buffer. Reallocates the
   buffer and updates the variables to make room if necessary. */
int strbuf_append(char **buf, size_t *size, size_t *offset, const char *s, size_t n)
{
    //ncat_assert(*offset <= *size);

    if (n >= *size - *offset) {
        *size += n + 1;
        *buf = (char *) safe_realloc(*buf, *size);
    }

    memcpy(*buf + *offset, s, n);
    *offset += n;
    (*buf)[*offset] = '\0';

    return n;
}

/* Append a '\0'-terminated string as with strbuf_append. */
int strbuf_append_str(char **buf, size_t *size, size_t *offset, const char *s)
{
    return strbuf_append(buf, size, offset, s, strlen(s));
}

/* Do a sprintf at the given offset into a malloc-allocated buffer. Reallocates
   the buffer and updates the variables to make room if necessary. */
int strbuf_sprintf(char **buf, size_t *size, size_t *offset, const char *fmt, ...)
{
    va_list va;
    int n;

    //ncat_assert(*offset <= *size);

    if (*buf == NULL) {
        *size = 1;
        *buf = (char *) safe_malloc(*size);
    }

    for (;;) {
        va_start(va, fmt);
        n = Vsnprintf(*buf + *offset, *size - *offset, fmt, va);
        va_end(va);
        if (n < 0)
            *size = MAX(*size, 1) * 2;
        else if (n >= *size - *offset)
            *size += n + 1;
        else
            break;
        *buf = (char *) safe_realloc(*buf, *size);
    }
    *offset += n;

    return n;
}

