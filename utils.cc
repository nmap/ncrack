
/***************************************************************************
 * utils.cc -- Various miscellaneous utility functions which defy          *
 * categorization :)                                                       *
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

int
base64_decode(const char *base64, size_t length, char *to)
{
  /* Table of base64 values for first 128 characters.  Note that this
     assumes ASCII (but so does Wget in other places).  */
  static short base64_char_to_value[256] =
  {
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62, 63, 62, 62, 63, 52, 53, 54, 55,
    56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,
    7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,
    0,  0,  0, 63,  0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 
  };
  size_t i;
  unsigned char* p = (unsigned char*) base64;
  char *q = to;
  int pad = length > 0 && (length % 4 || p[length - 1] == '=');
  const size_t L = ((length + 3) / 4 - pad) * 4;

  for (i = 0; i < length; i += 4) {
    //unsigned char c;
    //unsigned long value;

    int n = base64_char_to_value[p[i]] << 18 | base64_char_to_value[p[i + 1]] << 12 | base64_char_to_value[p[i + 2]] << 6 | base64_char_to_value[p[i + 3]];
    *q++ = n >> 16;
    *q++ = n >> 8 & 0xFF;
    *q++ = n & 0xFF;

  }
  if (pad) {
    int n = base64_char_to_value[p[L]] << 18 | base64_char_to_value[p[L + 1]] << 12;
    *q++ = n >> 16;

    if (length > L + 2 && p[L + 2] != '=')
    {
      n |= base64_char_to_value[p[L + 2]] << 6;
      *q++ = n >> 8 & 0xFF;
    }
  }
  return q - to;
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
    else if ((size_t)n >= *size - *offset)
      *size += n + 1;
    else
      break;
    *buf = (char *) safe_realloc(*buf, *size);
  }
  *offset += n;

  return n;
}


uint32_t le_to_be32(uint32_t x)
{
	return (((x>>24) & 0x000000ff) | ((x>>8) & 0x0000ff00) | ((x<<8) & 0x00ff0000) | ((x<<24) & 0xff000000));
}


uint16_t le_to_be16(uint16_t x)
{
  return ((x>>8) | (x<<8)); 
}

