#include "utils.h"
#include "Service.h"


void
memprint(const char *addr, size_t bytes)
{
  size_t i;
  for (i = 0; i < bytes; i++) {
    printf("%c", addr[i]);
  }
  fflush(stdout);
}



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
    fatal("Invalid value for number: %s\n", nptr);

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
    fatal("Invalid port number: %s\n", exp);
  if (pvalue > 65535) 
    fatal("Port number too large: %s\n", exp);

  return (u16)pvalue;
}


void
fatal(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  (void) vfprintf(stderr, fmt, ap);
  va_end(ap);
  exit(EXIT_FAILURE);
}


void error(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  (void) vfprintf(stderr, fmt, ap);
  va_end(ap);
  return;
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



