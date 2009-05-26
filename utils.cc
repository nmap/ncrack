#include "utils.h"
#include "Service.h"


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
Strndup(char *src, size_t size)
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
	if (!strcmp(str, "tcp"))
		return IPPROTO_TCP;
	else if (!strcmp(str, "udp"))
		return IPPROTO_UDP;
	else 
		return 0;
}



