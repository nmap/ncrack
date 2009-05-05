#include "utils.h"


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
