#ifndef UTILS_H
#define UTILS_H 1


#include <stdlib.h>

#include <stdarg.h>
#include <stdio.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

void fatal(const char *fmt, ...)
     __attribute__ ((format (printf, 1, 2)));

#ifdef __cplusplus
}
#endif

#endif /* UTILS_H */
