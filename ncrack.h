#ifndef NCRACK_H 
#define NCRACK_H 1

#ifdef WIN32
#include "mswin32\winclude.h"
#endif

#ifdef HAVE_CONFIG_H
#include "ncrack_config.h"
#else
#ifdef WIN32
#include "ncrack_winconfig.h"
#endif /* WIN32 */
#endif /* HAVE_CONFIG_H */

#include <nbase.h>
//#include <sysexits.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef STDC_HEADERS
#include <stdlib.h>
#else
void *malloc();
void *realloc();
#endif

#if STDC_HEADERS || HAVE_STRING_H
#include <string.h>
#if !STDC_HEADERS && HAVE_MEMORY_H
#include <memory.h>
#endif
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_BSTRING_H
#include <bstring.h>
#endif

#include <ctype.h>
#include <sys/types.h>

#ifndef WIN32 /* from nmapNT -- seems to work */
#include <sys/wait.h>
#endif /* !WIN32 */

#ifdef HAVE_SYS_PARAM_H   
#include <sys/param.h> /* Defines MAXHOSTNAMELEN on BSD*/
#endif



#include <stdio.h>

#if HAVE_RPC_TYPES_H
#include <rpc/types.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
 
#include <sys/stat.h>

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <errno.h>

#if HAVE_NETDB_H
#include <netdb.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <fcntl.h>
#include <stdarg.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif



#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

/* Keep assert() defined for security reasons */
#undef NDEBUG

#include <math.h>
#include <assert.h>

#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif



#define NCRACK_NAME "Ncrack"
#define NCRACK_URL "http://ncrack.org"
#define NCRACK_VERSION "0.01ALPHA"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif


#define MAXLINE 255

#include "global_structures.h"


// #define _POSIX_C_SOURCE

#endif
