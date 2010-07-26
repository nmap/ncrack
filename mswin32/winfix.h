#ifndef WINFIX_H
#define WINFIX_H

#include <winsock2.h>
#include <windows.h>

#ifndef EXTERNC
# ifdef __cplusplus
#  define EXTERNC extern "C"
# else
#  define EXTERNC extern
# endif
#endif

//	windows-specific options
typedef unsigned char u_int8_t;
typedef __int16 int16_t;
typedef unsigned __int16 u_int16_t;
typedef __int32 int32_t;
typedef unsigned __int32 u_int32_t;
typedef unsigned __int64 u_int64_t;
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
typedef signed __int8 int8_t;
typedef signed __int16 int16_t;
typedef signed __int32 int32_t;
typedef signed __int64 int64_t;
/*   (exported) functions   */

/* Its main function is to do WSAStartup() . */
EXTERNC void win_init();

#endif




