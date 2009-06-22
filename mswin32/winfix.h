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


/*   (exported) functions   */

/* Its main function is to do WSAStartup() . */
EXTERNC void win_init();

#endif




