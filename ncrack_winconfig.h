#ifndef NCRACK_WINCONFIG_H
#define NCRACK_WINCONFIG_H
/* Without this, Windows will give us all sorts of crap about using functions
   like strcpy() even if they are done safely */
#define _CRT_SECURE_NO_DEPRECATE 1
#define NCRACK_PLATFORM "i686-pc-windows-windows"


#define HAVE_OPENSSL 1
/* Apparently __func__ isn't yet supported */
#define __func__ __FUNCTION__

#endif /* NCRACK_WINCONFIG_H */