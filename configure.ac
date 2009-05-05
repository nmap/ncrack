# Require autoconf 2.13 -*- mode: fundamental; -*-
AC_PREREQ(2.13)

dnl Process this file with autoconf to produce a configure script.
AC_INIT(ncrack.cc)



LIBPCAP_LIBS="-lpcap"
LIBSSL_LIBS="-lssl"

AC_ARG_WITH(localdirs,
AC_HELP_STRING([--with-localdirs], [Explicitly ask compiler to use /usr/local/{include,libs} if they exist ]),
  [ case "$with_localdirs" in
      yes)
        user_localdirs=1
        ;;
      no)
        user_localdirs=0
        ;;
    esac
    ],
  [ user_localdirs=0 ] )

if test "$user_localdirs" = 1; then
   if test -d /usr/local/lib; then
     LDFLAGS="$LDFLAGS -L/usr/local/lib"
     fi
   if test -d /usr/local/include; then
     CFLAGS="$CFLAGS -I/usr/local/include"
     CXXFLAGS="$CFLAGS -I/usr/local/include"
   fi
fi



dnl use ncrack_config.h instead of -D macros
AC_CONFIG_HEADER(ncrack_config.h)



dnl Host specific hacks
AC_CANONICAL_HOST
AC_C_INLINE

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL

 if test -n "$GXX"; then
      CXXFLAGS="$CXXFLAGS -Wall "
 fi

AC_MSG_CHECKING([whether the compiler is gcc 4 or greater])
if test x"$GXX" = xno; then
  AC_MSG_RESULT([no])
else
  # On some distros, there are snapshots available as gcc4
  if test -z "$ac_cv_prog_CC" || test x"$CC" = xgcc4; then
    our_gcc="$CC"
  else
    our_gcc="$ac_cv_prog_CC"
  fi

  nmap_gcc_major_version=0
  case `$our_gcc --version | sed -e 's,\..*,.,' -e q` in
    *4.)
      nmap_gcc_major_version=4
      ;;
  esac

  if test 4 -ge $nmap_gcc_major_version; then
    AC_MSG_RESULT([yes])
    CXXFLAGS="$CXXFLAGS -fno-strict-aliasing"
  else
    AC_MSG_RESULT([no])
  fi
fi



# Remember that all following tests will run with this CXXFLAGS by default
AC_MSG_CHECKING(for __func__)
AC_TRY_COMPILE([
#include <stdio.h>
],[printf ("%s", __func__);],
have_func=yes, have_func=no)
if test "x$have_func" = "xyes"; then
   AC_MSG_RESULT(yes)
else
   AC_MSG_RESULT(no)
   AC_MSG_CHECKING(for __FUNCTION__)
   AC_TRY_COMPILE([
#include <stdio.h>
],[printf ("%s", __FUNCTION__);],
have_function=yes, have_function=no)
   if test "x$have_function" = "xyes"; then
      AC_MSG_RESULT(yes)
      AC_DEFINE(__func__, __FUNCTION__)
   else
      AC_MSG_RESULT(no)
      AC_DEFINE(__func__, __FILE__)
   fi
fi


AC_CHECK_HEADERS(pwd.h termios.h sys/sockio.h)

dnl If any socket libraries needed
AC_SEARCH_LIBS(setsockopt, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)



dnl This test is from the configure.in of Unix Network Programming second
dnl edition example code by W. Richard Stevens
dnl ##################################################################
dnl Check if sockaddr{} has sa_len member.
dnl
AC_CACHE_CHECK(if sockaddr{} has sa_len member, ac_cv_sockaddr_has_sa_len,
        AC_TRY_COMPILE([
               #include <sys/types.h>
               #include <sys/socket.h>],
                [unsigned int i = sizeof(((struct sockaddr *)0)->sa_len)],
        ac_cv_sockaddr_has_sa_len=yes,
        ac_cv_sockaddr_has_sa_len=no))
if test $ac_cv_sockaddr_has_sa_len = yes ; then
        AC_DEFINE(HAVE_SOCKADDR_SA_LEN)
fi

#dnl check endedness
AC_C_BIGENDIAN

AC_MSG_CHECKING([if struct in_addr is a wacky huge structure (some Sun boxes)])

AC_TRY_COMPILE([#include <netinet/in.h>], struct in_addr i; i._S_un._S_addr;, \
             AC_DEFINE(IN_ADDR_DEEPSTRUCT) \
             AC_MSG_RESULT(yes) , \
             AC_TRY_COMPILE([#include <sys/types.h>
#include <netinet/in.h>], struct in_addr i; i.S_un.S_addr;, \
                             AC_DEFINE(IN_ADDR_DEEPSTRUCT) \
                             AC_MSG_RESULT(yes) , \
                             AC_MSG_RESULT(no);))

AC_CACHE_CHECK(if struct icmp exists, ac_cv_struct_icmp_exists,
        AC_TRY_COMPILE([
               #include <sys/types.h>
               #include <sys/param.h>
               #include <netinet/in_systm.h>
               #include <netinet/in.h>               
               #define __USE_BSD
               #define __FAVOR_BSD
               #define _BSD_SOURCE
               #include <netinet/ip.h>
               #include <netinet/ip_icmp.h>],
                [unsigned int i = sizeof(struct icmp)],
        ac_cv_struct_icmp_exists=yes,
        ac_cv_struct_icmp_exists=no))
if test $ac_cv_struct_icmp_exists = yes ; then
        AC_DEFINE(HAVE_STRUCT_ICMP)
fi

AC_CACHE_CHECK(if struct ip exists, ac_cv_struct_ip_exists,
        AC_TRY_COMPILE([
               #include <sys/types.h>
               #include <sys/param.h>
               #include <netinet/in_systm.h>
               #include <netinet/in.h>               
               #define __USE_BSD
               #define __FAVOR_BSD
               #define _BSD_SOURCE
               #include <netinet/ip.h>],
                [unsigned int i = sizeof(struct ip)],
        ac_cv_struct_ip_exists=yes,
        ac_cv_struct_ip_exists=no))
if test $ac_cv_struct_ip_exists = yes ; then
        AC_DEFINE(HAVE_STRUCT_IP)
fi

AC_CACHE_CHECK(if struct ip has ip_sum member, ac_cv_ip_has_ip_sum,
        AC_TRY_COMPILE([
               #include <sys/types.h>
               #include <sys/param.h>
               #include <netinet/in_systm.h>
               #include <netinet/in.h>
               #define __USE_BSD
               #define __FAVOR_BSD
               #define _BSD_SOURCE
               #include <netinet/ip.h>
               #include <netinet/ip_icmp.h>],
                [unsigned int i = sizeof(((struct ip *)0)->ip_sum)],
        ac_cv_ip_has_ip_sum=yes,
        ac_cv_ip_has_ip_sum=no))
if test $ac_cv_ip_has_ip_sum = yes ; then
        AC_DEFINE(HAVE_IP_IP_SUM)
fi

dnl Checks for library functions.
AC_CHECK_FUNCS(strerror)
RECVFROM_ARG6_TYPE





# NBASE
AC_ARG_WITH(libnbase,
AC_HELP_STRING([--with-libnbase=DIR], [Look for nbase include/libs in DIR]),
[  case "$with_libnbase" in
  yes)
    ;;
  *)
    NBASEDIR="$with_libnbase"
    NBASE_BUILD=""
    ;;
  esac],
NBASE_BUILD="nbase_build"
NBASEDIR="nbase"
)

LDFLAGS="$LDFLAGS -L$NBASEDIR"
CPPFLAGS="$CPPFLAGS -I$NBASEDIR"
LIBNBASE_LIBS="-lnbase"

AC_SUBST(NBASEDIR)
AC_SUBST(NBASE_BUILD)
AC_SUBST(LIBNBASE_LIBS)

AC_CONFIG_SUBDIRS(nbase)


# NSOCK
NSOCKDIR="nsock"
NSOCK_BUILD="nsock_build"
AC_ARG_WITH(libnsock,
AC_HELP_STRING([--with-libnsock=DIR], [Compile and link to libnsock in DIR]),
[  case "$with_libnsock" in
  yes)
    ;;
  *)
    NSOCKDIR="$with_libnsock"
    NSOCK_BUILD=""
    ;;
  esac]
)

LDFLAGS="$LDFLAGS -L$NSOCKDIR/src"
CPPFLAGS="$CPPFLAGS -I$NSOCKDIR/include"
LIBNSOCK_LIBS="-lnsock"

AC_SUBST(NSOCKDIR)
AC_SUBST(NSOCK_BUILD)
AC_SUBST(LIBNSOCK_LIBS)

AC_CONFIG_SUBDIRS(nsock/src)



AC_SUBST(LIBPCAP_LIBS)
AC_SUBST(LIBSSL_LIBS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

AC_OUTPUT(Makefile)
