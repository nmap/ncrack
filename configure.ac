# Require autoconf 2.13 -*- mode: fundamental; -*-
AC_PREREQ(2.13)

dnl Process this file with autoconf to produce a configure script.
AC_INIT(ncrack.cc)


CXXFLAGS="$CXXFLAGS -O2"


# This variable is needed so that PCAP support, which is by default defined
# for Nsock due to Nmap, is disabled in Ncrack's case. 
ac_configure_args="$ac_configure_args --with-libpcap=no"


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
     CPPFLAGS="$CPPFLAGS -I/usr/local/include"
   fi
fi


dnl use ncrack_config.h instead of -D macros
AC_CONFIG_HEADER(ncrack_config.h)


AC_PATH_TOOL([STRIP], [strip], [/bin/true])


dnl Host specific hacks
AC_CANONICAL_HOST
AC_C_INLINE

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL

 if test -n "$GXX"; then
      CXXFLAGS="$CXXFLAGS -Wall"
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

  ncrack_gcc_major_version=0
  case `$our_gcc --version | sed -e 's,\..*,.,' -e q` in
    *4.)
      ncrack_gcc_major_version=4
      ;;
  esac

  if test 4 -ge $ncrack_gcc_major_version; then
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
      AC_DEFINE(__func__, __FUNCTION__, [__FUNCTION__ is available])
   else
      AC_MSG_RESULT(no)
      AC_DEFINE(__func__, __FILE__, [Use __FILE__ since __FUNCTION__ is not available])
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
        AC_DEFINE([HAVE_SOCKADDR_SA_LEN], [1], [struct sockaddr has sa_len member])
fi

#dnl check endedness
AC_C_BIGENDIAN

AC_MSG_CHECKING([if struct in_addr is a wacky huge structure (some Sun boxes)])

AC_TRY_COMPILE([#include <netinet/in.h>], struct in_addr i; i._S_un._S_addr;, \
             AC_DEFINE([IN_ADDR_DEEPSTRUCT], [1], [struct in_addr is a whacky huge structure]]) \
             AC_MSG_RESULT(yes) , \
             AC_TRY_COMPILE([#include <sys/types.h>
#include <netinet/in.h>], struct in_addr i; i.S_un.S_addr;, \
                             AC_DEFINE([IN_ADDR_DEEPSTRUCT], [1], [struct in_addr is a whacky huge structure]) \
                             AC_MSG_RESULT(yes) , \
                             AC_MSG_RESULT(no);))


dnl Checks for library functions.
AC_CHECK_FUNCS(strerror)
AC_CHECK_FUNCS(signal)


dnl Type of 6th argument to recvfrom(). Usually int or socklen_t.
AC_DEFUN([RECVFROM_ARG6_TYPE],
[
   AC_LANG_PUSH(C++)
   AC_MSG_CHECKING([for type of 6th argument to recvfrom()])
   recvfrom6_t=
   for t in socklen_t int; do
     AC_TRY_COMPILE([
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>],[
$t arg;
recvfrom (0, NULL, 0, 0, NULL, &arg);],[
      recvfrom6_t="$t"
      break])
   done

   if test "x$recvfrom6_t" = x; then
     AC_MSG_WARN([Cannot find type for 6th argument to recvfrom(). Using socklen_t ptr])
     recvfrom6_t="socklen_t"
   fi

   AC_MSG_RESULT($recvfrom6_t)
   AC_DEFINE_UNQUOTED(recvfrom6_t, $recvfrom6_t,
     [Type of 6th argument to recvfrom()])
   AC_LANG_POP(C++)
])

RECVFROM_ARG6_TYPE


# We test whether they specified openssl desires explicitly
use_openssl="yes"
specialssldir=""
AC_ARG_WITH(openssl,
AC_HELP_STRING([--with-openssl=DIR],[Use optional openssl libs and includes from [DIR]/lib/ and [DIR]/include/openssl/)]),
[  case "$with_openssl" in
  yes)
    ;;
  no)
    use_openssl="no"
    ;;
  *)
    specialssldir="$with_openssl"
    CPPFLAGS="$CPPFLAGS -I$with_openssl/include"
    LDFLAGS="$LDFLAGS -L$with_openssl/lib"
    ;;
  esac]
)

# If they didn't specify it, we try to find it
if test "$use_openssl" = "yes" -a -z "$specialssldir"; then
  AC_CHECK_HEADER(openssl/ssl.h,,
  [ use_openssl="no"
    if test "$with_openssl" = "yes"; then
      AC_MSG_ERROR([OpenSSL was explicitly requested but openssl/ssl.h was not found. Try the --with-openssl=DIR argument to give the location of OpenSSL or run configure with --without-openssl.])
    fi
    AC_MSG_WARN([Failed to find openssl/ssl.h so OpenSSL will not be used. If it is installed you can try the --with-openssl=DIR argument])
  ])

# use_openssl="yes" given explicitly in next 2 rules to avoid adding lib to $LIBS
 if test "$use_openssl" = "yes"; then
   AC_CHECK_LIB(crypto, BIO_int_ctrl,
    [ use_openssl="yes"],
    [ use_openssl="no"
    if test "$with_openssl" = "yes"; then
      AC_MSG_ERROR([OpenSSL was explicitly requested but libcrypto was not found. Try the --with-openssl=DIR argument to give the location of OpenSSL or run configure with --without-openssl.])
    fi
    AC_MSG_WARN([Failed to find libcrypto so OpenSSL will not be used. If it is installed you can try the --with-openssl=DIR argument])
   ])
 fi

 if test "$use_openssl" = "yes"; then
   AC_CHECK_LIB(ssl, SSL_new,
    [ use_openssl="yes" ],
    [ use_openssl="no"
    if test "$with_openssl" = "yes"; then
      AC_MSG_ERROR([OpenSSL was explicitly requested but libssl was not found. Try the --with-openssl=DIR argument to give the location of OpenSSL or run configure with --without-openssl.])
    fi
    AC_MSG_WARN([Failed to find libssl so OpenSSL will not be used. If it is installed you can try the --with-openssl=DIR argument]) ],
    [ -lcrypto ])
 fi
fi

OPENSSL_LIBS=
if test "$use_openssl" = "yes"; then

  AC_DEFINE([HAVE_OPENSSL], [1], [OpenSSL is available])
  OPENSSL_LIBS="-lssl -lcrypto"
fi

AC_SUBST(OPENSSL_LIBS)


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


# Modules
MODULES_BUILD="modules_build"
AC_SUBST(MODULES_BUILD)


OPENSSHLIB_DIR=
OPENSSHLIB_BUILD=
OPENSSH_LIB=

if test "$use_openssl" = "yes"; then
# OPENSSHLIB
OPENSSHLIB_DIR="opensshlib"
OPENSSHLIB_BUILD="opensshlib_build"
AC_ARG_WITH(libopenssh,
AC_HELP_STRING([--with-libopenssh=DIR], [Compile and link to libopenssh in DIR]),
[  case "$with_libopenssh" in
  yes)
    ;;
  *)
    OPENSSHLIB_DIR="$with_libopenssh"
    OPENSSHLIB_BUILD=""
    ;;
  esac]
)

LDFLAGS="$LDFLAGS -L$OPENSSHLIB_DIR"
CPPFLAGS="$CPPFLAGS -I$OPENSSHLIB_DIR"
OPENSSH_LIB="-lopenssh"
AC_CONFIG_SUBDIRS(opensshlib)

# The following modules rely on crypto functions which rely on OpenSSL, so
# build them only in case the system has OpenSSL.
MODULES_SRCS="ncrack_ssh.cc ncrack_smb.cc ncrack_smb2.cc ncrack_rdp.cc ncrack_sip.cc \
ncrack_psql.cc ncrack_mysql.cc ncrack_winrm.cc ncrack_mongodb.cc"
MODULES_OBJS="ncrack_ssh.o ncrack_smb.o ncrack_smb2.o ncrack_rdp.o ncrack_sip.o \
ncrack_psql.o ncrack_mysql.o ncrack_winrm.o ncrack_mongodb.o"

fi

MODULES_SRCS="$MODULES_SRCS ncrack_ftp.cc ncrack_telnet.cc ncrack_http.cc \
ncrack_pop3.cc ncrack_vnc.cc ncrack_redis.cc  ncrack_owa.cc \
ncrack_imap.cc ncrack_cassandra.cc ncrack_mssql.cc ncrack_cvs.cc \
ncrack_wordpress.cc ncrack_joomla.cc ncrack_dicom.cc ncrack_mqtt.cc"
MODULES_OBJS="$MODULES_OBJS ncrack_ftp.o ncrack_telnet.o ncrack_http.o \
ncrack_pop3.o ncrack_vnc.o ncrack_redis.o ncrack_owa.o \
ncrack_imap.o ncrack_cassandra.o ncrack_mssql.o ncrack_cvs.o \
ncrack_wordpress.o ncrack_joomla.o ncrack_dicom.o ncrack_mqtt.o"

AC_SUBST(MODULES_SRCS)
AC_SUBST(MODULES_OBJS)

AC_SUBST(OPENSSHLIB_DIR)
AC_SUBST(OPENSSHLIB_BUILD)
AC_SUBST(OPENSSH_LIB)

CPPFLAGS="$CPPFLAGS -Imodules"

AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

AC_OUTPUT(Makefile modules/Makefile)

if test -f docs/leet-ncrack-ascii-art.txt; then
	cat docs/leet-ncrack-ascii-art.txt
fi
echo "Configuration complete.  Type make (or gmake on some *BSD machines) to compile."
