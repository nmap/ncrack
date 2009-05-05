# Require autoconf 2.13 -*- mode: fundamental; -*-
AC_PREREQ(2.13)

dnl Process this file with autoconf to produce a configure script.
AC_INIT(ncrack.cc)


CPPFLAGS="-Wall -g"
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
