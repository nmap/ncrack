# $Id: Makefile.in,v 1.298 2008/11/05 05:20:46 djm Exp $

# uncomment if you run a non bourne compatable shell. Ie. csh
#SHELL = /bin/sh

AUTORECONF=autoreconf

prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sbindir=${exec_prefix}/sbin
libexecdir=${exec_prefix}/libexec
datadir=${datarootdir}
datarootdir=${prefix}/share
mandir=${datarootdir}/man
mansubdir=cat
sysconfdir=${prefix}/etc
piddir=/var/run
srcdir=.
top_srcdir=.

DESTDIR=

STRIP_OPT=-s

CC=gcc
LD=gcc
CFLAGS=-g -O2 -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wno-pointer-sign -Wformat-security -fno-builtin-memset -fstack-protector-all 
CPPFLAGS=-I. -I$(srcdir)  -DHAVE_CONFIG_H
#LIBS=-lcrypto -lutil -lz -lnsl  -lcrypt -lresolv -lresolv
AR=/usr/bin/ar
AWK=gawk
RANLIB=ranlib
INSTALL=/bin/install -c
PERL=/usr/bin/perl
SED=/bin/sed
ENT=
XAUTH_PATH=/usr/bin/xauth
LDFLAGS=  -fstack-protector-all -L. -Lopenbsd-compat/ $(STATIC)
EXEEXT=


TARGETS=$(LIBCOMPAT) libopenssh.a

LIBSSH_OBJS=acss.o authfd.o authfile.o bufaux.o bufbn.o buffer.o \
	canohost.o cipher.o cipher-acss.o cipher-aes.o \
	cipher-bf1.o cipher-ctr.o cipher-3des1.o cleanup.o \
	compat.o compress.o crc32.o deattack.o fatal.o hostfile.o \
	log.o match.o md-sha256.o moduli.o packet.o \
	rsa.o ttymodes.o xmalloc.o addrmatch.o \
	atomicio.o key.o kex.o mac.o uidswap.o uuencode.o misc.o \
	rijndael.o ssh-dss.o ssh-rsa.o dh.o kexdh.o \
	kexgex.o kexdhc.o kexgexc.o umac.o sshconnect2.o entropy.o

# channels.o nchan.o dispatch.o monitor_fdpass.o
#progressmeter.o dns.o entropy.o scard-opensc.o 
#gss-genr.o jpake.o schnorr.o


all: $(TARGETS)

$(LIBSSH_OBJS): Makefile.in config.h

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

LIBCOMPAT=openbsd-compat/libopenbsd-compat.a
$(LIBCOMPAT): always
	(cd openbsd-compat && $(MAKE))
always:

libopenssh.a: $(LIBCOMPAT) $(LIBSSH_OBJS)
	$(AR) cr $@ $(LIBSSH_OBJS)
	$(RANLIB) $@


# fake rule to stop make trying to compile moduli.o into a binary "moduli.o"
moduli:
	echo

clean:
	rm -f *.o *.a $(TARGETS) config.cache config.log
	rm -f *.out core
	(cd openbsd-compat && $(MAKE) clean)


veryclean: distclean
	rm -f configure config.h.in *.0


compat-tests: $(LIBCOMPAT)
	(cd openbsd-compat/regress && $(MAKE))

