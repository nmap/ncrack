# $Id: Makefile.in,v 1.4 2006/08/19 09:12:14 dtucker Exp $

sysconfdir=${prefix}/etc
piddir=/var/run
srcdir=.
top_srcdir=../..


CC=gcc
LD=gcc
CFLAGS=-g -O2 -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wno-pointer-sign -Wformat-security -fno-builtin-memset -fstack-protector-all 
CPPFLAGS=-I. -I.. -I$(srcdir) -I$(srcdir)/..  -DHAVE_CONFIG_H
EXEEXT=
LIBCOMPAT=../libopenbsd-compat.a
LIBS=-lcrypto -lutil -lz -lnsl  -lcrypt -lresolv -lresolv
LDFLAGS= -fstack-protector-all $(LIBCOMPAT)

TESTPROGS=closefromtest$(EXEEXT) snprintftest$(EXEEXT) strduptest$(EXEEXT) \
	strtonumtest$(EXEEXT)

all:	t-exec ${OTHERTESTS}

%$(EXEEXT):	%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $< $(LIBCOMPAT) $(LIBS)

t-exec:	$(TESTPROGS)
	@echo running compat regress tests
	@for TEST in ""$?; do \
		echo "run test $${TEST}" ... 1>&2; \
		./$${TEST}$(EXEEXT) || exit $$? ; \
	done
	@echo finished compat regress tests

clean:
	rm -f *.o *.a core $(TESTPROGS) valid.out

distclean: clean
	rm -f Makefile *~
