prefix = /usr/local
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
mandir = ${prefix}/share/man
srcdir = .

CC = gcc
AR = ar
RANLIB = ranlib
CCOPT = 
DEFS = -DHAVE_CONFIG_H
# With GCC, add extra security checks to source code.
DEFS += -D_FORTIFY_SOURCE=2
CPPFLAGS = 
CFLAGS = -g -O2 -Wall  $(CCOPT) $(GLIB_CFLAGS) $(DEFS) $(INCLS)
STATIC = 
LDFLAGS =  $(STATIC)
LIBS =  -lssl -lcrypto  
SHTOOL = ./shtool
INSTALL = $(SHTOOL) install 
MAKEDEPEND = @MAKEDEPEND@

TARGET = libnbase.a

DEPS = getopt.h nbase.h nbase_winconfig.h nbase_config.h nbase_ipv6.h nbase_winunix.h nbase_crc32ct.h
OBJS =  ${LIBOBJDIR}snprintf$U.o ${LIBOBJDIR}nbase_str$U.o ${LIBOBJDIR}nbase_misc$U.o ${LIBOBJDIR}nbase_memalloc$U.o ${LIBOBJDIR}nbase_rnd$U.o

all: $(TARGET) 

$(TARGET): $(DEPS) $(OBJS)
	rm -f $@
	$(AR) cr $@ $(OBJS)
	$(RANLIB) $@

clean:
	rm -f $(OBJS) $(TARGET) 

distclean: clean
	rm -f Makefile config.cache config.log config.status nbase_config.h

depend:
	$(MAKEDEPEND) $(INCLS) -s "# DO NOT DELETE" -- $(DEFS) -- $(SRCS)

configure: configure.ac
	autoconf

Makefile: Makefile.in config.status
	./config.status

config.status: configure
	./config.status --recheck

.cc.o:
	$(CC) -c $(CFLAGS) $*.cc

# DO NOT DELETE -- Needed by makedepend







