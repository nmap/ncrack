export NBASEDIR=nbase
export NSOCKDIR=nsock

CPPFLAGS = -Wall -g -Inbase -Insock/include
LDFLAGS =  -Lnbase -Lnsock/src 
LIBS = -lnsock -lnbase -lpcap -lssl

TARGET = ncrack

export SRCS = ncrack.cc module.cc utils.cc

OBJS = ncrack.o module.o utils.o

#.c :
#	$(CC) -c $(CPPFLAGS) $(CXXFLAGS) $< -o $@

all: nbase_build nsock_build 
	$(MAKE) $(TARGET)

$(TARGET): $(NSOCKDIR)/src/libnsock.a $(NBASEDIR)/libnbase.a $(OBJS)
	@echo Compiling ncrack... 
	rm -f $@
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

ncrack.o :
module.o :
utils.o :


nbase_build: $(NBASEDIR)/Makefile
	@echo Compiling libnbase;
	cd $(NBASEDIR) && $(MAKE)

nsock_build: $(NSOCKDIR)/src/Makefile nbase_build
	@echo Compiling libnsock;
	cd $(NSOCKDIR)/src && $(MAKE)



# cleaning stuff

clean: nsock_clean nbase_clean my_clean

my_clean:
	rm -f dependencies.mk makefile.dep
	rm -f $(OBJS) $(TARGET) config.cache
nbase_clean:
	-cd $(NBASEDIR) && $(MAKE) clean
nsock_clean:
	-cd $(NSOCKDIR)/src && $(MAKE) clean


Makefile: Makefile.in config.status
	./config.status

config.status: configure
	./config.status --recheck

makefile.dep:
	$(CXX) -MM $(CPPFLAGS) $(SRCS) > $@
include makefile.dep
