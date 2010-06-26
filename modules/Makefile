CC = gcc
CXX = g++

SRCS = ncrack_ssh.cc ncrack_smb.cc ncrack_ftp.cc ncrack_telnet.cc ncrack_http.cc ncrack_pop3.cc
OBJS = ncrack_ssh.o ncrack_smb.o ncrack_ftp.o ncrack_telnet.o ncrack_http.o ncrack_pop3.o

include_dirs := .. ../nsock/include ../nbase ../opensshlib
CPPFLAGS += $(addprefix -I,$(include_dirs)) -DHAVE_CONFIG_H

vpath %.h $(include_dirs)


all: $(OBJS)

.cc.o :
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $< -o $@

clean :
	rm -f $(OBJS) 


