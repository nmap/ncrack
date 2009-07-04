
sources	:= ncrack_telnet.cc
objects	:= $(subst .cc,.o,$(sources))

include_dirs := ../.. ../../nsock/include ../../nbase
CPPFLAGS += $(addprefix -I,$(include_dirs)) -DHAVE_CONFIG_H

vpath %.h $(include_dirs)


all: $(objects)

.cc.o :
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $< -o $@

