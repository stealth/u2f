
all: enroll

UNAME := $(shell uname)

SSL=/usr/local/ssl
CXX=c++
CC=cc

LDFLAGS=-Wl,$(SSL)/lib/libcrypto.so -Wl,$(SSL)/lib/libssl.so
CFLAGS=-I$(SSL)/include

CFLAGS+=-Wall -c -O2

ifeq ($(UNAME), Linux)

CFLAGS+=-Ihidapi/hidapi -D__OS_LINUX
LDFLAGS+=-lrt -ludev
HIDAPI=hid.o
hid.o: hidapi/linux/hid.c
	$(CC) $(CFLAGS) -o hid.o hidapi/linux/hid.c

endif  # Linux

ifeq ($(UNAME), Darwin)

CFLAGS+=-Ihidapi/hidapi -D__OS_MAC
LDFLAGS+=-framework IOKit -framework CoreFoundation
HIDAPI=hid.o
hid.o: hidapi/mac/hid.c
	$(CC) $(CFLAGS) -o hid.o hidapi/mac/hid.c

endif  # Darwin

u2f_util.o: u2f_util.cc u2f_util.h u2f.h u2f_hid.h
	$(CXX) $(CFLAGS) -o $@ u2f_util.cc

enroll.o: enroll.cc
	$(CXX) $(CFLAGS) $<

enroll: enroll.o u2f_util.o $(HIDAPI)
	$(CXX) $(LDFLAGS) -o $@ $^



