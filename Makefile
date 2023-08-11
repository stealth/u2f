
all: u2f-enroll u2f-sign pam

UNAME := $(shell uname)

#your own libcrypto install
#SSL=/usr/local/ssl
CXX=c++
CC=cc

LDFLAGS=-lcrypto
LDFLAGS=-L$(SSL)/lib -Wl,--rpath=$(SSL)/lib -lcrypto
CFLAGS=-I$(SSL)/include

CFLAGS+=-fPIC -c -O2

ifeq ($(UNAME), Linux)
LDFLAGS+=-Wl,-soname=pam_fido-u2f.so

CFLAGS+=-Wall
CFLAGS+=-Ihidapi/hidapi -D__OS_LINUX

HIDAPI=hid.o
hid.o: hidapi/linux/hid.c
	$(CC) $(CFLAGS) -o hid.o hidapi/linux/hid.c

endif  # Linux

ifeq ($(UNAME), Darwin)
LDFLAGS+=-framework IOKit -framework CoreFoundation

CFLAGS+=-w
CFLAGS+=-Ihidapi/hidapi -D__OS_DARWIN

HIDAPI=hid.o
hid.o: hidapi/mac/hid.c
	$(CC) $(CFLAGS) -o hid.o hidapi/mac/hid.c

endif  # Darwin

CXXFLAGS=$(CFLAGS) -std=c++11

pam: pam_fido-u2f.o
	$(CXX) $^ -shared $(LDFLAGS) -lpam -o pam_fido-u2f.so

pam_fido-u2f.o: pam_fido-u2f.cc
	$(CXX) $(CXXFLAGS) $<

u2f_util.o: u2f_util.cc u2f_util.h u2f.h u2f_hid.h
	$(CXX) $(CXXFLAGS) -o $@ u2f_util.cc

enroll.o: enroll.cc
	$(CXX) $(CXXFLAGS) $<

sign.o: sign.cc
	$(CXX) $(CXXFLAGS) $<

u2f-enroll: enroll.o u2f_util.o $(HIDAPI)
	$(CXX) $^ $(LDFLAGS) -lrt -ludev -o $@

u2f-sign: sign.o u2f_util.o $(HIDAPI)
	$(CXX) $^ $(LDFLAGS) -lrt -ludev -o $@


install:
	cp u2f-sign /usr/local/bin
	cp u2f-enroll /usr/local/bin
	cp pam-enroll /usr/local/bin
	cp pam_fido-u2f.so /lib64/security

clean:
	rm -rf *.o


