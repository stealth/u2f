/*
 * Copyright (C) 2015 Sebastian Krahmer.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastian Krahmer.
 * 4. The name Sebastian Krahmer may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <cstdio>
#include <cstddef>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <utime.h>
#include <time.h>
#include <cstring>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <openssl/sha.h>

#include "u2f.h"
#include "u2f_util.h"

using namespace std;


struct apdu_blob_t {
	//uint8_t ctrl; Not here; sent directly as P3
	unsigned char chall[32];
	unsigned char app[32];
	uint8_t kl;
	uint8_t kh[255];
} apdu_blob = {{0,}, {0,}, 0, {0,}};


enum input_filter_t {
	INPUT_HEX,
	INPUT_BIN
};


enum output_filter_t {
	OUTPUT_HEX,
	OUTPUT_BIN
};


enum sw_t {
	SW_OK   	= 0x9000,
	SW_NOUSER	= 0x6985
};


// stop after newline or \0
int hex2bin(const char *from, unsigned char *to, size_t tolen)
{
	int has_failed = 0;
	size_t i = 0;

	for (i = 0; from[2*i] != '\n' && from[2*i] != 0 && i < tolen; ++i) {
		if (sscanf(from + 2*i, "%02hhx", to + i) != 1) {
			has_failed = 1;
			break;
		}
	}

	if (has_failed)
		return -1;
	return (int)i;
}



int input(apdu_blob_t *a, enum input_filter_t f)
{
	if (f == INPUT_BIN) {
		if ((a->kl = read(fileno(stdin), a->kh, sizeof(a->kh))) <= 0)
			return -1;
		if (read(fileno(stdin), a->chall, sizeof(a->chall)) != (ssize_t)sizeof(a->chall))
			return -1;
	} else {
		char line[1024];
		memset(line, 0, sizeof(line));
		if (!fgets(line, sizeof(line) - 1, stdin))
			return -1;
		int r = hex2bin(line, reinterpret_cast<unsigned char *>(a->kh), sizeof(a->kh));
		if (r <= 0)
			return -1;
		apdu_blob.kl = (uint8_t)(r & 0xff);
		if (!fgets(line, sizeof(line) - 1, stdin))
			return -1;
		if (hex2bin(line, a->chall, sizeof(a->chall)) != (int)sizeof(a->chall))
			return -1;
	}
	return 0;
}


void sig_alarm(int x)
{
	exit(1);
}


int main(int argc, char **argv)
{
	input_filter_t fin = INPUT_BIN;
	output_filter_t fout = OUTPUT_BIN;
	string app_id = "pam_fido-u2f,type=u2f,kind=authentication,version=1";
	string devpath = "/dev/hidraw0";

	int c = 0;
	while ((c = getopt(argc, argv, "A:d:xX")) != -1) {
		switch (c) {
		case 'A':
			app_id = optarg;
			break;
		case 'x':
			fin = INPUT_HEX;
			break;
		case 'X':
			fout = OUTPUT_HEX;
			break;
		case 'd':
			devpath = optarg;
			break;
		}
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_alarm;
	sigaction(SIGALRM, &sa, NULL);
	alarm(30);

	if (input(&apdu_blob, fin) < 0)
		return -1;

	// create blob which is sent to token
	SHA256(reinterpret_cast<const unsigned char*>(app_id.c_str()), app_id.size(), apdu_blob.app);

	string msg = "";
	for (int tries = 0; tries < 3; ++tries) {
		// In udev case, it can take a short while until HID device comes up
		struct stat st;
		int failed = 1;
		for (int i = 0; i < 300; ++i) {
			if (stat(devpath.c_str(), &st) == 0) {
				failed = 0;
				break;
			}
			usleep(10000);
		}

		if (failed)
			continue;

		U2Fob *dev = NULL;
		if ((dev = U2Fob_create()) == NULL)
			return -1;

		if (U2Fob_open(dev, devpath.c_str()) != 0) {
			U2Fob_destroy(dev);
			return -1;
		}
		if (U2Fob_init(dev) != 0) {
			U2Fob_destroy(dev);
			return -1;
		}

		msg = "";
		string s = string(reinterpret_cast<char *>(&apdu_blob), offsetof(apdu_blob_t, kh) + apdu_blob.kl);
		int sw = U2Fob_apdu(dev, 0x0, U2F_INS_AUTHENTICATE, 0x3, 0, s, &msg);
		U2Fob_destroy(dev);

		if (sw == SW_NOUSER) {
			sleep(5);
			continue;
		}

		if (sw != SW_OK)
			return -1;

		// user presence?
		uint8_t up = (uint8_t)msg[0];
		if ((up & 0x1) != 0x1)
			return -1;
		break;
	}

	if (fout == OUTPUT_HEX) {
		for (string::size_type i = 0; i < msg.size(); ++i)
			printf("%02x", (uint8_t)(msg[i] & 0xff));
		printf("\n");
		fflush(stdout);
	} else {
		if (write(fileno(stdout), msg.c_str(), msg.size()) != (ssize_t)msg.size())
			return -1;
	}

	alarm(0);

	return 0;
}

