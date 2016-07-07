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

/* Enroll an FIDO-U2F NIST P-256 key on the security token and
 * print out the corresponding public key and certificate.
 *
 * As per FIDO U2F Raw Message Formats Proposed Standard from 09 Oct. 2014.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <cstring>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "u2f_util.h"

#include <openssl/ec.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>

using namespace std;

enum msg_type_t {
	ERROR_MSG_PERROR = 0,
	ERROR_MSG_SSL
};


enum sw_t {
	SW_OK	= 0x9000
};


void die(const char *msg, msg_type_t t = ERROR_MSG_PERROR)
{
	if (t == ERROR_MSG_SSL)
		fprintf(stderr, "%s: %s\n", msg, ERR_error_string(ERR_get_error(), NULL));
	else
		perror(msg);

	exit(errno);
}


void usage()
{
	printf("Usage: enroll [-A app-id] [-i device] [-d dumpfile] [-o outfile]\n");
	exit(1);
}


int main(int argc, char **argv)
{
	FILE *f = NULL, *fout = stdout;
	int c = 0;
	string infile = "/dev/hidraw0", dumpfile = "";
	string app = "pam_fido-u2f,type=u2f,kind=authentication,version=1";

	while ((c = getopt(argc, argv, "A:i:d:o:")) != -1) {
		switch (c) {
		case 'A':
			app = optarg;
			break;
		case 'i':
			infile = optarg;
			break;
		case 'd':
			dumpfile = optarg;
			break;
		case 'o':
			if (fout != stdout)
				break;
			if ((fout = fopen(optarg, "w")) == NULL)
				die("fopen");
			break;
		default:
			usage();
			break;
		}
	}

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();

	RAND_load_file("/dev/urandom", 256);
	ERR_clear_error();

	// the string blob the APDU returns for a registration message
	string msg = "";

	if (infile.find("/dev") != string::npos) {
		U2Fob *dev = NULL;
		if ((dev = U2Fob_create()) == NULL)
			die("U2Fob_create");

		if (U2Fob_open(dev, "/dev/hidraw0") != 0)
			die("U2Fob_open");
		if (U2Fob_init(dev) != 0)
			die("U2Fob_init");

		int sw = 0;

		unsigned char req[2*32];
		SHA256(reinterpret_cast<const unsigned char *>(app.c_str()), app.size(), req + 32);
		if (RAND_bytes(req, 32) != 1)
			die("RAND_bytes", ERROR_MSG_SSL);

		string s = string(reinterpret_cast<char *>(req), sizeof(req));
		if ((sw = U2Fob_apdu(dev, 0x0, U2F_INS_REGISTER, 0x1, 0, s, &msg)) != SW_OK) {
			fprintf(stderr, "Failure on APDU (sw=%x)\n", sw);
			die("U2Fob_apdu");
		}
		U2Fob_destroy(dev);
		printf("Got %d bytes (sw=%x)\n", (int)msg.size(), sw);
		if (dumpfile.size() > 0) {
			if ((f = fopen(dumpfile.c_str(), "w")) == NULL)
				die("fopen");
			fwrite(msg.c_str(), msg.size(), 1, f);
			fclose(f);
		}
	} else {
		if ((f = fopen(infile.c_str(), "r")) == NULL)
			die("fopen");
		struct stat st;
		if (fstat(fileno(f), &st) < 0)
			die("fstat");
		char *buf = new char[st.st_size];
		if (fread(buf, 1, st.st_size, f) != (size_t)st.st_size)
			die("fread");
		fclose(f);
		msg = string(buf, st.st_size);
		delete [] buf;
	}

	if (msg.size() <= 67)
		die("Something went wrong with the APDU");
	if (msg.size() < (size_t)(67 + (uint8_t)msg[66]))
		die("Something went wrong with the APDU");

	// Now all the byte fumbling part
	EC_GROUP *ecgrp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!ecgrp || !eckey)
		die("EC curve NIST P-256 init", ERROR_MSG_SSL);

	EC_POINT *point = EC_POINT_new(ecgrp);
	if (!point)
		die("EC_POINT_new", ERROR_MSG_SSL);

	if (EC_POINT_oct2point(ecgrp, point, (unsigned char *)msg.c_str() + 1, 65, NULL) != 1)
		die("EC_POINT_oct2point", ERROR_MSG_SSL);

	if (EC_KEY_set_public_key(eckey, point) != 1)
		die("EC_KEY_set_public_key", ERROR_MSG_SSL);

	EVP_PKEY *evpk = EVP_PKEY_new();
	if (!evpk)
		die("EVP_PKEY_new", ERROR_MSG_SSL);

	if (EVP_PKEY_assign_EC_KEY(evpk, eckey) != 1)
		die("EVP_PKEY_assign_EC_KEY", ERROR_MSG_SSL);

	fprintf(fout, "H=");
	for (uint8_t i = 0; i < (uint8_t)msg[66]; ++i)
		fprintf(fout, "%02x", (uint8_t)msg[66 + i + 1]);

	fprintf(fout, "\n");
	PEM_write_PUBKEY(fout, evpk);

	const unsigned char *cert = reinterpret_cast<const unsigned char*>(msg.c_str() + 67 + (uint8_t)msg[66]);
	X509 *x509 = d2i_X509(NULL, &cert, msg.size() - (67 + (uint8_t)msg[66]));
	if (!x509)
		die("d2i_X509", ERROR_MSG_SSL);
	printf("\npubkey claims to be signed with cert (unchecked!):\n\n");
	X509_print_fp(stdout, x509);

	X509_free(x509);
	EVP_PKEY_free(evpk);
	return 0;
}


