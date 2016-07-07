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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <cstring>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <poll.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#ifdef __OS_LINUX
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
#include <security/pam_misc.h>
#endif

#include <openssl/ec.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>

static const char *default_keydir = "/etc/u2f/keys/";
static const char *app_id = "pam_fido-u2f,type=u2f,kind=authentication,version=1";

#ifndef U2F_SIGNPATH
#define U2F_SIGNPATH "/usr/local/bin/u2f-sign"
#endif

enum {
	SIGN_TIMEOUT = 15
};


using namespace std;


struct u2f_auth {
	pam_handle_t *pamh;
	string devpath, user, keydir, sigdata, sig;
	EVP_PKEY *pkey;
};


#ifdef __OS_DARWIN

#include <syslog.h>
#include <stdarg.h>

static int pam_syslog(pam_handle_t *pamh, int level, const char *msg, ...)
{
	va_list va;
	va_start(va, msg);
	openlog("pam_fido-u2f", LOG_PID, LOG_AUTH);
	vsyslog(level, msg, va);
	closelog();
	va_end(va);
}

#endif


static int create_response(struct u2f_auth *auth)
{
	FILE *f = NULL;

	string keyfile = auth->keydir;
	keyfile += "_";
	keyfile += auth->user;

	// open key file belonging to this user
	if ((f = fopen(keyfile.c_str(), "r")) == NULL) {
		pam_syslog(auth->pamh, LOG_ERR, "fopen() of keyfile for user '%s' failed.", auth->user.c_str());
		return -1;
	}

	// parse keyfile (handle and PEM key)
	char line[1024], *h = NULL;
	for (;!feof(f);) {
		memset(line, 0, sizeof(line));
		if (!fgets(line, sizeof(line) - 1, f))
			break;
		if ((h = strstr(line, "H=")) != NULL) {
			h += 2;
			break;
		}
	}
	void *r = PEM_read_PUBKEY(f, &auth->pkey, NULL, NULL);
	fclose(f);

	if (!h || !r) {
		pam_syslog(auth->pamh, LOG_ERR, "Failed to find valid key or handle in '%s'.", keyfile.c_str());
		return -1;
	}

	// create blob which is sent to token
	unsigned char md[32];
	SHA256(reinterpret_cast<const unsigned char*>(app_id), strlen(app_id), md);
	auth->sigdata = string(reinterpret_cast<char *>(md), sizeof(md));

	unsigned char rand[32];
	if (RAND_bytes(rand, sizeof(rand)) != 1) {
		pam_syslog(auth->pamh, LOG_ERR, "Failed to generate RAND bytes.");
		return -1;
	}

	// standard demands SHA256 of challenge, so here we go...
	SHA256(rand, sizeof(rand), md);

	int p[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) < 0) {
		pam_syslog(auth->pamh, LOG_ERR, "Failed to spawn sign helper.");
		return -1;
	}

	// tell user about it
	const pam_conv *conv = NULL;
	pam_response *presp = NULL;
	pam_message pmsg = {PAM_TEXT_INFO, "User presence required! Insert coin and/or press button.\n"};
	const pam_message *cpmsg = &pmsg;
	if (pam_get_item(auth->pamh, PAM_CONV, reinterpret_cast<const void **>(&conv)) == PAM_SUCCESS) {
		if (conv)
			conv->conv(1, &cpmsg, &presp, NULL);
		// free(NULL) is defined
		if (presp)
			free(presp->resp);
		free(presp);
	}

	int status = -1;
	pid_t pid = fork();
	if (pid == 0) {
		close(0); close(1); close(2); close(p[0]);
		if (dup2(p[1], 0) < 0 || dup2(p[1], 1) < 0 || dup2(p[1], 2) < 0)
			exit(1);

		close(p[1]);

		char *const u2f_sign[] = {
			strdup(U2F_SIGNPATH),
			strdup("-A"), strdup(app_id),
			strdup("-x"),
			strdup("-d"), strdup(auth->devpath.c_str()), NULL
		};

		execve(*u2f_sign, u2f_sign, NULL);
		exit(1);
	} else if (pid < 0) {
		pam_syslog(auth->pamh, LOG_ERR, "Failed to spawn sign helper.");
		return -1;
	}
	close(p[1]);
	if ((f = fdopen(p[0], "r+")) == NULL) {
		pam_syslog(auth->pamh, LOG_ERR, "Failed to spawn sign helper.");
		waitpid(pid, &status, WNOHANG);
		return -1;
	}
	// key handle to use
	fprintf(f, "%s", h);
	// challenge to sign, app challenge goes via -A
	for (size_t i = 0; i < sizeof(md); ++i)
		fprintf(f, "%02x", md[i]);
	fprintf(f, "\n"); fflush(f);

	struct pollfd pfd = {p[0], POLLIN, 0};
	int n = poll(&pfd, 1, SIGN_TIMEOUT*1000);

	// any POLLERR or POLLHUP condition in revent is error
	if (n != 1 || pfd.revents != POLLIN) {
		pam_syslog(auth->pamh, LOG_ERR, "Error while waiting for sign operation to finish.");
		waitpid(pid, &status, WNOHANG);
		fclose(f);
		return -1;
	}

	// input was hex encoding, output goes raw
	n = 0;
	char sbuf[1024];
	n = read(p[0], sbuf, sizeof(sbuf));
	fclose(f);
	//close(p[0]); not needed, fclose() is doing so

	if (n <= 0) {
		pam_syslog(auth->pamh, LOG_ERR, "Failed to read signature from sign helper.");
		return -1;
	}

	// No WNOHANG here: login collects all childs via wait(-1) and closing
	// PAM session after it found the first child exiting, which could be u2f-sign
	// if we did not properly collect u2f-sign's exit(). u2f-sign is guaranteed to
	// finish in at least 30s by alarm().
	if (waitpid(pid, &status, 0) < 0) {
		pam_syslog(auth->pamh, LOG_ERR, "Failed to get exit status from sign helper.");
		return -1;
	}

	if (WEXITSTATUS(status) != 0) {
		pam_syslog(auth->pamh, LOG_ERR, "Sign helper did not exit cleanly.");
		return -1;
	}

	string msg = string(sbuf, n);

	// user presence?
	uint8_t up = (uint8_t)msg[0];
	if ((up & 0x1) != 0x1) {
		pam_syslog(auth->pamh, LOG_ERR, "Failed to check user presence.");
		return -1;
	}

	auth->sigdata += msg.substr(0, 1 + 4);
	auth->sigdata += string(reinterpret_cast<char *>(md), sizeof(md));

	auth->sig = msg.substr(1 + 4);
	return 0;
}


// 0 on success
static int check_signature(u2f_auth *auth)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(auth->pkey, NULL);
	if (!ctx)
		return -1;

	/* The following seems not necessary since curve params are saved inside the PEM
	 * file along with EC keydata. However it can also be set explicitely.
	if (EVP_PKEY_paramgen_init(ctx) != 1)
		return -1;

	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0)
		return -1;
	*/

	if (EVP_PKEY_verify_init(ctx) != 1)
		return -1;

	unsigned char md[32];
	SHA256(reinterpret_cast<const unsigned char *>(auth->sigdata.c_str()), auth->sigdata.size(), md);

	int r = EVP_PKEY_verify(ctx, reinterpret_cast<const unsigned char*>(auth->sig.c_str()), auth->sig.size(), md, sizeof(md));

	EVP_PKEY_CTX_free(ctx);

	if (r != 1)
		return -1;

	return 0;
}


extern "C" {

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	char keydir[1024], device[1024];
	const char *user = NULL;
	// only local supported yet
	int local_device = 1;

	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();

	memset(keydir, 0, sizeof(keydir));
	memset(device, 0, sizeof(device));

	snprintf(device, sizeof(device), "/dev/hidraw0");
	snprintf(keydir, sizeof(keydir), "%s", default_keydir);

	for (int i = 0; i < argc; ++i) {
		if (!argv[i])
			continue;
		if (sscanf(argv[i], "device=%1023c", device) == 1)
			continue;
		if (sscanf(argv[i], "local") == 1) {
			local_device = 1;
			continue;
		}
	}

	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "Unable to find user.");
		return PAM_USER_UNKNOWN;
	}

	if (getpwnam(user) == NULL) {
		pam_syslog(pamh, LOG_ERR, "User does not exist.");
		return PAM_USER_UNKNOWN;
	}

	pam_syslog(pamh, LOG_INFO, "About to check U2F token for user '%s'.", user);

	struct u2f_auth auth = {pamh, device, user, keydir};

	int r = -1;

	if (local_device)
		r = create_response(&auth);

	if (r != 0)
		return PAM_PERM_DENIED;

	if (check_signature(&auth) != 0)
		return PAM_PERM_DENIED;

	return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}


#ifdef PAM_STATIC

struct pam_module _pam_schroedinger = {
	"pam_fido-u2f",
	pam_sm_authenticate,
	pam_sm_setcred,
	NULL,	/* acct_mgmt		*/
	NULL,	/* open_session		*/
	NULL,	/* close_session	*/
	NULL	/* chauthtok		*/
};


#endif

} // extern "C"

