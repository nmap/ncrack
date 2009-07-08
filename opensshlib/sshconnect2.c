/* $OpenBSD: sshconnect2.c,v 1.171 2009/03/05 07:18:19 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <errno.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


#include "ssh.h"
#include "ssh2.h"
#include "xmalloc.h"
#include "buffer.h"
#include "packet.h"
#include "key.h"
#include "kex.h"
#include "myproposal.h"
#include "sshconnect.h"
#include "compat.h"
#include "cipher.h"
#include "misc.h"
#include "match.h"
#include "authfile.h"
#include "dh.h"
#include "authfd.h"
#include "log.h"
//#include "auth.h"



/*
 * Authenticate user
 */

typedef struct Authctxt Authctxt;
typedef struct Authmethod Authmethod;
typedef struct identity Identity;
typedef struct idlist Idlist;

struct identity {
	//TAILQ_ENTRY(identity) next;
	AuthenticationConnection *ac;	/* set if agent supports key */
	Key	*key;			/* public/private key */
	char	*filename;		/* comment for agent-only keys */
	int	tried;
	int	isprivate;		/* key points to the private key */
};
//TAILQ_HEAD(idlist, identity);

struct Authctxt {
	const char *server_user;
	const char *local_user;
	const char *host;
	const char *service;
	Authmethod *method;
	int success;
	char *authlist;
	/* pubkey */
	Identity key;
	AuthenticationConnection *agent;
	/* hostbased */
	Sensitive *sensitive;
	/* kbd-interactive */
	int info_req_seen;
	/* generic */
	void *methoddata;
};
struct Authmethod {
	char	*name;		/* string to compare against server's list */
	int	(*userauth)(Authctxt *authctxt);
	//void	(*cleanup)(Authctxt *authctxt);
	int	*enabled;	/* flag in option struct that enables method */
	//int	*batch_flag;	/* flag in option struct that disables method */
};

static Authmethod *authmethod_lookup(const char *name);
static int userauth_none(Authctxt *authctxt);
static int userauth_passwd(Authctxt *authctxt);



/* methods */
Authmethod method_none = {
	"none",
	userauth_none,
//	&none_enabled
};

Authmethod method_passwd = {
	"password",
	userauth_passwd,
//	&options.password_authentication
};


static int
userauth_passwd(Authctxt *authctxt)
{
#if 0
	char *password, *newpass;
	int authenticated = 0;
	int change;
	u_int len, newlen;

	change = packet_get_char();
	password = packet_get_string(&len);
	if (change) {
		/* discard new password from packet */
		newpass = packet_get_string(&newlen);
		memset(newpass, 0, newlen);
		xfree(newpass);
	}
	packet_check_eom();

	if (change)
		logit("password change not supported");
	else if (PRIVSEP(auth_password(authctxt, password)) == 1)
		authenticated = 1;
	memset(password, 0, len);
	xfree(password);
	return authenticated;
#endif
}


static int
userauth_none(Authctxt *authctxt)
{
#if 0
	none_enabled = 0;
	packet_check_eom();
	if (options.password_authentication)
		return (PRIVSEP(auth_password(authctxt, "")));
	return (0);
#endif
}




Authmethod *authmethods[] = {
	&method_none,
	&method_passwd,
	NULL
};




/*
 * SSH2 key exchange
 */

u_char *session_id2 = NULL;
u_int session_id2_len = 0;


Kex *
openssh_ssh_kex2(char *client_version_string, char *server_version_string,
  Buffer *ncrack_buf, Newkeys *ncrack_keys[MODE_MAX],
  CipherContext *send_context, CipherContext *receive_context)
{
	Kex *kex;

  myproposal[PROPOSAL_ENC_ALGS_CTOS] =
    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_CTOS]);
  myproposal[PROPOSAL_ENC_ALGS_STOC] =
    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_STOC]);

  myproposal[PROPOSAL_COMP_ALGS_CTOS] =
    myproposal[PROPOSAL_COMP_ALGS_STOC] = "none,zlib@openssh.com,zlib";

  /* start key exchange */
  kex = kex_setup(myproposal, ncrack_buf, ncrack_keys, send_context,
      receive_context);
  kex->kex[KEX_DH_GRP1_SHA1] = kexdh_client;
  kex->kex[KEX_DH_GRP14_SHA1] = kexdh_client;
  kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
  kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
  kex->client_version_string=client_version_string;
  kex->server_version_string=server_version_string;

  //dispatch_run(DISPATCH_BLOCK, &kex->done, kex);
  //

  return kex;

  //session_id2 = kex->session_id;
  //session_id2_len = kex->session_id_len;

}



void
openssh_start_userauth2(Buffer *ncrack_buf, Newkeys *ncrack_keys[MODE_MAX],
  CipherContext *send_context, CipherContext *receive_context)
{
	packet_start(SSH2_MSG_SERVICE_REQUEST);
	packet_put_cstring("ssh-userauth");
	packet_send(ncrack_buf, ncrack_keys, send_context, receive_context);
}




void
openssh_userauth2(Buffer *ncrack_buf, Newkeys *ncrack_keys[MODE_MAX],
  CipherContext *send_context, CipherContext *receive_context,
  const char *server_user, int type)
{
	Authctxt authctxt;

	debug("SSH2_MSG_SERVICE_REQUEST sent");
	if (type != SSH2_MSG_SERVICE_ACCEPT)
		fatal("Server denied authentication request: %d", type);
	if (packet_remaining() > 0) {
		char *reply = packet_get_string(NULL);
		debug2("service_accept: %s", reply);
		xfree(reply);
	} else {
		debug2("buggy server: service_accept w/o service");
	}
	packet_check_eom();
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	//if (options.preferred_authentications == NULL)
	//	options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, sizeof(authctxt));
//	pubkey_prepare(&authctxt);
	authctxt.server_user = server_user;
//	authctxt.local_user = local_user;
//	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = NULL;
	authctxt.methoddata = NULL;
	//authctxt.sensitive = sensitive;
	authctxt.info_req_seen = 0;
	if (authctxt.method == NULL)
		fatal("ssh_userauth2: internal error: cannot send userauth none request");

	/* initial userauth request */
  packet_start(SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(authctxt.server_user);
	packet_put_cstring(authctxt.service);
	packet_put_cstring(authctxt.method->name);
	packet_send(ncrack_buf, ncrack_keys, send_context, receive_context);
	//userauth_none(&authctxt);

#if 0
	dispatch_init(&input_userauth_error);
	dispatch_set(SSH2_MSG_USERAUTH_SUCCESS, &input_userauth_success);
	dispatch_set(SSH2_MSG_USERAUTH_FAILURE, &input_userauth_failure);
	dispatch_set(SSH2_MSG_USERAUTH_BANNER, &input_userauth_banner);
	dispatch_run(DISPATCH_BLOCK, &authctxt.success, &authctxt);	/* loop until success */
#endif

	//pubkey_cleanup(&authctxt);
	//dispatch_range(SSH2_MSG_USERAUTH_MIN, SSH2_MSG_USERAUTH_MAX, NULL);

	debug("Authentication succeeded (%s).", authctxt.method->name);
}

static Authmethod *
authmethod_lookup(const char *name)
{
	int i;

	if (name != NULL)
		for (i = 0; authmethods[i] != NULL; i++)
			if (authmethods[i]->enabled != NULL &&
			    *(authmethods[i]->enabled) != 0 &&
			    strcmp(name, authmethods[i]->name) == 0)
				return authmethods[i];
	debug2("Unrecognized authentication method name: %s",
	    name ? name : "NULL");
	return NULL;
}

