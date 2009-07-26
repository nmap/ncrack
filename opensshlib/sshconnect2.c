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
#include <sys/stat.h>

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifndef WIN32
#include <unistd.h>
#include <pwd.h>
#endif


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
#include "dh.h"
#include "log.h"


/*
 * Authenticate user
 */

typedef struct Authctxt Authctxt;
typedef struct Authmethod Authmethod;

struct Authctxt {
	const char *server_user;
	const char *local_user;
	const char *host;
	const char *service;
	Authmethod *method;
	int success;
	char *authlist;
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
	int	*enabled;	/* flag in option struct that enables method */
};


/*
 * SSH2 key exchange
 */
void
openssh_ssh_kex2(ncrack_ssh_state *nstate, char *client_version_string,
  char *server_version_string)
{
  myproposal[PROPOSAL_ENC_ALGS_CTOS] =
    compat_cipher_proposal(nstate, myproposal[PROPOSAL_ENC_ALGS_CTOS]);
  myproposal[PROPOSAL_ENC_ALGS_STOC] =
    compat_cipher_proposal(nstate, myproposal[PROPOSAL_ENC_ALGS_STOC]);

  myproposal[PROPOSAL_COMP_ALGS_CTOS] =
    myproposal[PROPOSAL_COMP_ALGS_STOC] = "none,zlib@openssh.com,zlib";

  /* start key exchange */
  kex_setup(nstate, myproposal);
  nstate->kex->kex[KEX_DH_GRP1_SHA1] = kexdh_client;
  nstate->kex->kex[KEX_DH_GRP14_SHA1] = kexdh_client;
  nstate->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
  nstate->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
  nstate->kex->client_version_string = client_version_string;
  nstate->kex->server_version_string = server_version_string;
}


void
openssh_start_userauth2(ncrack_ssh_state *nstate)
{
	packet_start(nstate, SSH2_MSG_SERVICE_REQUEST);
	packet_put_cstring(nstate, "ssh-userauth");
	packet_send(nstate);
}


int
openssh_userauth2_service_rep(ncrack_ssh_state *nstate)
{
	debug("SSH2_MSG_SERVICE_REQUEST sent");
	if (nstate->type != SSH2_MSG_SERVICE_ACCEPT)
    return -1;
	if (packet_remaining(nstate) > 0) { 
		char *reply = packet_get_string(nstate, NULL);
		debug2("service_accept: %s", reply);
		xfree(reply);
	} else {
		debug2("buggy server: service_accept w/o service");
	}
	packet_check_eom(nstate);
	debug("SSH2_MSG_SERVICE_ACCEPT received");
  return 0;
}


void
openssh_userauth2(ncrack_ssh_state *nstate, const char *server_user,
    const char *password)
{
	packet_start(nstate, SSH2_MSG_USERAUTH_REQUEST);
	packet_put_cstring(nstate, server_user);
	packet_put_cstring(nstate, "ssh-connection");
	packet_put_cstring(nstate, "password");
	packet_put_char(nstate, 0);
	packet_put_cstring(nstate, password);
	packet_add_padding(nstate, 64);
	packet_send(nstate);
}

