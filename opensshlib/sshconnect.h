/* $OpenBSD: sshconnect.h,v 1.24 2007/09/04 11:15:56 djm Exp $ */

/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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

#include "key.h"
#include "cipher.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct Sensitive Sensitive;
struct Sensitive {
	Key	**keys;
	int	nkeys;
	int	external_keysign;
};

int
ssh_connect(const char *, struct sockaddr_storage *, u_short, int, int,
    int *, int, int, const char *);

void
ssh_login(Sensitive *, const char *, struct sockaddr *, struct passwd *, int);

int	 verify_host_key(char *, struct sockaddr *, Key *);

void	 ssh_kex(char *, struct sockaddr *);

void	 ssh_userauth1(const char *, const char *, char *, Sensitive *);

void	 ssh_put_password(char *);
int	 ssh_local_cmd(const char *);


void openssh_ssh_kex2(ncrack_ssh_state *nstate,
  char *client_version_string, char *server_version_string);

void openssh_userauth2(ncrack_ssh_state *nstate, const char *server_user,
    const char *password);

void openssh_start_userauth2(ncrack_ssh_state *nstate);

int openssh_userauth2_service_rep(ncrack_ssh_state *nstate);

#ifdef __cplusplus
} /* End of 'extern "C"' */
#endif
