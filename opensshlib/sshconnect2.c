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


#include "xmalloc.h"
#include "buffer.h"
#include "packet.h"
#include "key.h"
#include "kex.h"
#include "myproposal.h"
#include "sshconnect.h"
#include "compat.h"
#include "cipher.h"



/* import */
extern char *client_version_string;
extern char *server_version_string;

/*
 * SSH2 key exchange
 */

u_char *session_id2 = NULL;
u_int session_id2_len = 0;


Kex *
ssh_kex2(Buffer *ncrack_buf)
{
	Kex *kex;

  packet_set_connection();


  myproposal[PROPOSAL_ENC_ALGS_CTOS] =
    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_CTOS]);
  myproposal[PROPOSAL_ENC_ALGS_STOC] =
    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_STOC]);

  myproposal[PROPOSAL_COMP_ALGS_CTOS] =
    myproposal[PROPOSAL_COMP_ALGS_STOC] = "none,zlib@openssh.com,zlib";

  /* start key exchange */
  kex = kex_setup(myproposal, ncrack_buf);
  kex->kex[KEX_DH_GRP1_SHA1] = kexdh_client;
  kex->kex[KEX_DH_GRP14_SHA1] = kexdh_client;
  kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
  kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
//  kex->client_version_string=client_version_string;
//  kex->server_version_string=server_version_string;

  //dispatch_run(DISPATCH_BLOCK, &kex->done, kex);
  //

  return kex;

  //session_id2 = kex->session_id;
  //session_id2_len = kex->session_id_len;

}


