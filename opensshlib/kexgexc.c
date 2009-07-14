/* $OpenBSD: kexgexc.c,v 1.11 2006/11/06 21:25:28 markus Exp $ */
/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "xmalloc.h"
#include "buffer.h"
#include "key.h"
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "ssh2.h"
#include "compat.h"

void
kexgex_client(ncrack_ssh_state *nstate)
{
	int min, max, nbits;

	nbits = dh_estimate(nstate->kex->we_need * 8);

	if (nstate->datafellows & SSH_OLD_DHGEX) {
		/* Old GEX request */
		packet_start(nstate, SSH2_MSG_KEX_DH_GEX_REQUEST_OLD);
		packet_put_int(nstate, nbits);
		min = DH_GRP_MIN;
		max = DH_GRP_MAX;
		debug("SSH2_MSG_KEX_DH_GEX_REQUEST_OLD(%u) sent", nbits);
	} else {
		/* New GEX request */
		min = DH_GRP_MIN;
		max = DH_GRP_MAX;
		packet_start(nstate, SSH2_MSG_KEX_DH_GEX_REQUEST);
		packet_put_int(nstate, min);
		packet_put_int(nstate, nbits);
		packet_put_int(nstate, max);
		debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
		    min, nbits, max);
	}
#ifdef DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
	    min, nbits, max);
#endif
	packet_send(nstate);

}


void
openssh_kexgex_2(ncrack_ssh_state *nstate)
{
  BIGNUM *p = NULL, *g = NULL;
  int min, max;

  min = DH_GRP_MIN;
  max = DH_GRP_MAX;

  debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
 // packet_read_expect(SSH2_MSG_KEX_DH_GEX_GROUP);

  if ((p = BN_new()) == NULL)
    fatal("BN_new");
  packet_get_bignum2(nstate, p);
  if ((g = BN_new()) == NULL)
    fatal("BN_new");
  packet_get_bignum2(nstate, g);
  packet_check_eom(nstate);

  if (BN_num_bits(p) < min || BN_num_bits(p) > max)
    fatal("DH_GEX group out of range: %d !< %d !< %d",
        min, BN_num_bits(p), max);

  nstate->dh = dh_new_group(g, p);
  dh_gen_key(nstate->dh, nstate->kex->we_need * 8);

#ifdef DEBUG_KEXDH
  DHparams_print_fp(stderr, nstate->dh);
  fprintf(stderr, "pub= ");
  BN_print_fp(stderr, nstate->dh->pub_key);
  fprintf(stderr, "\n");
#endif

  debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
  /* generate and send 'e', client DH public key */
  packet_start(nstate, SSH2_MSG_KEX_DH_GEX_INIT);
  packet_put_bignum2(nstate, nstate->dh->pub_key);
  packet_send(nstate);

}


void
openssh_kexgex_3(ncrack_ssh_state *nstate)
{
  BIGNUM *dh_server_pub = NULL, *shared_secret = NULL;
  Key *server_host_key;
  u_char *kbuf, *hash, *signature = NULL, *server_host_key_blob = NULL;
  u_int klen, slen, sbloblen, hashlen;
  int kout;
  int min, max, nbits;

  min = DH_GRP_MIN;
  max = DH_GRP_MAX;

  nbits = dh_estimate(nstate->kex->we_need * 8);

  debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
  //packet_read_expect(SSH2_MSG_KEX_DH_GEX_REPLY);

  /* key, cert */
  server_host_key_blob = packet_get_string(nstate, &sbloblen);

  server_host_key = key_from_blob(server_host_key_blob, sbloblen);
  if (server_host_key == NULL)
    fatal("cannot decode server_host_key_blob");
  if (server_host_key->type != nstate->kex->hostkey_type)
    fatal("type mismatch for decoded server_host_key_blob");


  /* DH parameter f, server public DH key */
  if ((dh_server_pub = BN_new()) == NULL)
    fatal("dh_server_pub == NULL");
  packet_get_bignum2(nstate, dh_server_pub);

#ifdef DEBUG_KEXDH
  fprintf(stderr, "dh_server_pub= ");
  BN_print_fp(stderr, dh_server_pub);
  fprintf(stderr, "\n");
  debug("bits %d", BN_num_bits(dh_server_pub));
#endif

  /* signed H */
  signature = packet_get_string(nstate, &slen);
  packet_check_eom(nstate);

  if (!dh_pub_is_valid(nstate->dh, dh_server_pub))
    packet_disconnect("bad server public DH value");

  klen = DH_size(nstate->dh);
  kbuf = xmalloc(klen);
  if ((kout = DH_compute_key(kbuf, dh_server_pub, nstate->dh)) < 0)
    fatal("DH_compute_key: failed");
#ifdef DEBUG_KEXDH
  dump_digest("shared secret", kbuf, kout);
#endif
  if ((shared_secret = BN_new()) == NULL)
    fatal("kexgex_client: BN_new failed");
  if (BN_bin2bn(kbuf, kout, shared_secret) == NULL)
    fatal("kexgex_client: BN_bin2bn failed");
  memset(kbuf, 0, klen);
  xfree(kbuf);

  if (nstate->datafellows & SSH_OLD_DHGEX)
    min = max = -1;

  /* calc and verify H */
  kexgex_hash(
      nstate->kex->evp_md,
      nstate->kex->client_version_string,
      nstate->kex->server_version_string,
      buffer_ptr(&nstate->kex->my), buffer_len(&nstate->kex->my),
      buffer_ptr(&nstate->kex->peer), buffer_len(&nstate->kex->peer),
      server_host_key_blob, sbloblen,
      min, nbits, max,
      nstate->dh->p, nstate->dh->g,
      nstate->dh->pub_key,
      dh_server_pub,
      shared_secret,
      &hash, &hashlen
      );

  /* have keys, free DH */
  DH_free(nstate->dh);
  xfree(server_host_key_blob);
  BN_clear_free(dh_server_pub);


  /* NCRACK: this is normally called by the ssh client/server
   * when they begin - we should also do it whenever we invoke
   * the ssh module for the first time */
  OpenSSL_add_all_digests();
  
  if (key_verify(nstate, server_host_key, signature, slen, hash, hashlen) != 1)
    fatal("key_verify failed for server_host_key");
    
  key_free(server_host_key);
  xfree(signature);


  /* save session id */
  if (nstate->kex->session_id == NULL) {
    nstate->kex->session_id_len = hashlen;
    nstate->kex->session_id = xmalloc(nstate->kex->session_id_len);
    memcpy(nstate->kex->session_id, hash, nstate->kex->session_id_len);
  }
  kex_derive_keys(nstate, hash, hashlen, shared_secret);
  BN_clear_free(shared_secret);

  kex_finish(nstate);
}
