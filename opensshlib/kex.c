/* $OpenBSD: kex.c,v 1.80 2008/09/06 12:24:13 djm Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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

#ifndef WIN32
 #include <sys/param.h>
#endif

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "xmalloc.h"
#include "ssh2.h"
#include "buffer.h"
#include "packet.h"
#include "compat.h"
#include "cipher.h"
#include "key.h"
#include "kex.h"
#include "log.h"
#include "mac.h"
#include "match.h"


#define KEX_COOKIE_LEN	16

#if OPENSSL_VERSION_NUMBER >= 0x00907000L
# if defined(HAVE_EVP_SHA256)
# define evp_ssh_sha256 EVP_sha256
# else
extern const EVP_MD *evp_ssh_sha256(void);
# endif
#endif

/* prototype */
static void kex_kexinit_finish(ncrack_ssh_state *nstate);
static void kex_choose_conf(ncrack_ssh_state *nstate);

/* put algorithm proposal into buffer */
static void
kex_prop2buf(Buffer *b, char *proposal[PROPOSAL_MAX])
{
	u_int i;

	buffer_clear(b);
	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	for (i = 0; i < KEX_COOKIE_LEN; i++)
		buffer_put_char(b, 0);
	for (i = 0; i < PROPOSAL_MAX; i++)
		buffer_put_cstring(b, proposal[i]);
	buffer_put_char(b, 0);			/* first_kex_packet_follows */
	buffer_put_int(b, 0);			/* uint32 reserved */
}

/* parse buffer and return algorithm proposal */
static char **
kex_buf2prop(Buffer *raw, int *first_kex_follows)
{
	Buffer b;
	u_int i;
	char **proposal;

	proposal = xcalloc(PROPOSAL_MAX, sizeof(char *));

	buffer_init(&b);
	buffer_append(&b, buffer_ptr(raw), buffer_len(raw));
	/* skip cookie */
	for (i = 0; i < KEX_COOKIE_LEN; i++)
		buffer_get_char(&b);
	/* extract kex init proposal strings */
	for (i = 0; i < PROPOSAL_MAX; i++) {
		proposal[i] = buffer_get_string(&b,NULL);
		debug2("kex_parse_kexinit: %s", proposal[i]);
	}
	/* first kex follows / reserved */
	i = buffer_get_char(&b);
	if (first_kex_follows != NULL)
		*first_kex_follows = i;
	debug2("kex_parse_kexinit: first_kex_follows %d ", i);
	i = buffer_get_int(&b);
	debug2("kex_parse_kexinit: reserved %u ", i);
	buffer_free(&b);
	return proposal;
}

static void
kex_prop_free(char **proposal)
{
	u_int i;

	for (i = 0; i < PROPOSAL_MAX; i++)
		xfree(proposal[i]);
	xfree(proposal);
}


static void
kex_reset_dispatch(void)
{
#if 0
	dispatch_range(SSH2_MSG_TRANSPORT_MIN,
	    SSH2_MSG_TRANSPORT_MAX, &kex_protocol_error);
	dispatch_set(SSH2_MSG_KEXINIT, &kex_input_kexinit);
#endif
}

void
kex_finish(ncrack_ssh_state *nstate)
{
	kex_reset_dispatch();

	packet_start(nstate, SSH2_MSG_NEWKEYS);
	packet_send(nstate);
  
	/* packet_write_wait(); */
	debug("SSH2_MSG_NEWKEYS sent");

	debug("expecting SSH2_MSG_NEWKEYS");
//	packet_read_expect(SSH2_MSG_NEWKEYS);
//	packet_check_eom();
	debug("SSH2_MSG_NEWKEYS received");

	nstate->kex->done = 1;
	buffer_clear(&nstate->kex->peer);
	/* buffer_clear(&kex->my); */
	nstate->kex->flags &= ~KEX_INIT_SENT;
	xfree(nstate->kex->name);
	nstate->kex->name = NULL;
}

void
kex_send_kexinit(ncrack_ssh_state *nstate)
{
	u_int32_t rnd = 0;
	u_char *cookie;
	u_int i;

	if (nstate->kex == NULL) {
		ssherror("kex_send_kexinit: no kex, cannot rekey");
		return;
	}
	if (nstate->kex->flags & KEX_INIT_SENT) {
		debug("KEX_INIT_SENT");
		return;
	}
	nstate->kex->done = 0;

	/* generate a random cookie */
	if (buffer_len(&nstate->kex->my) < KEX_COOKIE_LEN)
		fatal("kex_send_kexinit: kex proposal too short");
	cookie = buffer_ptr(&nstate->kex->my);
	for (i = 0; i < KEX_COOKIE_LEN; i++) {
		if (i % 4 == 0) 
#ifndef WIN32
			rnd = random();
#else
			rnd = rand();
#endif
		cookie[i] = rnd;
		rnd >>= 8;
	}
	packet_start(nstate, SSH2_MSG_KEXINIT);
	packet_put_raw(nstate, buffer_ptr(&nstate->kex->my),
      buffer_len(&nstate->kex->my));

	packet_send(nstate);
	nstate->kex->flags |= KEX_INIT_SENT;
}

/* ARGSUSED */
void
openssh_kex_input_kexinit(ncrack_ssh_state *nstate)
{
	char *ptr;
	u_int i, dlen;

	debug("SSH2_MSG_KEXINIT received");
	if (nstate->kex == NULL)
		fatal("kex_input_kexinit: no kex, cannot rekey");

	ptr = packet_get_raw(nstate, &dlen);
	buffer_append(&nstate->kex->peer, ptr, dlen);

	/* discard packet */
	for (i = 0; i < KEX_COOKIE_LEN; i++)
		packet_get_char(nstate);
	for (i = 0; i < PROPOSAL_MAX; i++)
		xfree(packet_get_string(nstate, NULL));
	(void) packet_get_char(nstate);
	(void) packet_get_int(nstate);
	packet_check_eom(nstate);

	kex_kexinit_finish(nstate);
}

void
kex_setup(ncrack_ssh_state *nstate, char *proposal[PROPOSAL_MAX])
{
	nstate->kex = xcalloc(1, sizeof(*nstate->kex));
	buffer_init(&nstate->kex->peer);
	buffer_init(&nstate->kex->my);
	kex_prop2buf(&nstate->kex->my, proposal);
	nstate->kex->done = 0;

	kex_send_kexinit(nstate); /* we start */
	//kex_reset_dispatch();

}

static void
kex_kexinit_finish(ncrack_ssh_state *nstate)
{
	//if (!(kex->flags & KEX_INIT_SENT))
	//	kex_send_kexinit(kex, ncrack_buf);

	kex_choose_conf(nstate);

	if (nstate->kex->kex_type >= 0 && nstate->kex->kex_type < KEX_MAX &&
	    nstate->kex->kex[nstate->kex->kex_type] != NULL) {
		(nstate->kex->kex[nstate->kex->kex_type])(nstate);
	} else {
		fatal("Unsupported key exchange %d", nstate->kex->kex_type);
	}
}

static void
choose_enc(Enc *enc, char *client, char *server)
{
	char *name = match_list(client, server, NULL);
	if (name == NULL)
		fatal("no matching cipher found: client %s server %s",
		    client, server);
	if ((enc->cipher = cipher_by_name(name)) == NULL)
		fatal("matching cipher is not supported: %s", name);
	enc->name = name;
	enc->enabled = 0;
	enc->iv = NULL;
	enc->key = NULL;
	enc->key_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
}

static void
choose_mac(ncrack_ssh_state *nstate, Mac *mac, char *client, char *server)
{
	char *name = match_list(client, server, NULL);
	if (name == NULL)
		fatal("no matching mac found: client %s server %s",
		    client, server);
	if (mac_setup(mac, name) < 0)
		fatal("unsupported mac %s", name);
	/* truncate the key */
	if (nstate->datafellows & SSH_BUG_HMAC)
		mac->key_len = 16;
	mac->name = name;
	mac->key = NULL;
	mac->enabled = 0;
}

static void
choose_comp(Comp *comp, char *client, char *server)
{
	char *name = match_list(client, server, NULL);
	if (name == NULL)
		fatal("no matching comp found: client %s server %s", client, server);
	if (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} else if (strcmp(name, "zlib") == 0) {
		comp->type = COMP_ZLIB;
	} else if (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} else {
		fatal("unsupported comp %s", name);
	}
	comp->name = name;
}

static void
choose_kex(Kex *k, char *client, char *server)
{
	k->name = match_list(client, server, NULL);

	if (k->name == NULL)
		fatal("Unable to negotiate a key exchange method");
	if (strcmp(k->name, KEX_DH1) == 0) {
		k->kex_type = KEX_DH_GRP1_SHA1;
		k->evp_md = EVP_sha1();
	} else if (strcmp(k->name, KEX_DH14) == 0) {
		k->kex_type = KEX_DH_GRP14_SHA1;
		k->evp_md = EVP_sha1();
	} else if (strcmp(k->name, KEX_DHGEX_SHA1) == 0) {
		k->kex_type = KEX_DH_GEX_SHA1;
		k->evp_md = EVP_sha1();
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
	} else if (strcmp(k->name, KEX_DHGEX_SHA256) == 0) {
		k->kex_type = KEX_DH_GEX_SHA256;
		k->evp_md = evp_ssh_sha256();
#endif
	} else
		fatal("bad kex alg %s", k->name);
}

static void
choose_hostkeyalg(Kex *k, char *client, char *server)
{
	char *hostkeyalg = match_list(client, server, NULL);
	if (hostkeyalg == NULL)
		fatal("no hostkey alg");
	k->hostkey_type = key_type_from_name(hostkeyalg);
	if (k->hostkey_type == KEY_UNSPEC)
		fatal("bad hostkey alg '%s'", hostkeyalg);
	xfree(hostkeyalg);
}

static int
proposals_match(char *my[PROPOSAL_MAX], char *peer[PROPOSAL_MAX])
{
	static int check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_KEY_ALGS, -1
	};
	int *idx;
	char *p;

	for (idx = &check[0]; *idx != -1; idx++) {
		if ((p = strchr(my[*idx], ',')) != NULL)
			*p = '\0';
		if ((p = strchr(peer[*idx], ',')) != NULL)
			*p = '\0';
		if (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			return (0);
		}
	}
	debug2("proposals match");
	return (1);
}

static void
kex_choose_conf(ncrack_ssh_state *nstate)
{
	Newkeys *newkeys;
	char **my, **peer;
	char **cprop, **sprop;
	int nenc, nmac, ncomp;
	u_int mode, ctos, need;
	int first_kex_follows;

	my   = kex_buf2prop(&nstate->kex->my, NULL);
	peer = kex_buf2prop(&nstate->kex->peer, &first_kex_follows);

	if (nstate->kex->server) {
		cprop=peer;
		sprop=my;
	} else {
		cprop=my;
		sprop=peer;
	}

	/* Algorithm Negotiation */
	for (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = xcalloc(1, sizeof(*newkeys));
		nstate->kex->newkeys[mode] = newkeys;
		ctos = (!nstate->kex->server && mode == MODE_OUT) ||
		    (nstate->kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		choose_enc (&newkeys->enc,  cprop[nenc],  sprop[nenc]);
		choose_mac (nstate, &newkeys->mac,  cprop[nmac],  sprop[nmac]);
		choose_comp(&newkeys->comp, cprop[ncomp], sprop[ncomp]);
#if 0
		fprintf(stderr, "kex: %s %s %s %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    newkeys->mac.name,
		    newkeys->comp.name);
#endif 
	}
	choose_kex(nstate->kex, cprop[PROPOSAL_KEX_ALGS], sprop[PROPOSAL_KEX_ALGS]);
	choose_hostkeyalg(nstate->kex, cprop[PROPOSAL_SERVER_HOST_KEY_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_KEY_ALGS]);
	need = 0;
	for (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = nstate->kex->newkeys[mode];
		if (need < newkeys->enc.key_len)
			need = newkeys->enc.key_len;
		if (need < newkeys->enc.block_size)
			need = newkeys->enc.block_size;
		if (need < newkeys->mac.key_len)
			need = newkeys->mac.key_len;
	}
	/* XXX need runden? */
	nstate->kex->we_need = need;

	/* ignore the next message if the proposals do not match */
	if (first_kex_follows && !proposals_match(my, peer) &&
	    !(nstate->datafellows & SSH_BUG_FIRSTKEX)) {
		//nstate->type = packet_read();
		debug2("skipping next packet (type %u)", nstate->type);
	}

	kex_prop_free(my);
	kex_prop_free(peer);
}

static u_char *
derive_key(ncrack_ssh_state *nstate, int id, u_int need, u_char *hash,
    u_int hashlen, BIGNUM *shared_secret)
{
	Buffer b;
	EVP_MD_CTX md;
	char c = id;
	u_int have;
	int mdsz;
	u_char *digest;

	if ((mdsz = EVP_MD_size(nstate->kex->evp_md)) <= 0)
		fatal("bad kex md size %d", mdsz);
	digest = xmalloc(roundup(need, mdsz));

	buffer_init(&b);
	buffer_put_bignum2(&b, shared_secret);

	/* K1 = HASH(K || H || "A" || session_id) */
	EVP_DigestInit(&md, nstate->kex->evp_md);
	if (!(nstate->datafellows & SSH_BUG_DERIVEKEY))
		EVP_DigestUpdate(&md, buffer_ptr(&b), buffer_len(&b));
	EVP_DigestUpdate(&md, hash, hashlen);
	EVP_DigestUpdate(&md, &c, 1);
	EVP_DigestUpdate(&md, nstate->kex->session_id, nstate->kex->session_id_len);
	EVP_DigestFinal(&md, digest, NULL);

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	for (have = mdsz; need > have; have += mdsz) {
		EVP_DigestInit(&md, nstate->kex->evp_md);
		if (!(nstate->datafellows & SSH_BUG_DERIVEKEY))
			EVP_DigestUpdate(&md, buffer_ptr(&b), buffer_len(&b));
		EVP_DigestUpdate(&md, hash, hashlen);
		EVP_DigestUpdate(&md, digest, have);
		EVP_DigestFinal(&md, digest + have, NULL);
	}
	buffer_free(&b);
#ifdef DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	return digest;
}

Newkeys *current_keys[MODE_MAX];

#define NKEYS	6
void
kex_derive_keys(ncrack_ssh_state *nstate,
    u_char *hash, u_int hashlen, BIGNUM *shared_secret)
{
	u_char *keys[NKEYS];
	u_int i, mode, ctos;

	for (i = 0; i < NKEYS; i++) {
		keys[i] = derive_key(nstate, 'A'+i, nstate->kex->we_need, hash,
        hashlen, shared_secret);
	}

	debug2("kex_derive_keys");
	for (mode = 0; mode < MODE_MAX; mode++) {
		nstate->current_keys[mode] = nstate->kex->newkeys[mode];
		nstate->kex->newkeys[mode] = NULL;
		ctos = (!nstate->kex->server && mode == MODE_OUT) ||
		    (nstate->kex->server && mode == MODE_IN);
		nstate->current_keys[mode]->enc.iv  = keys[ctos ? 0 : 1];
		nstate->current_keys[mode]->enc.key = keys[ctos ? 2 : 3];
		nstate->current_keys[mode]->mac.key = keys[ctos ? 4 : 5];
	}
}

Newkeys *
kex_get_newkeys(ncrack_ssh_state *nstate, int mode)
{
	Newkeys *ret;

	ret = nstate->current_keys[mode];
	nstate->current_keys[mode] = NULL;
	return ret;
}

void
derive_ssh1_session_id(BIGNUM *host_modulus, BIGNUM *server_modulus,
    u_int8_t cookie[8], u_int8_t id[16])
{
	const EVP_MD *evp_md = EVP_md5();
	EVP_MD_CTX md;
	u_int8_t nbuf[2048], obuf[EVP_MAX_MD_SIZE];
	int len;

	EVP_DigestInit(&md, evp_md);

	len = BN_num_bytes(host_modulus);
	if (len < (512 / 8) || (u_int)len > sizeof(nbuf))
		fatal("%s: bad host modulus (len %d)", __func__, len);
	BN_bn2bin(host_modulus, nbuf);
	EVP_DigestUpdate(&md, nbuf, len);

	len = BN_num_bytes(server_modulus);
	if (len < (512 / 8) || (u_int)len > sizeof(nbuf))
		fatal("%s: bad server modulus (len %d)", __func__, len);
	BN_bn2bin(server_modulus, nbuf);
	EVP_DigestUpdate(&md, nbuf, len);

	EVP_DigestUpdate(&md, cookie, 8);

	EVP_DigestFinal(&md, obuf, NULL);
	memcpy(id, obuf, 16);

	memset(nbuf, 0, sizeof(nbuf));
	memset(obuf, 0, sizeof(obuf));
	memset(&md, 0, sizeof(md));
}

#if defined(debug_KEX) || defined(debug_KEXDH)
void
dump_digest(char *msg, u_char *digest, int len)
{
	int i;

	fprintf(stderr, "%s\n", msg);
	for (i = 0; i < len; i++) {
		fprintf(stderr, "%02x", digest[i]);
		if (i%32 == 31)
			fprintf(stderr, "\n");
		else if (i%8 == 7)
			fprintf(stderr, " ");
	}
	fprintf(stderr, "\n");
}
#endif
