/* $OpenBSD: cipher-bf1.c,v 1.7 2015/01/14 10:24:42 markus Exp $ */
/*
 * Copyright (c) 2003 Markus Friedl.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
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

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <stdarg.h>
#include <string.h>

#include <openssl/evp.h>

#include "openssl-compat.h"

/*
 * SSH1 uses a variation on Blowfish, all bytes must be swapped before
 * and after encryption/decryption. Thus the swap_bytes stuff (yuk).
 */

const EVP_CIPHER * evp_ssh1_bf(void);

static void
swap_bytes(const u_char *src, u_char *dst, int n)
{
	u_char c[4];

	/* Process 4 bytes every lap. */
	for (n = n / 4; n > 0; n--) {
		c[3] = *src++;
		c[2] = *src++;
		c[1] = *src++;
		c[0] = *src++;

		*dst++ = c[0];
		*dst++ = c[1];
		*dst++ = c[2];
		*dst++ = c[3];
	}
}

#ifdef SSH_OLD_EVP
static void bf_ssh1_init (EVP_CIPHER_CTX * ctx, const unsigned char *key,
			  const unsigned char *iv, int enc)
{
	if (iv != NULL)
		memcpy (&(ctx->oiv[0]), iv, 8);
	memcpy (&(ctx->iv[0]), &(ctx->oiv[0]), 8);
	if (key != NULL)
		BF_set_key (&(ctx->c.bf_ks), EVP_CIPHER_CTX_key_length (ctx),
			    key);
}
#endif

static int (*orig_do_cipher)(EVP_CIPHER_CTX *, u_char *,
    const u_char *, LIBCRYPTO_EVP_INL_TYPE) = NULL;

static int
bf_ssh1_do_cipher(EVP_CIPHER_CTX *ctx, u_char *out, const u_char *in,
    LIBCRYPTO_EVP_INL_TYPE len)
{
	int ret;

	swap_bytes(in, out, len);
	ret = (*orig_do_cipher)(ctx, out, out, len);
	swap_bytes(out, out, len);
	return (ret);
}

static EVP_CIPHER *ssh1_bf;

const EVP_CIPHER *
evp_ssh1_bf(void)
{
	ssh1_bf = EVP_CIPHER_meth_dup(EVP_bf_cbc());
	orig_do_cipher = EVP_CIPHER_meth_get_do_cipher(ssh1_bf);
	/* FIXME(hb): Do we need to set the associated NID?
	   (ssh1_bf.nid = NID_undef)
	   Do we need to set key length? (ssh1_bf.key_len = 32)
	*/
	EVP_CIPHER_meth_set_do_cipher(ssh1_bf, bf_ssh1_do_cipher);
	return (ssh1_bf);
}
#endif /* WITH_OPENSSL */
