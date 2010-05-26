/* $OpenBSD: packet.c,v 1.160 2009/02/13 11:50:21 markus Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file contains code implementing the packet protocol and communication
 * with the other side.  This same code is used both on client and server side.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * SSH2 packet format added by Markus Friedl.
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
 
#include <sys/types.h>

#ifndef WIN32
#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "xmalloc.h"
#include "buffer.h"
#include "packet.h"
#include "crc32.h"
#include "deattack.h"
#include "compat.h"
#include "ssh1.h"
#include "ssh2.h"
#include "cipher.h"
#include "key.h"
#include "kex.h"
#include "mac.h"
#include "log.h"
#include "misc.h"
#include "ssh.h"

#ifdef PACKET_DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif

#define PACKET_MAX_SIZE (256 * 1024)


int keep_alive_timeouts = 0;

/* Session key for protocol v1 */
//static u_char ssh1_key[SSH_SESSION_KEY_LENGTH];
//static u_int ssh1_keylen;


/* XXX discard incoming data after MAC error */
//static u_int packet_discard = 0;
//static Mac *packet_discard_mac = NULL;


/*
 * Sets the descriptors used for communication.  Disables encryption until
 * packet_set_encryption_key is called.
 */
void
packet_set_connection(ncrack_ssh_state *nstate)
{
	Cipher *none = cipher_by_name("none");

	if (none == NULL)
		fatal("packet_set_connection: cannot load cipher 'none'");
	cipher_init(&nstate->send_context, none, (const u_char *)"",
	    0, NULL, 0, CIPHER_ENCRYPT);
	cipher_init(&nstate->receive_context, none, (const u_char *)"",
      0, NULL, 0, CIPHER_DECRYPT);
  nstate->keys[MODE_IN] = nstate->keys[MODE_OUT] = NULL;

  buffer_init(&nstate->input);
  buffer_init(&nstate->output);
  buffer_init(&nstate->outgoing_packet);
  buffer_init(&nstate->incoming_packet);
  nstate->p_send.packets = nstate->p_read.packets = 0;
}

#if 0
static void
packet_stop_discard(void)
{
  if (packet_discard_mac) {
    char buf[1024];

    memset(buf, 'a', sizeof(buf));
    while (buffer_len(&incoming_packet) < PACKET_MAX_SIZE)
      buffer_append(&incoming_packet, buf, sizeof(buf));
    (void) mac_compute(packet_discard_mac,
        p_read.seqnr,
        buffer_ptr(&incoming_packet),
        PACKET_MAX_SIZE);
  }
  ssherror("Finished discarding for %.200s", get_remote_ipaddr());
  cleanup_exit(255);
}
#endif

static void
packet_start_discard(Enc *enc, Mac *mac, u_int packet_length, u_int discard)
{
#if 0
  if (enc == NULL || !cipher_is_cbc(enc->cipher))
    packet_disconnect("Packet corrupt");
  if (packet_length != PACKET_MAX_SIZE && mac && mac->enabled)
    packet_discard_mac = mac;
  if (buffer_len(&input) >= discard)
    packet_stop_discard();
  packet_discard = discard - buffer_len(&input);
#endif
}



/* Closes the connection and clears and frees internal data structures. */
void
packet_close(void)
{
#if 0
  if (!initialized)
    return;
  initialized = 0;

  buffer_free(&input);
  buffer_free(&output);
  buffer_free(&outgoing_packet);
  buffer_free(&incoming_packet);
  if (compression_buffer_ready) {
    buffer_free(&compression_buffer);
    buffer_compress_uninit();
  }
  //cipher_cleanup(&send_context);
  //cipher_cleanup(&receive_context);
#endif 
}



#if 0 
/*
 * Causes any further packets to be encrypted using the given key.  The same
 * key is used for both sending and reception.  However, both directions are
 * encrypted independently of each other.
 */

void
packet_set_encryption_key(const u_char *key, u_int keylen,
    int number)
{
  Cipher *cipher = cipher_by_number(number);

  if (cipher == NULL)
    fatal("packet_set_encryption_key: unknown cipher number %d", number);
  if (keylen < 20)
    fatal("packet_set_encryption_key: keylen too small: %d", keylen);
  if (keylen > SSH_SESSION_KEY_LENGTH)
    fatal("packet_set_encryption_key: keylen too big: %d", keylen);
  memcpy(ssh1_key, key, keylen);
  ssh1_keylen = keylen;
  cipher_init(&send_context, cipher, key, keylen, NULL, 0, CIPHER_ENCRYPT);
  cipher_init(&receive_context, cipher, key, keylen, NULL, 0, CIPHER_DECRYPT);
}

u_int
packet_get_encryption_key(u_char *key)
{
  if (key == NULL)
    return (ssh1_keylen);
  memcpy(key, ssh1_key, ssh1_keylen);
  return (ssh1_keylen);
}
#endif

/* Start constructing a packet to send. */
void
packet_start(ncrack_ssh_state *nstate, u_char type)
{
  u_char buf[9];
  int len;

	// NCRACK: INITIALIZE COMPAT20 HERE FOR NOW
	nstate->compat20 = 1;
	nstate->packet_length = 0;

  DBG(debug("packet_start[%d]", type));
  len = nstate->compat20 ? 6 : 9;
  memset(buf, 0, len - 1);
  buf[len - 1] = type;
  buffer_clear(&nstate->outgoing_packet);
  buffer_append(&nstate->outgoing_packet, buf, len);
}

/* Append payload. */
void
packet_put_char(ncrack_ssh_state *nstate, int value)
{
  char ch = value;

  buffer_append(&nstate->outgoing_packet, &ch, 1);
}

void
packet_put_int(ncrack_ssh_state *nstate, u_int value)
{
  buffer_put_int(&nstate->outgoing_packet, value);
}

void
packet_put_string(ncrack_ssh_state *nstate, const void *buf, u_int len)
{
  buffer_put_string(&nstate->outgoing_packet, buf, len);
}

void
packet_put_cstring(ncrack_ssh_state *nstate, const char *str)
{
  buffer_put_cstring(&nstate->outgoing_packet, str);
}

void
packet_put_raw(ncrack_ssh_state *nstate, const void *buf, u_int len)
{
  buffer_append(&nstate->outgoing_packet, buf, len);
}

void
packet_put_bignum(ncrack_ssh_state *nstate, BIGNUM *value)
{
  buffer_put_bignum(&nstate->outgoing_packet, value);
}

void
packet_put_bignum2(ncrack_ssh_state *nstate, BIGNUM *value)
{
  buffer_put_bignum2(&nstate->outgoing_packet, value);
}


#if 0
/*
 * Finalizes and sends the packet.  If the encryption key has been set,
 * encrypts the packet before sending.
 */

static void
packet_send1(void)
{
  u_char buf[8], *cp;
  int i, padding, len;
  u_int checksum;
  u_int32_t rnd = 0;

  /*
   * If using packet compression, compress the payload of the outgoing
   * packet.
   */
  if (packet_compression) {
    buffer_clear(&compression_buffer);
    /* Skip padding. */
    buffer_consume(&outgoing_packet, 8);
    /* padding */
    buffer_append(&compression_buffer, "\0\0\0\0\0\0\0\0", 8);
    buffer_compress(&outgoing_packet, &compression_buffer);
    buffer_clear(&outgoing_packet);
    buffer_append(&outgoing_packet, buffer_ptr(&compression_buffer),
        buffer_len(&compression_buffer));
  }
  /* Compute packet length without padding (add checksum, remove padding). */
  len = buffer_len(&outgoing_packet) + 4 - 8;

  /* Insert padding. Initialized to zero in packet_start1() */
  padding = 8 - len % 8;
  if (!send_context.plaintext) {
    cp = buffer_ptr(&outgoing_packet);
    for (i = 0; i < padding; i++) {
      if (i % 4 == 0)
        rnd = arc4random();
      cp[7 - i] = rnd & 0xff;
      rnd >>= 8;
    }
  }
  buffer_consume(&outgoing_packet, 8 - padding);

  /* Add check bytes. */
  checksum = ssh_crc32(buffer_ptr(&outgoing_packet),
      buffer_len(&outgoing_packet));
  put_u32(buf, checksum);
  buffer_append(&outgoing_packet, buf, 4);

#ifdef PACKET_DEBUG
  fprintf(stderr, "packet_send plain: ");
  buffer_dump(&outgoing_packet);
#endif

  /* Append to output. */
  put_u32(buf, len);
  buffer_append(&output, buf, 4);
  cp = buffer_append_space(&output, buffer_len(&outgoing_packet));
  cipher_crypt(&send_context, cp, buffer_ptr(&outgoing_packet),
      buffer_len(&outgoing_packet));

#ifdef PACKET_DEBUG
  fprintf(stderr, "encrypted: ");
  buffer_dump(&output);
#endif
  p_send.packets++;
  p_send.bytes += len + buffer_len(&outgoing_packet);
  buffer_clear(&outgoing_packet);

  /*
   * Note that the packet is now only buffered in output.  It won't be
   * actually sent until packet_write_wait or packet_write_poll is
   * called.
   */
}
#endif

void
set_newkeys(int mode, ncrack_ssh_state *nstate)
{
  Enc *enc;
  Mac *mac;
  Comp *comp;
  CipherContext *cc;
  u_int64_t *max_blocks;
  int crypt_type;

  debug2("set_newkeys: mode %d", mode);

  if (mode == MODE_OUT) {
    cc = &nstate->send_context;
    crypt_type = CIPHER_ENCRYPT;
    nstate->p_send.packets = 0;
    nstate->p_send.blocks = 0;
    max_blocks = &nstate->max_blocks_out;
  } else {
    cc = &nstate->receive_context;
    crypt_type = CIPHER_DECRYPT;
    nstate->p_read.packets = 0;
	  nstate->p_read.blocks = 0;
    max_blocks = &nstate->max_blocks_in;
  }

  if (nstate->keys[mode] != NULL) {
    debug("set_newkeys: rekeying");
    cipher_cleanup(cc);
    enc  = &nstate->keys[mode]->enc;
    mac  = &nstate->keys[mode]->mac;
    comp = &nstate->keys[mode]->comp;
    mac_clear(mac);
    xfree(enc->name);
    xfree(enc->iv);
    xfree(enc->key);
    xfree(mac->name);
    xfree(mac->key);
    xfree(comp->name);
    xfree(nstate->keys[mode]);
  }
  nstate->keys[mode] = kex_get_newkeys(nstate, mode);

  if (nstate->keys[mode] == NULL)
    fatal("newkeys: no keys for mode %d", mode);
  enc  = &nstate->keys[mode]->enc;
  mac  = &nstate->keys[mode]->mac;
  comp = &nstate->keys[mode]->comp;
  if (mac_init(mac) == 0)
    mac->enabled = 1;
  DBG(debug("cipher_init_context: %d", mode));
  cipher_init(cc, enc->cipher, enc->key, enc->key_len,
      enc->iv, enc->block_size, crypt_type);

  /*
   * The 2^(blocksize*2) limit is too expensive for 3DES,
   * blowfish, etc, so enforce a 1GB limit for small blocksizes.
   */
  if (enc->block_size >= 16)
    *max_blocks = (u_int64_t)1 << (enc->block_size*2);
  else
    *max_blocks = ((u_int64_t)1 << 30) / enc->block_size;
}


/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
void
packet_send2_wrapped(ncrack_ssh_state *nstate)
{
  u_char type, *cp, *macbuf = NULL;
  u_char padlen, pad;
  u_int packet_length = 0;
  u_int i, len;
  u_int32_t rnd = 0;
  Enc *enc   = NULL;
  Mac *mac   = NULL;
  Comp *comp = NULL;
  int block_size;

  if (nstate->keys[MODE_OUT] != NULL) {
    enc  = &nstate->keys[MODE_OUT]->enc;
    mac  = &nstate->keys[MODE_OUT]->mac;
    comp = &nstate->keys[MODE_OUT]->comp;
  }
  block_size = enc ? enc->block_size : 8;

  cp = buffer_ptr(&nstate->outgoing_packet);
  type = cp[5];

#ifdef PACKET_DEBUG
  fprintf(stderr, "plain:     ");
  buffer_dump(&nstate->outgoing_packet);
#endif

  /* sizeof (packet_len + pad_len + payload) */
  len = buffer_len(&nstate->outgoing_packet);

  /*
   * calc size of padding, alloc space, get random data,
   * minimum padding is 4 bytes
   */
  padlen = block_size - (len % block_size);
  if (padlen < 4)
    padlen += block_size;
  if (nstate->extra_pad) {
    /* will wrap if extra_pad+padlen > 255 */
    nstate->extra_pad  = roundup(nstate->extra_pad, block_size);
    pad = nstate->extra_pad - ((len + padlen) % nstate->extra_pad);
    debug3("packet_send2: adding %d (len %d padlen %d extra_pad %d)",
        pad, len, padlen, nstate->extra_pad);
    padlen += pad;
    nstate->extra_pad = 0;
  }
  cp = buffer_append_space(&nstate->outgoing_packet, padlen);
  if (enc && !nstate->send_context.plaintext) {
    /* random padding */
    for (i = 0; i < padlen; i++) {
      if (i % 4 == 0)
        /* Ncrack: Normally this would be arc4random() */
#ifndef WIN32
        rnd = random();
#else
      rnd = rand();
#endif
      cp[i] = rnd & 0xff;
      rnd >>= 8;
    }
  } else {
    /* clear padding */
    memset(cp, 0, padlen);
  }
  /* packet_length includes payload, padding and padding length field */
  packet_length = buffer_len(&nstate->outgoing_packet) - 4;
  cp = buffer_ptr(&nstate->outgoing_packet);
  put_u32(cp, packet_length);
  cp[4] = padlen;
  DBG(debug("send: len %d (includes padlen %d)", packet_length+4, padlen));

  /* compute MAC over seqnr and packet(length fields, payload, padding) */
  if (mac && mac->enabled) {
    macbuf = mac_compute(mac, nstate->p_send.seqnr,
        buffer_ptr(&nstate->outgoing_packet),
        buffer_len(&nstate->outgoing_packet));
    DBG(debug("done calc MAC out #%d", nstate->p_send.seqnr));
  }
  /* encrypt packet and append to output buffer. */
  cp = buffer_append_space(&nstate->output, buffer_len(&nstate->outgoing_packet));
  cipher_crypt(&nstate->send_context, cp, buffer_ptr(&nstate->outgoing_packet),
      buffer_len(&nstate->outgoing_packet));

  /* append unencrypted MAC */
  if (mac && mac->enabled) {
    buffer_append(&nstate->output, macbuf, mac->mac_len);
  }
#ifdef PACKET_DEBUG
  fprintf(stderr, "encrypted: ");
  buffer_dump(&nstate->output);
#endif
  /* increment sequence number for outgoing packets */
  if (++nstate->p_send.seqnr == 0)
    ssherror("outgoing seqnr wraps around");
  if (++nstate->p_send.packets == 0)
    if (!(nstate->datafellows & SSH_BUG_NOREKEY))
      fatal("XXX too many packets with same key");
  nstate->p_send.blocks += (packet_length + 4) / block_size;
  nstate->p_send.bytes += packet_length + 4;
  buffer_clear(&nstate->outgoing_packet);

  if (type == SSH2_MSG_NEWKEYS)
    set_newkeys(MODE_OUT, nstate);

  /* 
   * NCRACK HOOK
   * Copy outgoing raw data to ncrack's buffer
   */
  //buffer_dump(&output);
  //  buffer_append(ncrack_buf, buffer_ptr(&output), buffer_len(&output));
}

void
packet_send2(ncrack_ssh_state *nstate)
{
  u_char type, *cp;

  cp = buffer_ptr(&nstate->outgoing_packet);
  type = cp[5];

  packet_send2_wrapped(nstate);

#if 0
  /* after a NEWKEYS message we can send the complete queue */
  if (type == SSH2_MSG_NEWKEYS) {
    rekeying = 0;
    while ((p = TAILQ_FIRST(&outgoing))) {
      type = p->type;
      //debug("dequeue packet: %u", type);
      buffer_free(&outgoing_packet);
      memcpy(&outgoing_packet, &p->payload,
          sizeof(Buffer));
      TAILQ_REMOVE(&outgoing, p, next);
      xfree(p);
      packet_send2_wrapped();
    }
  }
#endif
}

void
packet_send(ncrack_ssh_state *nstate)
{
  if (nstate->compat20)
    packet_send2(nstate);
  //else
  //packet_send1();
  DBG(debug("packet_send done"));
}



int
openssh_packet_read(ncrack_ssh_state *nstate)
{
  int type;

  DBG(debug("packet_read()"));

  /* Try to read a packet from the buffer. */
  type = packet_read_poll_seqnr(nstate);

  if (!nstate->compat20 && (
        type == SSH_SMSG_SUCCESS
        || type == SSH_SMSG_FAILURE
        || type == SSH_CMSG_EOF
        || type == SSH_CMSG_EXIT_CONFIRMATION))
    packet_check_eom(nstate);

  return type;
}


int
packet_read(void)
{
  return 1;
  //return packet_read_seqnr(NULL);
}

/*
 * Waits until a packet has been received, verifies that its type matches
 * that given, and gives a fatal error and exits if there is a mismatch.
 */

void
packet_read_expect(int expected_type)
{
  int type;

  type = packet_read();
  if (type != expected_type)
    packet_disconnect("Protocol error: expected packet type %d, got %d",
        expected_type, type);
}


#if 0
/* Checks if a full packet is available in the data received so far via
 * packet_process_incoming.  If so, reads the packet; otherwise returns
 * SSH_MSG_NONE.  This does not wait for data from the connection.
 *
 * SSH_MSG_DISCONNECT is handled specially here.  Also,
 * SSH_MSG_IGNORE messages are skipped by this function and are never returned
 * to higher levels.
 */

static int
packet_read_poll1(void)
{
  u_int len, padded_len;
  u_char *cp, type;
  u_int checksum, stored_checksum;

  /* Check if input size is less than minimum packet size. */
  if (buffer_len(&input) < 4 + 8)
    return SSH_MSG_NONE;
  /* Get length of incoming packet. */
  cp = buffer_ptr(&input);
  len = get_u32(cp);
  if (len < 1 + 2 + 2 || len > 256 * 1024)
    packet_disconnect("Bad packet length %u.", len);
  padded_len = (len + 8) & ~7;

  /* Check if the packet has been entirely received. */
  if (buffer_len(&input) < 4 + padded_len)
    return SSH_MSG_NONE;

  /* The entire packet is in buffer. */

  /* Consume packet length. */
  buffer_consume(&input, 4);

  /*
   * Cryptographic attack detector for ssh
   * (C)1998 CORE-SDI, Buenos Aires Argentina
   * Ariel Futoransky(futo@core-sdi.com)
   */
  if (!receive_context->plaintext) {
    switch (detect_attack(buffer_ptr(&input), padded_len)) {
      case DEATTACK_DETECTED:
        packet_disconnect("crc32 compensation attack: "
            "network attack detected");
      case DEATTACK_DOS_DETECTED:
        packet_disconnect("deattack denial of "
            "service detected");
    }
  }

  /* Decrypt data to incoming_packet. */
  buffer_clear(&incoming_packet);
  cp = buffer_append_space(&incoming_packet, padded_len);
  cipher_crypt(receive_context, cp, buffer_ptr(&input), padded_len);

  buffer_consume(&input, padded_len);

#ifdef PACKET_//debug
  fprintf(stderr, "read_poll plain: ");
  buffer_dump(&incoming_packet);
#endif

  /* Compute packet checksum. */
  checksum = ssh_crc32(buffer_ptr(&incoming_packet),
      buffer_len(&incoming_packet) - 4);

  /* Skip padding. */
  buffer_consume(&incoming_packet, 8 - len % 8);

  /* Test check bytes. */
  if (len != buffer_len(&incoming_packet))
    packet_disconnect("packet_read_poll1: len %d != buffer_len %d.",
        len, buffer_len(&incoming_packet));

  cp = (u_char *)buffer_ptr(&incoming_packet) + len - 4;
  stored_checksum = get_u32(cp);
  if (checksum != stored_checksum)
    packet_disconnect("Corrupted check bytes on input.");
  buffer_consume_end(&incoming_packet, 4);

  p_read.packets++;
  p_read.bytes += padded_len + 4;
  type = buffer_get_char(&incoming_packet);
  if (type < SSH_MSG_MIN || type > SSH_MSG_MAX)
    packet_disconnect("Invalid ssh1 packet type: %d", type);
  return type;
}
#endif

static int
packet_read_poll2(ncrack_ssh_state *nstate)
{
  u_int padlen, need;
  u_char *macbuf, *cp, type;
  u_int maclen, block_size;
  Enc *enc   = NULL;
  Mac *mac   = NULL;
  Comp *comp = NULL;

  // if (packet_discard)
  //   return SSH_MSG_NONE;

  if (nstate->keys[MODE_IN] != NULL) {
    enc  = &nstate->keys[MODE_IN]->enc;
    mac  = &nstate->keys[MODE_IN]->mac;
    comp = &nstate->keys[MODE_IN]->comp;
  }
  maclen = mac && mac->enabled ? mac->mac_len : 0;
  block_size = enc ? enc->block_size : 8;

  if (nstate->packet_length == 0) {
    /*
     * check if input size is less than the cipher block size,
     * decrypt first block and extract length of incoming packet
     */
    if (buffer_len(&nstate->input) < block_size)
      return SSH_MSG_NONE;
    buffer_clear(&nstate->incoming_packet);
    cp = buffer_append_space(&nstate->incoming_packet, block_size);
    cipher_crypt(&nstate->receive_context, cp, buffer_ptr(&nstate->input),
        block_size);
    cp = buffer_ptr(&nstate->incoming_packet);
    nstate->packet_length = get_u32(cp);
#if 0
    if (nstate->keys[MODE_IN] != NULL) {
      int i =0;
      printf("------------KEY-----------------\n");
      for (i = 0; i < enc->key_len; i++)
        printf("%x", enc->key[i]);
      printf("\n");
    }
#endif

    if (nstate->packet_length < 1 + 4 
        || nstate->packet_length > PACKET_MAX_SIZE) {
#ifdef PACKET_DEBUG
      buffer_dump(&nstate->incoming_packet);
#endif
      ssherror("Bad packet length %u.", nstate->packet_length);
      packet_start_discard(enc, mac, nstate->packet_length,
          PACKET_MAX_SIZE);
      return SSH_MSG_NONE;
    }
    DBG(debug("input: packet len %u", nstate->packet_length+4));
    buffer_consume(&nstate->input, block_size);
  }
  /* we have a partial packet of block_size bytes */
  need = 4 + nstate->packet_length - block_size;
  DBG(debug("partial packet %d, need %d, maclen %d", block_size,
        need, maclen));
  if (need % block_size != 0) {
    ssherror("padding error: need %d block %d mod %d",
        need, block_size, need % block_size);
    packet_start_discard(enc, mac, nstate->packet_length,
        PACKET_MAX_SIZE - block_size);
    return SSH_MSG_NONE;
  }
  /*
   * check if the entire packet has been received and
   * decrypt into incoming_packet
   */
  if (buffer_len(&nstate->input) < need + maclen) 
    return SSH_MSG_NONE;
#ifdef PACKET_DEBUG
  fprintf(stderr, "read_poll enc/full: ");
  buffer_dump(&nstate->input);
#endif
  cp = buffer_append_space(&nstate->incoming_packet, need);
  cipher_crypt(&nstate->receive_context, cp, buffer_ptr(&nstate->input), need);
  buffer_consume(&nstate->input, need);
  /*
   * compute MAC over seqnr and packet,
   * increment sequence number for incoming packet
   */
  if (mac && mac->enabled) {
    macbuf = mac_compute(mac, nstate->p_read.seqnr,
        buffer_ptr(&nstate->incoming_packet),
        buffer_len(&nstate->incoming_packet));
    if (memcmp(macbuf, buffer_ptr(&nstate->input), mac->mac_len) != 0) {
      ssherror("Corrupted MAC on input.");
      if (need > PACKET_MAX_SIZE)
        fatal("internal error need %d", need);
      packet_start_discard(enc, mac, nstate->packet_length,
          PACKET_MAX_SIZE - need);
      return SSH_MSG_NONE;
    }

    DBG(debug("MAC #%d ok", nstate->p_read.seqnr));
    buffer_consume(&nstate->input, mac->mac_len);
  }

  /* XXX now it's safe to use fatal/packet_disconnect */

  if (++nstate->p_read.seqnr == 0)
    ssherror("incoming seqnr wraps around");
  if (++nstate->p_read.packets == 0)
    if (!(nstate->datafellows & SSH_BUG_NOREKEY))
      fatal("XXX too many packets with same key");
  nstate->p_read.blocks += (nstate->packet_length + 4) / block_size;
  nstate->p_read.bytes += nstate->packet_length + 4;

  /* get padlen */
  cp = buffer_ptr(&nstate->incoming_packet);
  padlen = cp[4];
  DBG(debug("input: padlen %d", padlen));
  if (padlen < 4)
    packet_disconnect("Corrupted padlen %d on input.", padlen);

  /* skip packet size + padlen, discard padding */
  buffer_consume(&nstate->incoming_packet, 4 + 1);
  buffer_consume_end(&nstate->incoming_packet, padlen);

  /*
   * get packet type, implies consume.
   * return length of payload (without type field)
   */
  type = buffer_get_char(&nstate->incoming_packet);
  if (type < SSH2_MSG_MIN || type >= SSH2_MSG_LOCAL_MIN)
    packet_disconnect("Invalid ssh2 packet type: %d", type);
  if (type == SSH2_MSG_NEWKEYS)
    set_newkeys(MODE_IN, nstate);
#ifdef PACKET_DEBUG
  fprintf(stderr, "read/plain[%d]:\r\n", type);
  buffer_dump(&nstate->incoming_packet);
#endif
  /* reset for next packet */
  nstate->packet_length = 0;
  return type;
}

int
packet_read_poll_seqnr(ncrack_ssh_state *nstate)
{
  u_int reason, seqnr;
  u_char type;
  char *msg;

  for (;;) {
    if (nstate->compat20) {
      type = packet_read_poll2(nstate);
      if (type) {
        keep_alive_timeouts = 0;
        DBG(debug("received packet type %d", type));
      }
      switch (type) {
        case SSH2_MSG_IGNORE:
          debug3("Received SSH2_MSG_IGNORE");
          break;
        case SSH2_MSG_DEBUG:
          packet_get_char(nstate);
          msg = packet_get_string(nstate, NULL);
          debug("Remote: %.900s", msg);
          xfree(msg);
          msg = packet_get_string(nstate, NULL);
          xfree(msg);
          break;
        case SSH2_MSG_DISCONNECT:
          reason = packet_get_int(nstate);
          nstate->disc_reason = packet_get_string(nstate, NULL);
          return type;
          break;
        case SSH2_MSG_UNIMPLEMENTED:
          seqnr = packet_get_int(nstate);
          debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
              seqnr);
          break;
        default:
          return type;
      }
    } 
#if 0
    else {
      type = packet_read_poll1();
      switch (type) {
        case SSH_MSG_IGNORE:
          break;
        case SSH_MSG_DEBUG:
          msg = packet_get_string(NULL);
          debug("Remote: %.900s", msg);
          xfree(msg);
          break;
        case SSH_MSG_DISCONNECT:
          msg = packet_get_string(NULL);
          ssherror("Received disconnect from %s: %.400s",
              get_remote_ipaddr(), msg);
          cleanup_exit(255);
          break;
        default:
          if (type)
            DBG(debug("received packet type %d", type));
          return type;
      }
    }
#endif
  }
}

/*
 * Buffers the given amount of input characters.  This is intended to be used
 * together with packet_read_poll.
 */
void
packet_process_incoming(ncrack_ssh_state *nstate, const char *buf, u_int len)
{
#if 0
  if (packet_discard) {
    keep_alive_timeouts = 0; /* ?? */
    if (len >= packet_discard)
      packet_stop_discard();
    packet_discard -= len;
    return;
  }
#endif
  buffer_append(&nstate->input, buf, len);
}


/* Returns a character from the packet. */
u_int
packet_get_char(ncrack_ssh_state *nstate)
{
  char ch;

  buffer_get(&nstate->incoming_packet, &ch, 1);
  return (u_char) ch;
}

/* Returns an integer from the packet data. */
u_int
packet_get_int(ncrack_ssh_state *nstate)
{
  return buffer_get_int(&nstate->incoming_packet);
}

/*
 * Returns an arbitrary precision integer from the packet data.  The integer
 * must have been initialized before this call.
 */
void
packet_get_bignum(ncrack_ssh_state *nstate, BIGNUM *value)
{
  buffer_get_bignum(&nstate->incoming_packet, value);
}

void
packet_get_bignum2(ncrack_ssh_state *nstate, BIGNUM *value)
{
  buffer_get_bignum2(&nstate->incoming_packet, value);
}

void *
packet_get_raw(ncrack_ssh_state *nstate, u_int *length_ptr)
{
  u_int bytes = buffer_len(&nstate->incoming_packet);

  if (length_ptr != NULL)
    *length_ptr = bytes;
  return buffer_ptr(&nstate->incoming_packet);
}

int
packet_remaining(ncrack_ssh_state *nstate)
{
  return buffer_len(&nstate->incoming_packet);
}


/* don't allow remaining bytes after the end of the message */
void
packet_check_eom(ncrack_ssh_state *nstate)
{
  int _len = packet_remaining(nstate); 
  if (_len > 0) { 
    ssherror("Packet integrity error (%d bytes remaining) at %s:%d", 
        _len ,__FILE__, __LINE__); 
    packet_disconnect("Packet integrity error."); 
  } 
}


/*
 * Returns a string from the packet data.  The string is allocated using
 * xmalloc; it is the responsibility of the calling program to free it when
 * no longer needed.  The length_ptr argument may be NULL, or point to an
 * integer into which the length of the string is stored.
 */

void *
packet_get_string(ncrack_ssh_state *nstate, u_int *length_ptr)
{
  return buffer_get_string(&nstate->incoming_packet, length_ptr);
}

void *
packet_get_string_ptr(ncrack_ssh_state *nstate, u_int *length_ptr)
{
  return buffer_get_string_ptr(&nstate->incoming_packet, length_ptr);
}


/*
 * Logs the error plus constructs and sends a disconnect packet, closes the
 * connection, and exits.  This function never returns. The error message
 * should not contain a newline.  The length of the formatted message must
 * not exceed 1024 bytes.
 */
void
packet_disconnect(const char *fmt,...)
{
#if 0
  char buf[1024];
  va_list args;
  static int disconnecting = 0;

  if (disconnecting)	/* Guard against recursive invocations. */
    fatal("packet_disconnect called recursively.");
  disconnecting = 1;

  /*
   * Format the message.  Note that the caller must make sure the
   * message is of limited size.
   */
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  /* Display the error locally */
  ssherror("Disconnecting: %.100s", buf);

  /* Send the disconnect message to the other side, and wait for it to get sent. */
  if (compat20) {
    packet_start(SSH2_MSG_DISCONNECT);
    packet_put_int(SSH2_DISCONNECT_PROTOCOL_ERROR);
    packet_put_cstring(buf);
    packet_put_cstring("");
  } else {
    packet_start(SSH_MSG_DISCONNECT);
    packet_put_cstring(buf);
  }
#if 0  
  packet_send();
  packet_write_wait();
#endif
  /* Stop listening for connections. */
  //channel_close_all();

  /* Close the connection. */
  packet_close();
  cleanup_exit(255);
#endif
}


/* roundup current message to pad bytes */
void
packet_add_padding(ncrack_ssh_state *nstate, u_char pad)
{
  nstate->extra_pad = pad;
}


