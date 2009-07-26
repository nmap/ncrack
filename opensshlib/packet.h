/* $OpenBSD: packet.h,v 1.49 2008/07/10 18:08:11 markus Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Interface for the packet protocol functions.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef PACKET_H
#define PACKET_H

#include "opensshlib.h"

//#include <termios.h>
#include "buffer.h"
#include "cipher.h"
#include "key.h"
#include "kex.h"

#include <openssl/bn.h>

#ifdef __cplusplus
extern "C" {
#endif


void  packet_close(void);
void  packet_set_encryption_key(const u_char *, u_int, int);
u_int	packet_get_encryption_key(u_char *);

void  packet_start(ncrack_ssh_state *nstate, u_char);
void  packet_put_char(ncrack_ssh_state *nstate, int ch);
void  packet_put_int(ncrack_ssh_state *nstate, u_int value);
void  packet_put_bignum(ncrack_ssh_state *nstate, BIGNUM *value);
void  packet_put_bignum2(ncrack_ssh_state *nstate, BIGNUM *value);
void  packet_put_string(ncrack_ssh_state *nstate, const void *buf, u_int len);
void  packet_put_cstring(ncrack_ssh_state *nstate, const char *str);
void  packet_put_raw(ncrack_ssh_state *nstate, const void *buf, u_int len);

int   packet_read(void);
void  packet_read_expect(int type);
int   packet_read_poll(void);
void  packet_process_incoming(ncrack_ssh_state *nstate, const char *buf,
    u_int len);

u_int packet_get_char(ncrack_ssh_state *nstate);
u_int packet_get_int(ncrack_ssh_state *nstate);
void  packet_get_bignum(ncrack_ssh_state *nstate, BIGNUM *value);
void  packet_get_bignum2(ncrack_ssh_state *nstate, BIGNUM *value);
void *packet_get_raw(ncrack_ssh_state *nstate, u_int *length_ptr);
void *packet_get_string_ptr(ncrack_ssh_state *nstate, u_int *length_ptr);
void *packet_get_string(ncrack_ssh_state *nstate, u_int *length_ptr);

void  packet_disconnect(const char *fmt,...) __attribute__((format(printf, 1, 2)));
void  packet_send_debug(const char *fmt,...) __attribute__((format(printf, 1, 2)));
int	  packet_get_ssh1_cipher(void);

void  packet_write_poll(void);
void  packet_write_wait(void);

void	packet_send_ignore(int);

extern u_int max_packet_size;
extern int keep_alive_timeouts;
int	 packet_set_maxsize(u_int);
#define  packet_get_maxsize() max_packet_size

void packet_check_eom(ncrack_ssh_state *nstate);
int packet_remaining(ncrack_ssh_state *nstate);
void packet_set_connection(ncrack_ssh_state *nstate);

int openssh_packet_read(ncrack_ssh_state *nstate);

int packet_read_poll_seqnr(ncrack_ssh_state *nstate);

void set_newkeys(int mode, ncrack_ssh_state *nstate);

void packet_send(ncrack_ssh_state *nstate);

void packet_send2(ncrack_ssh_state *nstate);

void packet_send2_wrapped(ncrack_ssh_state *nstate);

void packet_add_padding(ncrack_ssh_state *nstate, u_char pad);

#ifdef __cplusplus
} /* End of 'extern "C"' */
#endif

#endif				/* PACKET_H */
