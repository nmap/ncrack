#ifndef OPENSSHLIB_H
#define OPENSSHLIB_H

#include "buffer.h"
#include "cipher.h"
#include "ssh1.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Kex;
struct Newkeys;

typedef struct packet_state {
  u_int32_t seqnr;
  u_int32_t packets;
  u_int64_t blocks;
  u_int64_t bytes;
} packet_state;


/* 
 * Every module invocation has its own Ncrack_state struct which holds every
 * bit of information needed to keep track of things. Most of the variables
 * found inside this object were usually static/global variables in the original
 * OpenSSH codebase.
 */
typedef struct ncrack_ssh_state {

  struct Kex *kex;
  DH *dh;
  /* Session key information for Encryption and MAC */
  struct Newkeys *keys[2];
  char *client_version_string;
  char *server_version_string;
  /* Encryption context for receiving data. This is only used for decryption. */
  CipherContext receive_context;
  /* Encryption context for sending data. This is only used for encryption. */
  CipherContext send_context;

  /* ***** IO Buffers ****** */
  Buffer ncrack_buf;

  /* Buffer for raw input data from the socket. */
  Buffer input;
  /* Buffer for raw output data going to the socket. */
  Buffer output;
  /* Buffer for the incoming packet currently being processed. */
  Buffer incoming_packet;
  /* Buffer for the partial outgoing packet being constructed. */
  Buffer outgoing_packet;

  u_int64_t max_blocks_in;
  u_int64_t max_blocks_out;
  packet_state p_read;
  packet_state p_send;

	int compat20;	/* boolean -> true if SSHv2 compatible */

  /* Compatibility mode for different bugs of various older sshd
   * versions. It holds a list of these bug types in a binary OR list
   */
  int datafellows;
  int type;   /* type of packet returned */
  u_char extra_pad; /* extra padding that might be needed */

  /* 
   * Reason that this connection was ended. It might be that we got a
   * disconnnect packet from the server due to many authentication attempts
   * or some other exotic reason.
   */
  char *disc_reason;

	u_int packet_length; 

} ncrack_ssh_state;


#ifdef __cplusplus
} /* End of 'extern "C"' */
#endif



#endif
