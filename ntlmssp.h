#ifndef NTLMSSP_H
#define NTLMSSP_H

struct auth_data;

struct auth_data *
ntlmssp_init_context(const char *user,
                     const char *password,
                     const char *domain,
                     const char *workstation,
                     const char *client_challenge);

int
ntlmssp_generate_blob(struct auth_data *auth_data,
                      unsigned char *input_buf, int input_len,
                      unsigned char **output_buf, uint16_t *output_len);

void
ntlmssp_destroy_context(struct auth_data *auth);

int ntlmssp_get_session_key(struct auth_data *auth, uint8_t **key, uint8_t *key_size);

#endif
