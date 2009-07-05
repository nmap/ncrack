
#ifndef OPENSSH_H
#define OPENSSH_H

#ifdef __cplusplus
extern "C" {
#endif

#include "kex.h"
#include "buffer.h"

u_int	 buffer_len(Buffer *);
void	*buffer_ptr(Buffer *);
Kex	*kex_setup(char *[PROPOSAL_MAX], Buffer ncrack_buf);



#ifdef __cplusplus
} /* End of 'extern "C"' */
#endif

#endif
