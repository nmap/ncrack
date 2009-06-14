#ifndef MODULES_H 
#define MODULES_H 1

#include "nsock.h"

void ncrack_ftp(nsock_pool nsp, Connection *con);
void ncrack_telnet(nsock_pool nsp, Connection *con);


#endif
