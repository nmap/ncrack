#ifndef NCRACK_H 
#define NCRACK_H 1

/* common library requirements and definitions */

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
//#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sysexits.h>
//#include <arpa/inet.h>
#include <sys/select.h>
#include <signal.h>
#include <sys/wait.h>
#include <getopt.h>
#include <stdarg.h>
#include "nsock.h"

#define MAXLINE 255

typedef struct m_data {
	nsock_pool nsp;
	nsock_iod nsi;
	int state;
	int protocol;
	unsigned short port;
	struct in_addr ip;
	int attempts;
	int max_attempts;	/* how many attempts in one connection */
	char *username;
	char *password;
	char *buf;
	int bufsize;
} m_data;



// #define _POSIX_C_SOURCE

#endif
