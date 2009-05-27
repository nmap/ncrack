#ifndef GLOBAL_STRUCTURES_H
#define GLOBAL_STRUCTURES_H

#include "nsock.h"
#include "nbase.h"

#include <vector>
using namespace std;

typedef struct service_lookup {
  char *name;
  u8 proto;
  u16 portno;
} sevice_lookup;


typedef struct timing_options {
  long connection_limit;  /* maximum number connections per minute */
  long auth_limit;  /* maximum number of authentication attempts per minute */
  long connection_delay; /* number of milliseconds to wait between each connection */
  long retries; /* number of connection retries before marking host as dead */

  // TODO: more options??
} timing_options;


typedef struct misc_options {
  bool ssl; /* use ssl */
  // ... more 
} misc_options;


typedef struct global_service {
  bool registered;        /* true if user has specified this service */
  service_lookup lookup;  /* name, port number and protocol */
  timing_options timing;  /* timing options */
  misc_options misc;      /* miscellaneous options */
  vector <void *> module_options; /* service-specific options */
} global_service;



typedef struct m_data {
  nsock_pool nsp;
  nsock_iod nsi;
  int state;
  int protocol;
  unsigned short port;
  struct in_addr ip;
  int attempts;
  int max_attempts; /* how many attempts in one connection */
  char *username;
  char *password;
  char *buf;
  int bufsize;
} m_data;



#endif
