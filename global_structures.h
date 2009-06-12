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
  long min_connection_limit;/* minimum number of parallel connections */
  long max_connection_limit;/* maximum number of parallel connections */
  long auth_tries;          /* authentication attempts per connection */
  long connection_delay;    /* number of milliseconds to wait between each connection */
  long connection_retries;  /* number of connection retries after connection failure */

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



#endif
