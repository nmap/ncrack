#ifndef NCRACK_OPS_H
#define NCRACK_OPS_H 1

#include "ncrack.h"

class NcrackOps {
  public:
    NcrackOps();
    ~NcrackOps();

    void setaf(int af) { addressfamily = af; }
    int af() { return addressfamily; }

    bool passwords_first;/* iterate password list for each username instead of opposite */
    bool global_options; /* true if -g has been specified */
    bool list_only;      /* only list hosts and exit */
    int timing_level;    /* timing template number: T(0-5) */
    int debugging;       /* valid for range 0-9 */
    int verbose;
    int numhosts_scanned;
    long connection_limit;  /* global maximum total connections */
    unsigned long host_timeout;

  private:
    int addressfamily; /* Address family:  AF_INET or AF_INET6 */  
};

#endif
