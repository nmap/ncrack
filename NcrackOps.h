#ifndef NCRACK_OPS_H
#define NCRACK_OPS_H 1

#include "ncrack.h"

class NcrackOps {
  public:
    NcrackOps();
    ~NcrackOps();

    void setaf(int af) { addressfamily = af; }
    int af() { return addressfamily; }

    uint16_t *portlist;
    bool global_options;
    bool list_only;
    int timing_level;
    int debugging;
    int verbose;
    int numhosts_scanned;
    int max_group_size;
    unsigned long host_timeout;

  private:
    int addressfamily; /*  Address family:  AF_INET or AF_INET6 */  
};

#endif
