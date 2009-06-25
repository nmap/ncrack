#ifndef NCRACK_OPS_H
#define NCRACK_OPS_H 1

#include "ncrack.h"
#include "output.h"

class NcrackOps {
  public:
    NcrackOps();
    ~NcrackOps();

    void setaf(int af) { addressfamily = af; }
    int af() { return addressfamily; }

    bool log_errors;      /* write errors to log files */
    bool append_output;   /* append output to log files */
    bool passwords_first; /* iterate password list for each username instead of opposite */
    bool global_options;  /* true if -g has been specified */
    bool list_only;       /* only list hosts and exit */
    int timing_level;     /* timing template number: T(0-5) */
    int debugging;        /* valid for range 0-9 */
    int verbose;
    int numhosts_scanned;
    long connection_limit;/* global maximum total connections */
    unsigned long host_timeout;
    FILE *logfd[LOG_NUM_FILES];
    FILE *ncrack_stdout; /* Ncrack standard output */

  private:
    int addressfamily; /* Address family:  AF_INET or AF_INET6 */  
};

#endif
