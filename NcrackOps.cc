#include "ncrack.h"
#include "NcrackOps.h"

NcrackOps o;

NcrackOps::NcrackOps() {

  log_errors = false;
  append_output = false;
  passwords_first = false;
  global_options = false;
  list_only = false;
  debugging = 0;
  verbose = 0;
  timing_level = 3;
  connection_limit = -1;
  numhosts_scanned = 0;
  host_timeout = 0;
  memset(logfd, 0, sizeof(FILE *) * LOG_NUM_FILES);
  ncrack_stdout = stdout;
}

NcrackOps::~NcrackOps() {
  ;
}

