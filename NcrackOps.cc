#include "ncrack.h"
#include "nbase.h"
#include "NcrackOps.h"
#include "utils.h"

NcrackOps o;

NcrackOps::NcrackOps() {
  passwords_first = false;
  global_options = false;
  list_only = false;
  debugging = 0;
  verbose = 0;
  timing_level = 3;
  connection_limit = -1;
  numhosts_scanned = 0;
  host_timeout = 0;
}

NcrackOps::~NcrackOps() {
  ;
}

