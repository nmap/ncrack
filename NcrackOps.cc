#include "ncrack.h"
#include "nbase.h"
#include "NcrackOps.h"
#include "utils.h"

NcrackOps o;

NcrackOps::NcrackOps() {
	global_options = false;
	list_only = false;
	debugging = 0;
	verbose = 0;
	timing_level = 3;
	numhosts_scanned = 0;
	max_group_size = 1024;
	host_timeout = 0;
	;
}

NcrackOps::~NcrackOps() {
	;
}

