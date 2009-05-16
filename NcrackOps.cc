#include "ncrack.h"
#include "nbase.h"
#include "NcrackOps.h"
#include "utils.h"

NcrackOps o;

NcrackOps::NcrackOps() {
	service = NULL;
	list_only = 0;
	debugging = 0;
	verbose = 0;
	numhosts_scanned = 0;
	max_group_size = 1024;
	host_timeout = 0;
	;
}

NcrackOps::~NcrackOps() {
	;
}

