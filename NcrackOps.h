#include "ncrack.h"

class NcrackOps {
	public:
		NcrackOps();
		~NcrackOps();

		void setaf(int af) { addressfamily = af; }
		int af() { return addressfamily; }

		int debugging;
		int verbose;
		int numhosts_scanned;

	private:
		int addressfamily; /*  Address family:  AF_INET or AF_INET6 */  
};
