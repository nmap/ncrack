#ifndef SERVICE_H
#define SERVICE_H

#include "ncrack.h"
#include "utils.h"
#include "Target.h"
#include <list>



/* 
 * Active connection taking place for authenticating service.
 * Each connection may try to authenticatate more than once before closing,
 * depending on the service. For UDP 1 connection = 1 authentication session.
 */
class Connection
{
	public:
		// TODO: modify accordingly
		int time_started;
		int	time_elapsed;
		unsigned int login_attempts;	/* login attempts up until now */
		nsock_iod niod;	/* I/O descriptor for this connection */
};



class Service
{
	public:
		Service();
		~Service();

		Service(const Service&); /* copy constructor */

		Target *target; /* service belongs to this host */
		char *name;
		u8 proto;
		u16 portno;

		int done;

		/* timing options that override global ones */
		long connection_limit; 
		long auth_limit;
		long connection_delay;
		long retries;
		/* misc options */
		bool ssl;
		void *module_data; /* service/module-specific data */

		list <Connection *> connections;
};


class ServiceGroup {
public:
  ServiceGroup();
  ~ServiceGroup();
  list<Service *> services_finished; /* Services finished (successfully or not) */
  list<Service *> services_in_progress; /* Services currently being cracked */ 
  list<Service *> services_remaining; /* Services not started being cracked yet */
	unsigned int total_services; /* how many services we need to crack in total */
  unsigned int ideal_parallelism; /* Max (and desired) number of connections at once */
	unsigned int active_connections; /* total number of active connections */
	list <Service *>::iterator last_accessed;	/* last element accessed */
 //  ScanProgressMeter *SPM;
  int num_hosts_timedout; /* # of hosts timed out during (or before) scan */
};




#endif 
