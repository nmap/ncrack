#ifndef SERVICE_H
#define SERVICE_H

#include "ncrack.h"
#include "utils.h"
#include "Target.h"
#include <list>


#define BUFSIZE 256

class Connection;
class Service;
class ServiceGroup;


/* 
 * Active connection taking place for authenticating service.
 * Each connection may try to authenticatate more than once before closing,
 * depending on the service. For UDP 1 connection = 1 authentication session.
 */
class Connection
{
	public:
		Connection(Service *serv);
		~Connection();

		// TODO: modify accordingly
		int time_started;
		int time_elapsed;
		int state;
    bool retry; /* true-> retry login attempt within current connection */
		char *buf;
		int bufsize;  /* buffer size not including '\0' */
		unsigned int login_attempts;  /* login attempts up until now */
		nsock_iod niod; /* I/O descriptor for this connection */
		Service *service; /* service it belongs to */
};



class Service
{
	public:
		Service();
		~Service();

		Service(const Service&); /* copy constructor */

		/* members */
		char *name;
		Target *target; /* service belongs to this host */
		u8 proto;
		u16 portno;

    long active_connections;
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
    
    /* Services finished (successfully or not) */
		list<Service *> services_finished; 

    /* Services that temporarily cannot initiate another
     * connection due to timing constraints (connection limit)
     */
		list<Service *> services_full;

    /* Services not started being cracked yet */
		list<Service *> services_remaining;

		unsigned long total_services; /* how many services we need to crack in total */

		long active_connections; /* total number of active connections */
    long connection_limit; /* maximum total number of active connections */

		int num_hosts_timedout; /* # of hosts timed out during (or before) scan */
		list <Service *>::iterator last_accessed; /* last element accessed */
};




#endif 
