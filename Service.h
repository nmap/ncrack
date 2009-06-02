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

		int time_started;
		int time_elapsed;
    char *login;
    char *pass;

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
    void NextPair(char **login, char **pass);

		/* members */
		char *name;
		Target *target; /* service belongs to this host */
		u8 proto;
		u16 portno;

    vector <char *> *LoginArray;
    vector <char *> *PassArray;

    long active_connections;
    struct timeval last; /* time of last activated connection */
		int done;
    bool full;  /* service is now on 'services_full' list */
    unsigned int total_attempts;

		/* timing options that override global ones */
		long connection_limit; 
		long auth_limit;
		long connection_delay;
		long retries;
		/* misc options */
		bool ssl;
		void *module_data; /* service/module-specific data */

		list <Connection *> connections;
  private:
    vector <char *>::iterator loginvi;
    vector <char *>::iterator passvi;
    char *NextLogin();
    char *NextPass();
};




class ServiceGroup {
	public:
		ServiceGroup();
		~ServiceGroup();

    /* Find and set minimum connection delay from all services */
    void MinDelay();
    
    /* Services finished (successfully or not) */
		list<Service *> services_finished; 

    /* Services that temporarily cannot initiate another
     * connection due to timing constraints (connection limit)
     */
		list<Service *> services_full;

    /* Services that have to wait a time of 'connection_delay'
     * until initiating another connection */
    list<Service *> services_wait;

    /* Services not started being cracked yet */
		list<Service *> services_remaining;

		unsigned long total_services; /* how many services we need to crack in total */

    long min_connection_delay;  /* minimum connection delay from all services */
		long active_connections; /* total number of active connections */
    long connection_limit; /* maximum total number of active connections */

		int num_hosts_timedout; /* # of hosts timed out during (or before) scan */
		list <Service *>::iterator last_accessed; /* last element accessed */
};




#endif 
