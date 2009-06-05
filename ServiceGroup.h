#ifndef SERVICE_GROUP_H
#define SERVICE_GROUP_H

#include "ncrack.h"
#include "Service.h"
#include <list>


class ServiceGroup {
	public:
		ServiceGroup();
		~ServiceGroup();

    /* Find and set minimum connection delay from all services */
    void MinDelay(void);

    void UnStall(Service *serv);

    void UnFull(Service *serv);
    
    /* Services finished (successfully or not) */
		list<Service *> services_finished; 

    /* Services that temporarily cannot initiate another
     * connection due to timing constraints (connection limit)
     */
		list<Service *> services_full;

    /* Services that have to wait a time of 'connection_delay'
     * until initiating another connection */
    list<Service *> services_wait;

    /* Services that have to wait until our pair pool has at least one element
     * to grab a login pair from, since the username list has already finished
     * being iterated through.
     */
    list<Service *> services_stalled;

    /* Services not started being cracked yet */
		list<Service *> services_remaining;

		unsigned long total_services; /* how many services we need to crack in total */

    long min_connection_delay;  /* minimum connection delay from all services */
		long active_connections; /* total number of active connections */
    long connection_limit; /* maximum total number of active connections */

		int num_hosts_timedout; /* # of hosts timed out during (or before) scan */
		list <Service *>::iterator last_accessed; /* last element accessed */

    RateMeter auth_rate_meter;
    double last_auth_rate;
};

#endif
