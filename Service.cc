#include "Service.h"



ServiceGroup::ServiceGroup()
{
	struct timeval now;

	/* members initialization */
	total_services = 0;
	active_connections = 0;
	ideal_parallelism = 100; // TODO: modify for performance

	gettimeofday(&now, NULL);

}


ServiceGroup::~ServiceGroup()
{
	// free stuff
}



Service::Service()
{
	name = NULL;
	portno = 0;
	done = 0;
	

}

Service::~Service()
{
	// free stuff
}
