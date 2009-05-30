#include "Service.h"



ServiceGroup::ServiceGroup()
{
	struct timeval now;

	/* members initialization */
	total_services = 0;
	active_connections = 0;
	ideal_parallelism = 3; // TODO: modify for performance

	gettimeofday(&now, NULL);

}


ServiceGroup::~ServiceGroup()
{
	// free stuff
}


/* A connection must *always* belong to one specific Service */
Connection::Connection(Service *serv)
{
	state = 0;
	service = serv;
}

Connection::~Connection()
{
  if (buf) {
    free(buf);
    buf = NULL;
  }
}


Service::Service()
{
	name = NULL;
	target = NULL;
	proto = IPPROTO_TCP;
	portno = 0;
	done = 0;
  active_connections = 0;
	connection_limit = -1;
	auth_limit = -1;
	connection_delay = -1;
	retries = -1;
	ssl = false;
	module_data = NULL;

}

/* copy constructor */
Service::Service(const Service& ref)
{
	name = strdup(ref.name);
	proto = ref.proto;
	portno = ref.portno;
	connection_limit = ref.connection_limit;
	auth_limit = ref.auth_limit;
	connection_delay = ref.connection_delay;
	retries = ref.retries;
	ssl = ref.ssl;

}

Service::~Service()
{
	free(name);
	free(module_data);
}
