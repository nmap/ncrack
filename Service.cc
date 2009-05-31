#include "Service.h"


/* 
 * Find and set minimum connection delay from all services 
 */
void
ServiceGroup::MinDelay()
{
  list<long> delays;
  list<Service *>::iterator li;

  for (li = services_remaining.begin(); li != services_remaining.end(); li++) {
    delays.push_back((*li)->connection_delay);
  }

  delays.sort();
  min_connection_delay = delays.front();
  delays.clear();
}




ServiceGroup::ServiceGroup()
{
	struct timeval now;

	/* members initialization */
	total_services = 0;
	active_connections = 0;

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
  retry = false;
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
  full = false;
  total_attempts = 0;
  active_connections = 0;
	connection_limit = -1;
	auth_limit = -1;
	connection_delay = -1;
	retries = -1;
	ssl = false;
	module_data = NULL;
  memset(&last, 0, sizeof(last));

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
