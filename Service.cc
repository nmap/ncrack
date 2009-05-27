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
  // free stuff
}
