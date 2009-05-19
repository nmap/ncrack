#include "Service.h"



ServiceGroup::ServiceGroup(vector<Target *> &Targets)
{
	unsigned int targetno;
	Service *serv;
	struct timeval now;

	/* members initialization */
	total_services = 0;
	active_connections = 0;
	ideal_parallelism = 100; // TODO: modify for performance


	gettimeofday(&now, NULL);

	for (targetno = 0; targetno < Targets.size(); targetno++) {
		if (Targets[targetno]->timedOut(&now)) {
			num_hosts_timedout++;
			continue;
		}
		for (unsigned int i = 0; i < Targets[targetno]->services.size(); i++) {
			serv = new Service();
			serv->target = Targets[targetno];
			serv->name = strdup(Targets[targetno]->services[i]->name);
			serv->portno = Targets[targetno]->services[i]->portno;
			serv->proto = Targets[targetno]->services[i]->proto;

			// get from ncrack-services file??? optimized values for each service
			serv->T_connections = 10;
			serv->T_login_attempts = 30;
			
			total_services++;
			services_remaining.push_back(serv);
		}
	}

	if (services_remaining.size())
		last_accessed = services_remaining.end();
	else
		fatal("No services have been specified for cracking\n");

	
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
