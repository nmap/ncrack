#include "ServiceGroup.h"


/* 
 * Find and set minimum connection delay from all services 
 */
void
ServiceGroup::MinDelay(void)
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




void
ServiceGroup::UnFini(Service *serv)
{
  list <Service *>::iterator Sli;

  for (Sli = services_finishing.begin(); Sli != services_finishing.end(); Sli++) {
    // ??perhaps we should instead use a unique service id to cmp between them
    if (((*Sli)->portno == serv->portno) && (!strcmp((*Sli)->name, serv->name)) 
        && (!(strcmp((*Sli)->target->NameIP(), serv->target->NameIP()))))
      break;
  }
  if (Sli == services_finishing.end())
    fatal("%s: no service found in 'services_finishing' list as should happen!\n", __func__);
  services_finishing.erase(Sli);
  serv->finishing = false;
  services_remaining.push_back(serv);
}


void
ServiceGroup::Fini(Service *serv)
{
  list <Service *>::iterator Sli;

  for (Sli = services_finishing.begin(); Sli != services_finishing.end(); Sli++) {
    // ??perhaps we should instead use a unique service id to cmp between them
    if (((*Sli)->portno == serv->portno) && (!strcmp((*Sli)->name, serv->name)) 
        && (!(strcmp((*Sli)->target->NameIP(), serv->target->NameIP()))))
      break;
  }
  if (Sli == services_finishing.end())
    fatal("%s: no service found in 'services_finishing' list as should happen!\n", __func__);
  services_finishing.erase(Sli);
  serv->finishing = false;
  serv->finished = true;
  services_finished.push_back(serv);
}




void
ServiceGroup::UnStall(Service *serv)
{
  list <Service *>::iterator Sli;

  for (Sli = services_stalled.begin(); Sli != services_stalled.end(); Sli++) {
    // ??perhaps we should instead use a unique service id to cmp between them
    if (((*Sli)->portno == serv->portno) && (!strcmp((*Sli)->name, serv->name)) 
        && (!(strcmp((*Sli)->target->NameIP(), serv->target->NameIP()))))
      break;
  }
  if (Sli == services_stalled.end())
    fatal("%s: no service found in 'services_stalled' list as should happen!\n", __func__);
  services_stalled.erase(Sli);
  serv->stalled = false;
  services_remaining.push_back(serv);

}


void
ServiceGroup::UnFull(Service *serv)
{
  list <Service *>::iterator Sli;

  for (Sli = services_full.begin(); Sli != services_full.end(); Sli++) {
    // ??perhaps we should instead use a unique service id to cmp between them
    if (((*Sli)->portno == serv->portno) && (!strcmp((*Sli)->name, serv->name)) 
        && (!(strcmp((*Sli)->target->NameIP(), serv->target->NameIP()))))
      break;
  }
  if (Sli == services_full.end())
    fatal("%s: no service found in 'services_full' list as should happen!\n", __func__);
  services_full.erase(Sli);
  serv->full = false;
  services_remaining.push_back(serv);

}


