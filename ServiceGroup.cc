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
ServiceGroup::MovToFin(Service *serv)
{
  list <Service *>::iterator Sli;
  list <Service *> *p = NULL;

  if (serv->list_remaining)
    p = &services_remaining;
  else if (serv->list_stalled)
    p = &services_stalled;
  else 
    fatal("%s: can't move to finished from any other list than remaining "
        " or stalled!\n", __func__);

  for (Sli = p->begin(); Sli != p->end(); Sli++) {
    // ??perhaps we should instead use a unique service id to cmp between them
    if (((*Sli)->portno == serv->portno) && (!strcmp((*Sli)->name, serv->name)) 
        && (!(strcmp((*Sli)->target->NameIP(), serv->target->NameIP()))))
      break;
  }
  if (Sli == p->end()) 
    fatal("%s: no service found in list as should happen!\n", __func__);

  p->erase(Sli);
  serv->SetListFull();
  services_finished.push_back(serv);
  printf("%s FINISHED!!!!\n", serv->HostInfo());

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
  serv->SetListRemaining();
  services_remaining.push_back(serv);
  printf("%s moved from FINISHING to REMAINING\n", serv->HostInfo());
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
  serv->SetListFull();
  services_finished.push_back(serv);
  printf("%s FINISHED!!!!\n", serv->HostInfo());
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
  serv->SetListRemaining();
  services_remaining.push_back(serv);
  printf("%s moved from STALLED to REMAINING\n", serv->HostInfo());

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
  serv->SetListRemaining();
  services_remaining.push_back(serv);

  printf("%s moved from FULL to REMAINING\n", serv->HostInfo());

}


