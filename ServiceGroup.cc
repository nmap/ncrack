#include "ServiceGroup.h"
#include "NcrackOps.h"

extern NcrackOps o;


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


list <Service *>::iterator
ServiceGroup::MoveServiceToList(Service *serv, list <Service *> *dst)
{
  list <Service *>::iterator li;
  list <Service *> *src = NULL;
  const char *srcname = NULL;
  const char *dstname = NULL;

  assert(dst);
  if (serv->list_remaining) {
    src = &services_remaining;
    srcname = Strndup("REMAINING", sizeof("REMAINING") - 1);
  } else if (serv->list_wait) {
    src = &services_wait;
    srcname = Strndup("WAIT", sizeof("WAIT") - 1);
  } else if (serv->list_stalled) {
    src = &services_stalled;
    srcname = Strndup("STALLED", sizeof("STALLED") - 1);
  } else if (serv->list_full) {
    src = &services_full;
    srcname = Strndup("FULL", sizeof("FULL") - 1);
  } else if (serv->list_finishing) {
    src = &services_finishing;
    srcname = Strndup("FINISHING", sizeof("FINISHING") - 1);
  } else if (serv->list_finished) {
    fatal("%s: service %s tried to move from services_finished! "
        "That cannot happen!\n", __func__, serv->HostInfo());
  } else 
    fatal("%s: service %s doesn't belong in any list!\n", __func__, serv->HostInfo()); 
 
  for (li = src->begin(); li != src->end(); li++) {
    if (((*li)->portno == serv->portno) && (!strcmp((*li)->name, serv->name)) 
      && (!(strcmp((*li)->target->NameIP(), serv->target->NameIP()))))
      break;
  }
  if (li == src->end())
    fatal("%s: no service %s found in list %s as should happen!\n", __func__, 
        serv->HostInfo(), srcname);

  if (dst == &services_remaining) {
    serv->SetListRemaining();
    dstname = Strndup("REMAINING", sizeof("REMAINING") - 1);
  } else if (dst == &services_wait) {
    serv->SetListWait();
    dstname = Strndup("WAIT", sizeof("WAIT") - 1);
  } else if (dst == &services_stalled) {
    serv->SetListStalled();
    dstname = Strndup("STALLED", sizeof("STALLED") - 1);
  } else if (dst == &services_full) {
    serv->SetListFull();
    dstname = Strndup("FULL", sizeof("FULL") - 1);
  } else if (dst == &services_finishing) {
    serv->SetListFinishing();
    dstname = Strndup("FINISHING", sizeof("FINISHING") - 1);
  } else if (dst == &services_finished) {
    serv->SetListFinished();
    dstname = Strndup("FINISHED", sizeof("FINISHED") - 1);
  } else
    fatal("%s destination list invalid!\n", __func__);

  li = src->erase(li);
  dst->push_back(serv);

  if (o.debugging > 5)
    printf("%s moved from list %s to %s\n", serv->HostInfo(), srcname, dstname);

  free((char *)srcname);
  free((char *)dstname);
  return li;
}


