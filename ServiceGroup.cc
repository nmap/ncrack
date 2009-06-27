
/***************************************************************************
 * ServiceGroup.cc -- The "ServiceGroup" class holds lists for all         *
 * services that are under active cracking or have been stalled for one    *
 * reason or another. Information and options that apply to all services   *
 * as a whole are also kept here.                                          *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                * 
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/


#include "ServiceGroup.h"
#include "NcrackOps.h"

extern NcrackOps o;


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


/* 
 * Find and set minimum connection delay from all services 
 */
void
ServiceGroup::findMinDelay(void)
{
  list<long> delays;
  list<Service *>::iterator li;

  for (li = services_active.begin(); li != services_active.end(); li++) {
    delays.push_back((*li)->connection_delay);
  }

  delays.sort();
  min_connection_delay = delays.front();
  delays.clear();
}


/* 
 * Moves service into one of the ServiceGroup lists 
 */
list <Service *>::iterator
ServiceGroup::moveServiceToList(Service *serv, list <Service *> *dst)
{
  list <Service *>::iterator li;
  list <Service *> *src = NULL;
  const char *srcname = NULL;
  const char *dstname = NULL;

  assert(dst);
  if (serv->list_active) {
    src = &services_active;
    srcname = Strndup("ACTIVE", sizeof("ACTIVE") - 1);
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
    return services_finished.end();
    //fatal("%s: service %s tried to move from services_finished! "
    //   "That cannot happen!\n", __func__, serv->HostInfo());
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

  if (dst == &services_active) {
    serv->SetListActive();
    dstname = Strndup("ACTIVE", sizeof("ACTIVE") - 1);
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

  if (o.debugging > 8)
    log_write(LOG_STDOUT, "%s moved from list %s to %s\n", serv->HostInfo(), srcname, dstname);

  free((char *)srcname);
  free((char *)dstname);
  return li;
}


void
ServiceGroup::printStatusMessage(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  int time = (int) (o.TimeSinceStartMS(&tv) / 1000.0);
  
  log_write(LOG_STDOUT, 
	    "Stats: %d:%02d:%02d elapsed; %d services completed (%d total)\n", 
	    time/60/60, time/60 % 60, time % 60, services_finished.size(), 
      total_services);
}

