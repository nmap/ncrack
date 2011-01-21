
/***************************************************************************
 * ServiceGroup.cc -- The "ServiceGroup" class holds lists for all         *
 * services that are under active cracking or have been stalled for one    *
 * reason or another. Information and options that apply to all services   *
 * as a whole are also kept here.                                          *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
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
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
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


ServiceGroup::
ServiceGroup()
{
	/* members initialization */
	total_services = 0;
	active_connections = 0;
  connections_total = 0;
  connections_timedout = 0;
  connections_closed = 0;
  credentials_found = 0;
  SPM = new ScanProgressMeter();
}


ServiceGroup::
~ServiceGroup()
{
	// free stuff
}


/* 
 * Find and set minimum connection delay from all unfinished services 
 */
void ServiceGroup::
findMinDelay(void)
{
  list<long> delays;
  list<Service *>::iterator li;

  for (li = services_all.begin(); li != services_all.end(); li++) {
    /* Append to temporary list only the unfinished services */
    if (!(*li)->getListFinished())
      delays.push_back((*li)->connection_delay);
  }

  delays.sort();
  min_connection_delay = delays.front();
  delays.clear();
}


/* 
 * Pushes service into one of the ServiceGroup lists. A Service might belong:
 * a) to 'services_active' OR
 * b) to 'services_finished' OR
 * c) to any other combination of the rest of the lists
 * A service might belong to more than one of the lists in case c) when
 * for example it needs to wait both for the 'connection_delay' and the 
 * 'connection_limit'.
 */
list <Service *>::iterator ServiceGroup::
pushServiceToList(Service *serv, list <Service *> *dst)
{
  list <Service *>::iterator li = services_active.end();
  list <Service *>::iterator templi;
  const char *dstname = NULL;

  assert(dst);
  assert(serv);

  /* Check that destination list is valid and that service doesn't already
   * belong to it. */
  if (!set_servlist(serv, dst) || !(dstname = list2name(dst)))
    return li;

  /* 
   * If service belonged to 'services_active' then we also have to remove it
   * from there. In any other case, we just copy the service to the list
   * indicated by 'dst'.
   */
  if (serv->getListActive()) {
    for (li = services_active.begin(); li != services_active.end(); li++) {
      if (((*li)->portno == serv->portno) && (!strcmp((*li)->name, serv->name)) 
          && (!(strcmp((*li)->target->NameIP(), serv->target->NameIP()))))
        break;
    }
    if (li == services_active.end())
      fatal("%s: %s service not found in 'services_active' as indicated by "
          "'getListActive()'!\n", __func__, serv->HostInfo());

    serv->unsetListActive();
    li = services_active.erase(li);
  }

  /* 
   * Now append service to destination list. The service can still be in other
   * lists too. However, if we move it to 'services_finished', then no other
   * action can happen on it. We also can never move a service to
   * 'services_active' by  this way. The service must stop being in any other
   * list before finally being moved back to 'services_active' and this only
   * happens through 'popServiceFromList()'.
   */

  if (dst == &services_active) {
    if (o.debugging > 8)
      error("%s cannot be pushed into 'services_active'.This is not allowed!\n",
          serv->HostInfo());
  }

  dst->push_back(serv);
  if (o.debugging > 8)
    log_write(LOG_STDOUT, "%s pushed to list %s\n", serv->HostInfo(), dstname);

  // TODO: probably we should also remove from any other list too, if service
  // is finished.

  free((char *)dstname);
  return li;
}


/* 
 * Pops service from one of the ServiceGroup lists. This is the only way for a
 * service to return back to 'services_active' and this happens if and only if
 * it stops belonging to any other list (except 'services_finished' from which
 * you are not allowed to remove a service once it moves there)
 */
list <Service *>::iterator ServiceGroup::
popServiceFromList(Service *serv, list <Service *> *src)
{
  list <Service *>::iterator li = services_finished.end();
  const char *srcname = NULL;

  assert(src);
  assert(serv);

  if (src == &services_active) {
    if (o.debugging > 8)
      error("%s cannot be popped from 'services_active'.This is not allowed!\n",
          serv->HostInfo());
  }  

  /* unset corresponding boolean for service's list - If operation is invalid
   * then return immediately (with null iterator) */
  if (!unset_servlist(serv, src) || !(srcname = list2name(src)))
    return li;

  for (li = src->begin(); li != src->end(); li++) {
    if (((*li)->portno == serv->portno) && (!strcmp((*li)->name, serv->name)) 
        && (!(strcmp((*li)->target->NameIP(), serv->target->NameIP()))))
      break;
  }
  if (li == src->end())
    fatal("%s: %s service was not found in %s and thus cannot be popped!\n",
        __func__, serv->HostInfo(), srcname);

  /* 
   * If service now doesn't belong to any other list other than
   * 'services_active' then we can move them back there!
   */
  if (!serv->getListWait() && !serv->getListPairfini() &&
      !serv->getListFull() && !serv->getListFinishing() &&
      !serv->getListFinished()) {
    serv->setListActive();
    services_active.push_back(serv);
  }

  li = src->erase(li);
  if (o.debugging > 8)
    log_write(LOG_STDOUT, "%s popped from list %s\n",
        serv->HostInfo(), srcname);


  free((char *)srcname);
  return li;
}


/*
 * Returns list's equivalent name. e.g for 'services_finished' it will return
 * a "FINISHED" string. We prefer capitals for debugging purposes. Caller must
 * free the string after it finishes using it.
 */
const char *ServiceGroup::
list2name(list <Service *> *list)
{
  const char *name = NULL;

  if (list == &services_active)
    name = Strndup("ACTIVE", sizeof("ACTIVE") - 1);
  else if (list == &services_wait)
    name = Strndup("WAIT", sizeof("WAIT") - 1);
  else if (list == &services_pairfini)
    name = Strndup("PAIRFINI", sizeof("PAIRFINI") - 1);
  else if (list == &services_full)
    name = Strndup("FULL", sizeof("FULL") - 1);
  else if (list == &services_finishing)
    name = Strndup("FINISHING", sizeof("FINISHING") - 1);
  else if (list == &services_finished)
    name = Strndup("FINISHED", sizeof("FINISHED") - 1);
  else
    error("%s Invalid list specified!\n", __func__);

  return name;
}


/* 
 * Set service's corresponding boolean indicating that it now
 * belongs to the particular list. If service is already on the list or an
 * invalid list is specified, then the operation is invalid. 
 * Returns true if operation is valid and false for invalid.
 */
bool ServiceGroup::
set_servlist(Service *serv, list <Service *> *list)
{
  if (list == &services_active && !serv->getListActive())
    serv->setListActive();
  else if (list == &services_wait && !serv->getListWait())
    serv->setListWait();
  else if (list == &services_pairfini && !serv->getListPairfini())
    serv->setListPairfini();
  else if (list == &services_full && !serv->getListFull())
    serv->setListFull();
  else if (list == &services_finishing && !serv->getListFinishing())
    serv->setListFinishing();
  else if (list == &services_finished && !serv->getListFinished())
    serv->setListFinished();
  else
    return false;

  return true;
}


/* 
 * Unset service's corresponding boolean indicating that it stops
 * belonging to the particular list.
 * Returns true if operation is valid.
 */
bool ServiceGroup::
unset_servlist(Service *serv, list <Service *> *list)
{
  if (list == &services_active)
    serv->unsetListActive();
  else if (list == &services_wait)
    serv->unsetListWait();
  else if (list == &services_pairfini)
    serv->unsetListPairfini();
  else if (list == &services_full)
    serv->unsetListFull();
  else if (list == &services_finishing)
    serv->unsetListFinishing();
  else if (list == &services_finished) {
    if (o.debugging > 8)
      error("%s cannot remove from 'services_finished'.This is not allowed!\n",
          __func__);
    return false;
  } else {
    error("%s destination list invalid!\n", __func__);
    return false;
  }
  return true;
}


double ServiceGroup::
getCompletionFraction(void)
{
  double total = 0;
  unsigned int services_left = 0;

  list <Service *>::iterator li;

  for (li = services_all.begin(); li != services_all.end(); li++) {
    if ((*li)->getListFinished())
      continue;
    services_left++;
    total += (*li)->getPercDone();
  }

  if (total)
    total /= (double)services_left;
  else 
    total = 0;
  return total;
}

