
/***************************************************************************
 * ServiceGroup.cc -- The "ServiceGroup" class holds lists for all         *
 * services that are under active cracking or have been stalled for one    *
 * reason or another. Information and options that apply to all services   *
 * as a whole are also kept here.                                          *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2019 Insecure.Com LLC ("The Nmap  *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed Nmap technology into proprietary      *
 * software, we sell alternative licenses (contact sales@nmap.com).        *
 * Dozens of software vendors already license Nmap technology such as      *
 * host discovery, port scanning, OS detection, version detection, and     *
 * the Nmap Scripting Engine.                                              *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, the Nmap Project grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * The Nmap Project has permission to redistribute Npcap, a packet         *
 * capturing driver and library for the Microsoft Windows platform.        *
 * Npcap is a separate work with it's own license rather than this Nmap    *
 * license.  Since the Npcap license does not permit redistribution        *
 * without special permission, our Nmap Windows binary packages which      *
 * contain Npcap may not be redistributed without special permission.      *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, we are happy to help.  As mentioned above, we also *
 * offer an alternative license to integrate Nmap into proprietary         *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing support and updates.  They also fund the continued         *
 * development of Nmap.  Please email sales@nmap.com for further           *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify            *
 * otherwise) that you are offering the Nmap Project the unlimited,        *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because     *
 * the inability to relicense code has caused devastating problems for     *
 * other Free Software projects (such as KDE and NASM).  We also           *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
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
  delete SPM;
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
      error("%s cannot be pushed into 'services_active'. This is not allowed!\n",
          serv->HostInfo());
  }

  dst->push_back(serv);
  if (o.debugging > 8)
    log_write(LOG_STDOUT, "%s pushed to list %s\n", serv->HostInfo(), dstname);

  // TODO: probably we should also remove from any other list too, if service
  // is finished.

  free((char *)dstname);
  prev_modified = li;
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
      error("%s cannot be popped from 'services_active'. This is not allowed!\n",
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
  prev_modified = li;
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
  else if (list == &services_finished && !serv->getListFinished()) {
    serv->setListFinished();
    serv->stopTimeOutClock(nsock_gettimeofday());
  }
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


/* 
 * Return true if there is still a pending connection from the rest of the services
 */
bool ServiceGroup::
checkLinearPending(void)
{
  list <Service *>::iterator li;
  for (li = services_all.begin(); li != services_all.end(); li++) {
    if ((*li)->getLinearState() == LINEAR_INIT || (*li)->getLinearState() == LINEAR_ACTIVE)
      return true;
  }

  return false;
}
