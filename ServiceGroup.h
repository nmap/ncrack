
/***************************************************************************
 * ServiceGroup.h -- The "ServiceGroup" class holds lists for all          *
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


#ifndef SERVICE_GROUP_H
#define SERVICE_GROUP_H

#include "ncrack.h"
#include "Service.h"
#include <list>


class ServiceGroup {
	public:
		ServiceGroup();
		~ServiceGroup();

    /* ********************* Functions ******************* */

    /* Find and set minimum connection delay from all services */
    void findMinDelay(void);

    /* 
     * Pushes service into one of the ServiceGroup lists. 
     * A Service might belong:
     * a) to 'services_active' OR
     * b) to 'services_finished' OR
     * c) to any other combination of the rest of the lists
     * A service might belong to more than one of the lists in case c) when
     * for example it needs to wait both for the 'connection_delay' and the 
     * 'connection_limit'.
     */
    list <Service *>::iterator pushServiceToList(Service *serv,
        list <Service *> *dst);

    /* 
     * Pops service from one of the ServiceGroup lists. This is the only way
     * for a service to return back to 'services_active' and this happens if
     * and only if it stops belonging to any other list (except
     * 'services_finished' from which you are not allowed to remove a service
     * once it moves there).
     */
    list <Service *>::iterator popServiceFromList(Service *serv,
        list <Service *> *src);

    double getCompletionFraction(void);

    /* ********************* Members ********************* */

    /* All Services. This includes all active and inactive services.
     * This list is useful for iterating through all services in one
     * global place instead of searching for each one of them in
     * separate lists. This list is *never* touched except at creation.
     */
    list<Service *> services_all;

    /* Services finished (successfully or not) */
    list<Service *> services_finished; 

    /* 
     * Service has its credential list finished, the pool is empty
     * but there are pending connections still active 
     */
    list<Service *> services_finishing;

    /*
     * Services that temporarily cannot initiate another
     * connection due to timing constraints (connection limit)
     */
    list<Service *> services_full;

    /* 
     * Services that have to wait a time of 'connection_delay'
     * until initiating another connection
     */
    list<Service *> services_wait;

    /* 
     * Services that have to wait until our pair pool has at least one element
     * to grab a login pair from, since the main credential list (username or
     * password depending on the mode of iteration) has already finished being
     * iterated through.
     */
    list<Service *> services_pairfini;

    /* Services that can initiate more connections */
    list<Service *> services_active;

    /* how many services we need to crack in total */
    unsigned long total_services; 

    long min_connection_delay;/* minimum connection delay from all services */
    long active_connections;  /* total number of active connections */
    long connection_limit;    /* maximum total number of active connections */

    /* how many connections have been initiated */
    unsigned long connections_total;  
    unsigned long connections_timedout; /* how many connections have failed */

    /* how many connections prematurely closed */
    unsigned long connections_closed;

    /* total credentials found */
    unsigned long credentials_found; 

    int num_hosts_timedout;  /* # of hosts timed out during (or before) scan */
    list <Service *>::iterator last_accessed; /* last element accessed */

    RateMeter auth_rate_meter;
    ScanProgressMeter *SPM;

  private:

    /*
     * Returns list's equivalent name. e.g for services_finished it will return
     * a "FINISHED" string. We prefer capitals for debugging purposes. Caller
     * must free the string after it finishes using it.
     */
    const char *list2name(list <Service *> *list);

    /* 
     * Set service's corresponding boolean indicating that it now
     * belongs to the particular list.
     * Returns true if operation is valid.
     */
    bool set_servlist(Service *serv, list <Service *> *list);

    /* 
     * Unset service's corresponding boolean indicating that it stops
     * belonging to the particular list.
     * Returns true if operation is valid.
     */
    bool unset_servlist(Service *serv, list <Service *> *list);

};

#endif
