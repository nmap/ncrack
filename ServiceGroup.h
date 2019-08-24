
/***************************************************************************
 * ServiceGroup.h -- The "ServiceGroup" class holds lists for all          *
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

    bool checkLinearPending(void);

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
    list <Service *>::iterator prev_modified; /* prev element modified */

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
