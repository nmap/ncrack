
/***************************************************************************
 * Service.h -- The "Service" class encapsulates every bit of information  *
 * about the associated target's (Target class) service. Service-specific  *
 * options, statistical and timing information as well as functions for    *
 * handling username/password list iteration all belong to this class.     *
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


#ifndef SERVICE_H
#define SERVICE_H

#include "ncrack.h"
#include "utils.h"
#include "Target.h"
#include "Buf.h"
#include "timing.h"
#include "Connection.h"
#include <list>


#define BUFSIZE 256
#define MAX_HOSTINFO_LEN 1024



typedef struct loginpair
{
  char *user;
  char *pass;
} loginpair;


struct end_reason
{
  bool orly;    /* did it end? */
  char *reason; /* why did it end */
};


struct host_timeout_nfo {
  unsigned long msecs_used; /* How many msecs has this Target used? */
  bool toclock_running; /* Is the clock running right now? */
  struct timeval toclock_start; /* When did the clock start? */
  time_t host_start, host_end; /* The absolute start and end for this host */
};

enum linear_states { LINEAR_INIT, LINEAR_ACTIVE, LINEAR_DONE };

class Service
{
	public:
		Service();
		~Service();

    /* ********************* Functions ******************* */

		Service(const Service&); /* copy constructor */
    const char *HostInfo(void);

    double getPercDone(void); 

    /* Add discovered credential to 'credentials_found' */
    void addCredential(char *user, char *pass);

    int getNextPair(char **login, char **pass);
    void appendToPool(char *login, char *pass);
    void removeFromPool(char *login, char *pass);
    bool isMirrorPoolEmpty(void);
    bool isPoolEmpty(void);

    void setListActive(void) { list_active = true; };
    void unsetListActive(void) { list_active = false; };
    bool getListActive(void) { return list_active; };

    void setListWait(void) { list_wait = true; };
    void unsetListWait(void) { list_wait = false; };
    bool getListWait(void) { return list_wait; };

    void setListPairfini(void) { list_pairfini = true; };
    void unsetListPairfini(void) { list_pairfini = false; };
    bool getListPairfini(void) { return list_pairfini; };

    void setListFull(void) { list_full = true; };
    void unsetListFull(void) { list_full = false; };
    bool getListFull(void) { return list_full; };

    void setListFinishing(void) { list_finishing = true; };
    void unsetListFinishing(void) { list_finishing = false; };
    bool getListFinishing(void) { return list_finishing; };

    void setListFinished(void) { list_finished = true; };
    bool getListFinished(void) { return list_finished; };

    uint32_t getUserlistIndex(void);
    void setUserlistIndex(uint32_t index);
    uint32_t getPasslistIndex(void);
    void setPasslistIndex(uint32_t index);

    void setLinearState(size_t state);
    size_t getLinearState(void);


    /* ********************* Members ********************* */

    uint32_t uid;  /* uniquely identifies service */
		char *name;
		Target *target; /* service belongs to this host */
		u8 proto;
		u16 portno;

    struct end_reason end; /* reason that this service ended */

    /* list which holds discovered credentials if any */
    vector <loginpair> credentials_found;
  
		bool loginlist_fini;/* true if login list has been iterated through */ 
    bool userlist_fini;
    bool passlist_fini;

    vector <char *> *UserArray;
    vector <char *> *PassArray;

    /* true -> reconnaissance/timing probe */
    bool just_started;
    
    /* True if more connections needed for timing probe - usually modules like
     * HTTP might need this, because they need to also check other variables
     * like keep-alive values and authentication schemes (in separate
     * connections)
     */
    bool more_rounds;

    /* Will skip current username and move on to the next one if true.
     * Currently used for MongoDB user-enum vulnerability in SCRAM_SHA1 auth.
     */
    bool skip_username;

    unsigned int failed_connections;
    long active_connections;
    struct timeval last; /* time of last activated connection */

    /*
     * How many attempts the service supports per connection before
     * closing on us. This is used as a valuable piece of information
     * for many timing checks, and is gathered during the first connection
     * (since that probably is the most reliable one, because in the beginning
     * we haven't opened up too many connections yet)
     */
    unsigned long supported_attempts;

    /* total auth attempts, including failed ones */
    unsigned long total_attempts;
    
    /* auth attempts that have finished up to the point of completing
     * all authentication steps and getting the results */
    unsigned long finished_attempts; 

		/* timing options that override global ones */

    /* minimum number of concurrent parallel connections */
		long min_connection_limit;
    /* maximum number of concurrent parallel connections */
    long max_connection_limit;
    /* ideal number of concurrent parallel connections */
    long ideal_parallelism;
    /* authentication attempts per connections */
		long auth_tries; 
    /* number of milliseconds to wait between each connection */
		long connection_delay; 
    /* number of connection retries after connection failure */
		long connection_retries;
    /* maximum cracking time regardless of success so far */
    long long timeout;

		/* misc options */
		bool ssl;   /* true -> SSL enabled over this service */
    char *path; /* used for HTTP or other modules that need a path-name */

    char *db; /* used for MongoDB or other modules that need a database name */

    char *domain; /* used for modules like WinRM that need a domain */

		void *module_data; /* service/module-specific data */

    RateMeter auth_rate_meter;
    struct last_auth_rate { 
      double rate;
      struct timeval time;
    } last_auth_rate;

    list <Connection *> connections;

    /*
     * Starts the timeout clock for the host running (e.g. you are
     * beginning a scan). If you do not have the current time handy,
     * you can pass in NULL. When done, call stopTimeOutClock (it will
     * also automatically be stopped if timedOut() returns true)
     */
    void startTimeOutClock(const struct timeval *now);

    /* The complement to startTimeOutClock. */
    void stopTimeOutClock(const struct timeval *now);

    /* Is the timeout clock currently running? */
    bool timeOutClockRunning() { return htn.toclock_running; }

    /* 
     * Returns whether the host is timedout. If the timeoutclock is
     * running, counts elapsed time for that. Pass NULL if you don't have the
     * current time handy. You might as well also pass NULL if the
     * clock is not running, as the func won't need the time.
     */
    bool timedOut(const struct timeval *now);

    /* Return time_t for the start and end time of this host */
    time_t StartTime() { return htn.host_start; }

    time_t EndTime() { return htn.host_end; }

  private:

    /* 
     * hostinfo in form "<service_name>://<ip or hostname>:<port number>"
     * e.g ftp://scanme.nmap.org:21 - Will be returned by HostInfo()  
     */
    char *hostinfo;

    /* 
     * Login pair pool that holds pairs that didn't manage to be authenticated
     * due to an error (the host timed out, the connection was forcefully closed
     * etc). If this pool has elements, then the next returned pair from
     * NextPair() will come from this pool. NextPair() will remove the
     * element from the list.
     */
    list <loginpair> pair_pool;

    /* 
     * Mirror login pair pool, that holds pairs from login pair pool but which
     * aren't removed from the list at the time they are used.
     * By this way we can determine, if we are currently using pairs from the
     * pair_pool by checking if the mirror_pair_pool is non-empty.
     */
    list <loginpair> mirror_pair_pool;

    vector <char *>::iterator uservi;
    vector <char *>::iterator passvi;

    bool list_active;   /* service is now on 'services_active' list */
    bool list_wait;     /* service appended to 'services_wait' list */
    bool list_pairfini; /* service appended to 'services_pairfini' list */ 
    bool list_full;     /* service appended to 'services_full' list */
    bool list_finishing;/* service appended to 'services_finishing' list */
    bool list_finished; /* service is now on 'services_finished' list */


    /* 
     * LINEAR_INIT: service hasn't started connection yet
     * LINEAR_ACTIVE: service has active connection
     * LINEAR_DONE: service has finished connection
     */
    size_t linear_state;

    struct host_timeout_nfo htn;

};


#endif 
