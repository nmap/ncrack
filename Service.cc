
/***************************************************************************
 * Service.cc -- The "Service" class encapsulates every bit of information *
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

#include "Service.h"
#include "NcrackOps.h"

extern NcrackOps o;


Service::
Service()
{
  static unsigned long id = 0;
  name = NULL;
  target = NULL;
  proto = IPPROTO_TCP;
  portno = 0;

  uid = id++;

  loginlist_fini = false;
  list_active = true;
  list_full = false;
  list_wait = false;
  list_pairfini = false;
  list_finishing = false;
  list_finished = false;
  just_started = true;
  more_rounds = false;
  skip_username = false;

  end.orly = false;
  end.reason = NULL;

  failed_connections = 0;
  total_attempts = 0;
  finished_attempts = 0;
  supported_attempts = 0;
  active_connections = 0;

  min_connection_limit = -1;
  max_connection_limit = -1;
  ideal_parallelism = 1;  /* we start with 1 connection exactly */
  auth_tries = -1;
  connection_delay = -1;
  connection_retries = -1;
  timeout = -1;
  path = Strndup("/", 2); /* path is '/' by default */
  
  db = Strndup("admin", 5); /* databse is 'admin' by default */
  domain = Strndup("Workstation", 11); /* domain is 'Workstation' by default */

  ssl = false;

  module_data = NULL;
  memset(&last, 0, sizeof(last));
  UserArray = NULL;
  PassArray = NULL;
  hostinfo = NULL;
  memset(&last_auth_rate, 0, sizeof(last_auth_rate));

  htn.msecs_used = 0;
  htn.toclock_running = false;
  htn.host_start = htn.host_end = 0;

  linear_state = LINEAR_INIT;
}

/* copy constructor */
Service::
Service(const Service& ref)
{
  name = strdup(ref.name);
  proto = ref.proto;
  portno = ref.portno;

  uid = ref.uid;

  min_connection_limit = ref.min_connection_limit;
  max_connection_limit = ref.max_connection_limit;
  auth_tries = ref.auth_tries;
  connection_delay = ref.connection_delay;
  connection_retries = ref.connection_retries;
  timeout = ref.timeout;
  ssl = ref.ssl;
  //if (path)
  //  free(path);
  path = Strndup(ref.path, strlen(ref.path));

  db = Strndup(ref.db, strlen(ref.db));

  domain = Strndup(ref.domain, strlen(ref.domain));

  ideal_parallelism = 1;  /* we start with 1 connection exactly */

  ssl = ref.ssl;
  UserArray = ref.UserArray;
  PassArray = ref.PassArray;
  uservi = UserArray->begin();
  passvi = PassArray->begin();
  
  failed_connections = 0;
  total_attempts = 0;
  finished_attempts = 0;
  supported_attempts = 0;
  active_connections = 0;

  loginlist_fini = false;
  passlist_fini = false;
  userlist_fini = false;
  list_active = true;
  list_full = false;
  list_wait = false;
  list_pairfini = false;
  list_finishing = false;
  list_finished = false;
  just_started = true;
  more_rounds = false;
  skip_username = false;

  end.orly = false;
  end.reason = NULL;
  
  module_data = NULL;
  hostinfo = NULL;
  memset(&last, 0, sizeof(last));
  memset(&last_auth_rate, 0, sizeof(last_auth_rate));

  htn.msecs_used = 0;
  htn.toclock_running = false;
  htn.host_start = htn.host_end = 0;

  linear_state = ref.linear_state;
}

Service::
~Service()
{
  if (name)
    free(name);
  if (module_data)
    free(module_data);
  if (hostinfo)
    free(hostinfo);
  if (end.reason)
    free(end.reason);
}

const char *Service::
HostInfo(void)
{
  if (!hostinfo) 
    hostinfo = (char *) safe_malloc(MAX_HOSTINFO_LEN);

  if (!target)
    fatal("%s: tried to print hostinfo with uninitialized Target\n", __func__);

  Snprintf(hostinfo, MAX_HOSTINFO_LEN, "%s://%s:%hu", name,
      target->NameIP(), portno);
  return hostinfo;
}


/* Add discovered credential to private list */
void Service::
addCredential(char *user, char *pass)
{
  loginpair tmp;
  tmp.user = user;
  tmp.pass = pass;
  credentials_found.push_back(tmp);
}

uint32_t Service::
getUserlistIndex(void)
{
  return std::distance(UserArray->begin(), uservi);
}

void Service::
setUserlistIndex(uint32_t index)
{
  uservi = UserArray->begin() + index;
}

uint32_t Service::
getPasslistIndex(void)
{
  return std::distance(PassArray->begin(), passvi);
}

void Service::
setPasslistIndex(uint32_t index)
{
  passvi = PassArray->begin() + index;
}


/* 
 * returns -1 for end of login list and empty pool
 * 0 for successful retrieval through lists
 * 1 for successful retrieval through pool
 */
int Service::
getNextPair(char **user, char **pass)
{
  if (!UserArray)
    fatal("%s: uninitialized UserArray\n", __func__);

  if (!PassArray)
    fatal("%s: uninitialized PassArray\n", __func__);

  loginpair tmp;

  /* If the login pair pool is not empty, then give priority to these
   * pairs and extract the first one you find. */
  if (!pair_pool.empty()) {

    list <loginpair>::iterator pairli = pair_pool.begin();
    tmp = pair_pool.front();
    *user = tmp.user;
    *pass = tmp.pass;
    pair_pool.erase(pairli);
    if (o.debugging > 8)
      log_write(LOG_STDOUT, "%s Pool: extract '%s' '%s'\n", HostInfo(),
          tmp.user, tmp.pass);
    return 1;
  }

  if (loginlist_fini)
    return -1;

  if (!strcmp(name, "redis")) {
    if (passvi == PassArray->end()) {
      if (o.debugging > 8)
        log_write(LOG_STDOUT, "%s Password list finished!\n", HostInfo());
      loginlist_fini = true;
      return -1;
    } 
    *user = *uservi;
    *pass = *passvi;
    passvi++;
    return 0;
  }

  if (!strcmp(name, "mongodb")) {
    if (skip_username == true) {
      uservi--;
      if (o.debugging > 5)
        log_write(LOG_STDOUT, "%s skipping username!!!! %s\n", HostInfo(), *(uservi));
      uservi = UserArray->erase(uservi);
      if (uservi == UserArray->end()) {
        uservi = UserArray->begin();
        passvi++;
        if (passvi == PassArray->end()) {
          if (o.debugging > 8)
            log_write(LOG_STDOUT, "%s Password list finished!\n", HostInfo());
          loginlist_fini = true;
          return -1;
        }
      } 
      //printf("next user: %s\n", *uservi);
      skip_username = false;
    }
  }

  if (!strcmp(name, "ssh")) {

    /* catches bug where ssh module crashed when user had specified correct username and
     * password in the first attempt
     */
    if (just_started == false && PassArray->size() == 1 && UserArray->size() == 1) {
      uservi = UserArray->end();
      passvi = PassArray->end();
      loginlist_fini = true;
      return -1;
    }

    /* special case for ssh */
    if (just_started == true) {

      /* keep using same username for first timing probe */
      if (passvi == PassArray->end()) {                                          
        passvi = PassArray->begin();
        uservi++;
        if (uservi == UserArray->end()) {
          if (o.debugging > 8)
            log_write(LOG_STDOUT, "%s Username list finished!\n", HostInfo());
          loginlist_fini = true;
          return -1;
        } 
      } 
      *user = *uservi;
      *pass = *passvi;
      passvi++;

      return 0;
    } 
  }

  if (o.pairwise && strcmp(name, "mongodb")) {

    if (uservi == UserArray->end() && passvi == PassArray->end()) {
      if (o.debugging > 8)
        log_write(LOG_STDOUT, "%s Password list finished!\n", HostInfo());
      loginlist_fini = true;
      return -1;
    }
    if (uservi == UserArray->end()) {
      uservi = UserArray->begin();
      userlist_fini = true;
    }
    if (passvi == PassArray->end()) {
      passvi = PassArray->begin();
      passlist_fini = true;
    }
    if (userlist_fini == true && passlist_fini == true) {
      if (o.debugging > 8)
        log_write(LOG_STDOUT, "%s Password list finished!\n", HostInfo());
      loginlist_fini = true;
      return -1;
    }
    *pass = *passvi;
    *user = *uservi;
    uservi++;
    passvi++;

  } else if (o.passwords_first && strcmp(name, "mongodb")) {
    /* Iteration of password list for each username. */
    /* If password list finished one iteration then reset the password pointer
     * to show at the beginning and get next username from username list. */
    if (passvi == PassArray->end()) {                                          
      passvi = PassArray->begin();
      uservi++;
      if (uservi == UserArray->end()) {
        if (o.debugging > 8)
          log_write(LOG_STDOUT, "%s Username list finished!\n", HostInfo());
        loginlist_fini = true;
        return -1;
      } 
    } 
    *user = *uservi;
    *pass = *passvi;
    passvi++;

  } else if (!o.passwords_first || !strcmp(name, "mongodb")) {
    /* Iteration of username list for each password (default). */
    /* If username list finished one iteration then reset the username pointer
     * to show at the beginning and get password from password list. */
    if (uservi == UserArray->end()) {
      uservi = UserArray->begin();
      passvi++;
      if (passvi == PassArray->end()) {
        if (o.debugging > 8)
          log_write(LOG_STDOUT, "%s Password list finished!\n", HostInfo());
        loginlist_fini = true;
        return -1;
      }
    }
    *pass = *passvi;
    *user = *uservi;
    uservi++;
  }

    
  return 0;
}


void Service::
removeFromPool(char *user, char *pass)
{
  loginpair tmp;
  list <loginpair>::iterator li;

  if (!user || !pass)
    return;

  tmp.user = user;
  tmp.pass = pass;

  for (li = mirror_pair_pool.begin(); li != mirror_pair_pool.end(); li++) {
    if ((tmp.user == li->user) && (tmp.pass == li->pass))
      break;
  }
  if (li != mirror_pair_pool.end()) {
    if (o.debugging > 8) {
      if (!strcmp(name, "redis"))
        log_write(LOG_STDOUT, "%s Pool: Removed '%s' \n", HostInfo(), tmp.pass);
      else
        log_write(LOG_STDOUT, "%s Pool: Removed %s %s\n", HostInfo(),
            tmp.user, tmp.pass);
    }
    mirror_pair_pool.erase(li);
  }
}



void Service::
appendToPool(char *user, char *pass)
{
  loginpair tmp;
  list <loginpair>::iterator li;

  if (!user)
    fatal("%s: tried to append NULL user into pair pool", __func__);
  if (!pass)
    fatal("%s: tried to append NULL password into pair pool", __func__);

  tmp.user = user;
  tmp.pass = pass;
  pair_pool.push_back(tmp);

  if (o.debugging > 8) {
    if (!strcmp(name, "redis"))
      log_write(LOG_STDOUT, "%s Pool: Append '%s' \n", HostInfo(), tmp.pass);
    else
      log_write(LOG_STDOUT, "%s Pool: Append '%s' '%s' \n", HostInfo(),
          tmp.user, tmp.pass);
  }

  /* 
   * Try and see if login pair was already in our mirror pool. Only if
   * it doesn't already exist, then append it to the list.
   */
  for (li = mirror_pair_pool.begin(); li != mirror_pair_pool.end(); li++) {
    if ((tmp.user == li->user) && (tmp.pass == li->pass))
      break;
  }
  if (li == mirror_pair_pool.end())
    mirror_pair_pool.push_back(tmp);
}


bool Service::
isMirrorPoolEmpty(void)
{
  return mirror_pair_pool.empty();
}


bool Service::
isPoolEmpty(void)
{
  return pair_pool.empty();
}


double Service::
getPercDone(void)
{
  double ret = 0.0;
  vector <char *>::iterator usertmp = uservi;
  vector <char *>::iterator passtmp = passvi;

  if (!o.passwords_first) {
    if (passtmp != PassArray->begin())
      passtmp--;
    if (uservi == UserArray->end()) {
      ret = distance(PassArray->begin(), passtmp) * UserArray->size();
    } else {
      if (usertmp != UserArray->begin())
        usertmp--;
      ret = distance(PassArray->begin(), passtmp) * UserArray->size()
        + distance(UserArray->begin(), usertmp);
    }
  } else {
    if (usertmp != UserArray->begin())
      usertmp--;
    if (passvi == PassArray->end()) {
      ret = distance(UserArray->begin(), usertmp) * PassArray->size();
    } else {
      if (passtmp != PassArray->begin())
        passtmp--;
      ret = distance(UserArray->begin(), usertmp) * PassArray->size()
        + distance(PassArray->begin(), passtmp);
    }
  }

  if (ret) {
    ret /= (double) (UserArray->size() * PassArray->size());
    if (ret >= 0.9999)
      ret = 0.9999;
  } else
    ret = 0.0;

  return ret;
}


/*
 * Starts the timeout clock for the host running (e.g. you are
 * beginning a scan). If you do not have the current time handy,
 * you can pass in NULL. When done, call stopTimeOutClock (it will
 * also automatically be stopped of timedOut() returns true)
 */
void Service::
startTimeOutClock(const struct timeval *now) {
  assert(htn.toclock_running == false);
  htn.toclock_running = true;
  if (now) htn.toclock_start = *now;
  else gettimeofday(&htn.toclock_start, NULL);
  if (!htn.host_start) htn.host_start = htn.toclock_start.tv_sec;
}


/* The complement to startTimeOutClock. */
void Service::
stopTimeOutClock(const struct timeval *now) {
  struct timeval tv;
  assert(htn.toclock_running == true);
  htn.toclock_running = false;
  if (now) tv = *now;
  else gettimeofday(&tv, NULL);
  htn.msecs_used += timeval_msec_subtract(tv, htn.toclock_start);
  htn.host_end = tv.tv_sec;
}

/*
 * Returns whether the host is timedout. If the timeoutclock is
 * running, counts elapsed time for that. Pass NULL if you don't have the
 * current time handy. You might as well also pass NULL if the
 * clock is not running, as the func won't need the time.
 */
bool Service::
timedOut(const struct timeval *now) {
  unsigned long used = htn.msecs_used;
  struct timeval tv;

  if (!timeout)
    return false;
  if (htn.toclock_running) {
    if (now)
      tv = *now;
    else
      gettimeofday(&tv, NULL);

    used += timeval_msec_subtract(tv, htn.toclock_start);
  }

  return (used > (unsigned long)timeout)? true : false;
}

void Service::
setLinearState(size_t state) {

  linear_state = state;
}


size_t Service::
getLinearState(void) {

  return linear_state;
}
