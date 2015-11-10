
/***************************************************************************
 * Service.cc -- The "Service" class encapsulates every bit of information *
 * about the associated target's (Target class) service. Service-specific  *
 * options, statistical and timing information as well as functions for    *
 * handling username/password list iteration all belong to this class.     *
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

  end.orly = false;
  end.reason = NULL;
  
  module_data = NULL;
  hostinfo = NULL;
  memset(&last, 0, sizeof(last));
  memset(&last_auth_rate, 0, sizeof(last_auth_rate));

  htn.msecs_used = 0;
  htn.toclock_running = false;
  htn.host_start = htn.host_end = 0;
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

  if (!strcmp(name, "ssh")) {

    //printf("ssh special case\n");

    /* special case for ssh */
    if (just_started == true) {
      //printf("just started\n");

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

      //printf("user: %s \n", *user);
      //printf("pass: %s \n", *pass);
      return 0;
    } 
  }

  if (o.pairwise) {

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

    /* Iteration of username list for each password (default). */
  } else if (!o.passwords_first) {
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

    /* Iteration of password list for each username. */
  } else if (o.passwords_first) { 
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
    if (o.debugging > 8)
      log_write(LOG_STDOUT, "%s Pool: Removed %s %s\n", HostInfo(),
          tmp.user, tmp.pass);
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

  if (o.debugging > 8)
    log_write(LOG_STDOUT, "%s Pool: Append '%s' '%s' \n", HostInfo(),
        tmp.user, tmp.pass);

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


