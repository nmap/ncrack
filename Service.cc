#include "Service.h"
#include "NcrackOps.h"

extern NcrackOps o;


/* A connection must *always* belong to one specific Service */
Connection::Connection(Service *serv)
{
	state = 0;
	service = serv;
  check_closed = false;
  auth_complete = false;
  auth_success = false;
  peer_alive = false;
  peer_might_close = false;
  login_attempts = 0;
  buf = NULL;
  misc_info = NULL;
}

Connection::~Connection()
{
  if (buf) {
    free(buf);
    buf = NULL;
  }
  if (misc_info) {
    free(misc_info);
    misc_info = NULL;
  }
}


Service::Service()
{
	name = NULL;
	target = NULL;
	proto = IPPROTO_TCP;
	portno = 0;

	loginlist_fini = false;
  list_active = true;
  list_full = false;
  list_wait = false;
  list_stalled = false;
  list_finishing = false;
  list_finished = false;
  just_started = true;

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

	ssl = false;
	module_data = NULL;
  memset(&last, 0, sizeof(last));
  UserArray = NULL;
  PassArray = NULL;
  hostinfo = NULL;
  memset(&last_auth_rate, 0, sizeof(last_auth_rate));
}

/* copy constructor */
Service::Service(const Service& ref)
{
	name = strdup(ref.name);
	proto = ref.proto;
	portno = ref.portno;

	min_connection_limit = ref.min_connection_limit;
  max_connection_limit = ref.max_connection_limit;
	auth_tries = ref.auth_tries;
	connection_delay = ref.connection_delay;
	connection_retries = ref.connection_retries;
  ideal_parallelism = 1;  /* we start with 1 connection exactly */

	ssl = ref.ssl;
  UserArray = ref.UserArray;
  PassArray = ref.PassArray;
  uservi = UserArray->begin();
  passvi = PassArray->begin();
  active_connections = 0;
  total_attempts = 0;
  finished_attempts = 0;
  failed_connections = 0;

  loginlist_fini = false;
  list_active = true;
  list_full = false;
  list_wait = false;
  list_stalled = false;
  list_finishing = false;
  list_finished = false;
  just_started = true;
  
  hostinfo = NULL;
  memset(&last_auth_rate, 0, sizeof(last_auth_rate));
}


const char *
Service::HostInfo(void)
{
  if (!hostinfo)
    hostinfo = (char *) safe_malloc(MAX_HOSTINFO_LEN);

  if (!target)
    fatal("%s: tried to print hostinfo with uninitialized Target\n", __func__);

  Snprintf(hostinfo, MAX_HOSTINFO_LEN, "%s://%s:%hu", name,
      target->NameIP(), portno);

  return hostinfo;
}




void
Service::SetListActive(void)
{
  list_active = true;
  list_wait = false;
  list_stalled = false;
  list_full = false;
  list_finishing = false;
  list_finished = false;
}

void
Service::SetListWait(void)
{
  list_active = false;
  list_wait = true;
  list_stalled = false;
  list_full = false;
  list_finishing = false;
  list_finished = false;
}


void
Service::SetListStalled(void)
{
  list_active = false;
  list_wait = false;
  list_stalled = true;
  list_full = false;
  list_finishing = false;
  list_finished = false;
}


void
Service::SetListFull(void)
{
  list_active = false;
  list_wait = false;
  list_stalled = false;
  list_full = true;
  list_finishing = false;
  list_finished = false;
}



void
Service::SetListFinishing(void)
{
  list_active = false;
  list_wait = false;
  list_stalled = false;
  list_full = false;
  list_finishing = true;
  list_finished = false;
}


void
Service::SetListFinished(void)
{
  list_active = false;
  list_wait = false;
  list_stalled = false;
  list_full = false;
  list_finishing = false;
  list_finished = true;
}


/* 
 * returns -1 for end of login list and empty pool
 * 0 for successful retrieval through lists
 * 1 for successful retrieval through pool
 */
int 
Service::NextPair(char **user, char **pass)
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
    if (o.debugging > 4)
      printf("%s Pool: extract %s %s\n", HostInfo(), tmp.user, tmp.pass);
    return 1;
  }

  if (loginlist_fini)
    return -1;

  /* Iteration of username list for each password (default). */
  if (!o.passwords_first) {
    /* If username list finished one iteration then reset the username pointer
     * to show at the beginning and get password from password list. */
    if (uservi == UserArray->end()) {
      uservi = UserArray->begin();
      passvi++;
      if (passvi == PassArray->end()) {
        if (o.debugging > 4)
          printf("%s Password list finished!\n", HostInfo());
        loginlist_fini = true;
        return -1;
      }
    }
    *pass = *passvi;
    *user = *uservi;
    uservi++;
  } else if (o.passwords_first) { /* Iteration of password list for each username. */
    /* If password list finished one iteration then reset the password pointer
     * to show at the beginning and get next username from username list. */
    if (passvi == PassArray->end()) {                                          
      passvi = PassArray->begin();
      uservi++;
      if (uservi == UserArray->end()) {
        if (o.debugging > 4)
          printf("%s Username list finished!\n", HostInfo());
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


void
Service::RemoveFromPool(char *user, char *pass)
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
    if (o.debugging > 4)
      printf("%s Pool: Removed %s %s\n", HostInfo(), tmp.user, tmp.pass);
    mirror_pair_pool.erase(li);
  }
}



void
Service::AppendToPool(char *user, char *pass)
{
  loginpair tmp;
  list <loginpair>::iterator li;

  if (!user)
    fatal("%s: tried to append NULL user into pair pool\n", __func__);
  if (!pass)
    fatal("%s: tried to append NULL password into pair pool\n", __func__);

  tmp.user = user;
  tmp.pass = pass;
  pair_pool.push_back(tmp);

  if (o.debugging > 4)
    printf("%s Pool: Append %s %s \n", HostInfo(), tmp.user, tmp.pass);

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


bool
Service::isMirrorPoolEmpty(void)
{
  return mirror_pair_pool.empty();
}


bool
Service::isPoolEmpty(void)
{
  return pair_pool.empty();
}


Service::~Service()
{
  if (name)
    free(name);
  if (module_data)
    free(module_data);
  if (hostinfo)
    free(hostinfo);
}
