#include "Service.h"


/* A connection must *always* belong to one specific Service */
Connection::Connection(Service *serv)
{
	state = 0;
	service = serv;
  retry = false;
  auth_complete = false;
  login_attempts = 0;
}

Connection::~Connection()
{
  if (buf) {
    free(buf);
    buf = NULL;
  }
}


Service::Service()
{
	name = NULL;
	target = NULL;
	proto = IPPROTO_TCP;
	portno = 0;
	userfini = false;
  full = false;
  stalled = false;
  finishing = false;
  finished = false;
  total_attempts = 0;
  active_connections = 0;
	connection_limit = -1;
	auth_limit = -1;
	connection_delay = -1;
	retries = -1;
	ssl = false;
	module_data = NULL;
  memset(&last, 0, sizeof(last));
  LoginArray = NULL;
  PassArray = NULL;
  hostinfo = NULL;
}

/* copy constructor */
Service::Service(const Service& ref)
{
	name = strdup(ref.name);
	proto = ref.proto;
	portno = ref.portno;
	connection_limit = ref.connection_limit;
	auth_limit = ref.auth_limit;
	connection_delay = ref.connection_delay;
	retries = ref.retries;
	ssl = ref.ssl;
  LoginArray = ref.LoginArray;
  PassArray = ref.PassArray;
  loginvi = LoginArray->begin();
  passvi = PassArray->begin();
  active_connections = 0;
  total_attempts = 0;
  full = false;
  userfini = false;
  finishing = false;
  stalled = false;
  finished = false;
  hostinfo = NULL;
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


char *
Service::NextLogin(void)
{
  char *ret;
  loginvi++;

  if (loginvi == LoginArray->end()) {
    printf("DONE!\n");
    userfini = true;
    return NULL;
  }

  ret = *loginvi;
  return ret;
}


char *
Service::NextPass(void)
{
  char *ret;

  ret = *passvi;
  printf("PASS %s\n", ret);
  passvi++;
  return ret;
}


/* 
 * returns -1 for end of login list
 * 0 for successful retrieval through lists
 * 1 for successful retrieval through pool
 */
int 
Service::NextPair(char **login, char **pass)
{
  if (!PassArray)
    fatal("%s: uninitialized LoginArray\n", __func__);

  if (!PassArray)
    fatal("%s: uninitialized PassArray\n", __func__);

  loginpair tmp;

  if (!pair_pool.empty()) {
    
    list <loginpair>::iterator pairli = pair_pool.begin();
    tmp = pair_pool.front();
    *login = tmp.login;
    *pass = tmp.pass;
    pair_pool.erase(pairli);
    printf("Pool: extract %s %s\n", tmp.login, tmp.pass);
    return 1;
  }

  if (userfini)
    return -1;
    
  if (passvi == PassArray->end()) {
    passvi = PassArray->begin();
    *login = NextLogin();
    if (!*login) {
      return -1;
    }
  } else {
    *login = *loginvi;
  }
  *pass = NextPass();

  return 0;
}


void
Service::RemoveFromPool(char *login, char *pass)
{
  loginpair tmp;
  list <loginpair>::iterator li;

  printf("Pool: Remove\n");

  if (!login || !pass)
    return;

  tmp.login = login;
  tmp.pass = pass;

  for (li = mirror_pair_pool.begin(); li != mirror_pair_pool.end(); li++) {
    if ((tmp.login == li->login) && (tmp.pass == li->pass))
      break;
  }
  if (li != mirror_pair_pool.end()) {
    printf("Pool: Removed %s %s\n", tmp.login, tmp.pass);
    mirror_pair_pool.erase(li);
  }
}



void
Service::AppendToPool(char *login, char *pass)
{
  loginpair tmp;
  list <loginpair>::iterator li;


  if (!login)
    fatal("%s: tried to append NULL login into pair pool\n", __func__);
  if (!pass)
    fatal("%s: tried to append NULL password into pair pool\n", __func__);

  tmp.login = login;
  tmp.pass = pass;
  pair_pool.push_back(tmp);

  printf("Pool: Append %s %s \n", tmp.login, tmp.pass);

  /* 
   * Try and see if login pair was already in our mirror pool. Only if
   * it doesn't already exist, then append it to the list.
   */
  for (li = mirror_pair_pool.begin(); li != mirror_pair_pool.end(); li++) {
    if ((tmp.login == li->login) && (tmp.pass == li->pass))
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
