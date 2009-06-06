#ifndef SERVICE_H
#define SERVICE_H

#include "ncrack.h"
#include "utils.h"
#include "Target.h"
#include "timing.h"
#include <list>


#define BUFSIZE 256
#define MAX_HOSTINFO_LEN 1024

class Connection;
class Service;


/* 
 * Active connection taking place for authenticating service.
 * Each connection may try to authenticatate more than once before closing,
 * depending on the service. For UDP 1 connection = 1 authentication session.
 */
class Connection
{
	public:
		Connection(Service *serv);
		~Connection();

		int time_started;
		int time_elapsed;

    char *login;
    char *pass;

    bool check;         /* true -> check if peer closed connection on us */
    bool auth_complete; /* true -> login pair tested */
    bool from_pool;     /* true -> login pair was extracted from pair_pool */
    bool retry;         /* true- > retry login attempt within current connection */

		int state;    /* module state-machine's current state */
		char *buf;    /* auxiliary buffer */
		int bufsize;  /* buffer size not including '\0' */
		unsigned int login_attempts;  /* login attempts up until now */
		nsock_iod niod;     /* I/O descriptor for this connection */
		Service *service;   /* service it belongs to */
};


typedef struct loginpair
{
  char *login;
  char *pass;
} loginpair;


class Service
{
	public:
		Service();
		~Service();

		Service(const Service&); /* copy constructor */
    int NextPair(char **login, char **pass);
    const char *HostInfo(void);
    void AppendToPool(char *login, char *pass);
    void RemoveFromPool(char *login, char *pass);
    bool isMirrorPoolEmpty(void);
    bool isPoolEmpty(void);

		/* members */
		char *name;
		Target *target; /* service belongs to this host */
		u8 proto;
		u16 portno;

    
		bool userfini; /* true if username list has been iterated through */
    bool stalled;   /* service is now on 'services_stalled' list */
    bool full;      /* service is now on 'services_full' list */
    bool finishing; /* service is now on 'services_finishing' list */
    bool finished;  /* service is now on 'services_finished' list */


    vector <char *> *LoginArray;
    vector <char *> *PassArray;

    long active_connections;
    struct timeval last; /* time of last activated connection */
    unsigned int total_attempts;

		/* timing options that override global ones */
		long connection_limit; 
		long auth_limit;
		long connection_delay;
		long retries;
		/* misc options */
		bool ssl;
		void *module_data; /* service/module-specific data */

		list <Connection *> connections;
  private:

    /* 
     * hostinfo in form "<service_name>://<ip or hostname>:<port number>"
     * e.g ftp://scanme.nmap.org:21
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
     * aren't removed from the list at the time they are used (by NextPair().
     * By this way we can determine, if we are currently using pairs from the
     * pair_pool by checking if the mirror_pair_pool is non-empty.
     */
    list <loginpair> mirror_pair_pool;

    vector <char *>::iterator loginvi;
    vector <char *>::iterator passvi;
    char *NextLogin(void);
    char *NextPass(void);
};



#endif 
