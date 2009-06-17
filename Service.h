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

    char *user;
    char *pass;

    /* 
     * True when we peer might close connection at the near moment. 
     * Consider the case, when some services after reaching the maximum
     * authentication limit per connecton, just drop the connection without
     * specifically telling you that you failed at the last authentication
     * attempt. Thus, we use this, to be able to count the correct number of
     * maximum attempts the peer lets us do (stored in 'supported_attempts'
     * inside the Service class). A module should probably set it to true
     * after writing the password on the wire and before issuing the next
     * read call. Also if you use it, don't forget to set it to false, in the first
     * state of your module, because we might need it to differentiate between
     * normal server FINs and FINs/RSTs sent in the middle of an authentication
     * due to strange network conditions.
     */
    bool peer_might_close; 

    bool check_closed;  /* true -> check if peer closed connection on us */
    bool peer_alive;    /* true -> if peer is certain to be alive currently */
    bool auth_complete; /* true -> login pair tested */
    bool from_pool;     /* true -> login pair was extracted from pair_pool */
    bool auth_success;  /* true -> we found a valid pair!!! */

    void *misc_info;    /* additional state information that might be needed */

		int state;          /* module state-machine's current state */
		char *buf;          /* auxiliary buffer */
		int bufsize;        /* total buffer size in bytes */
		long login_attempts;/* login attempts up until now */
		nsock_iod niod;     /* I/O descriptor for this connection */
		Service *service;   /* service it belongs to */
};


typedef struct loginpair
{
  char *user;
  char *pass;
} loginpair;


class Service
{
	public:
		Service();
		~Service();

		Service(const Service&); /* copy constructor */
    const char *HostInfo(void);
    
    int NextPair(char **login, char **pass);
    void AppendToPool(char *login, char *pass);
    void RemoveFromPool(char *login, char *pass);
    bool isMirrorPoolEmpty(void);
    bool isPoolEmpty(void);

    void SetListActive(void);
    void SetListWait(void);
    void SetListStalled(void);
    void SetListFull(void);
    void SetListFinishing(void);
    void SetListFinished(void);

		/* members */
		char *name;
		Target *target; /* service belongs to this host */
		u8 proto;
		u16 portno;
  
		bool loginlist_fini;/* true if login list has been iterated through */ 
    bool list_active;   /* service is now on 'services_active' list */
    bool list_wait;     /* service is now on 'services_wait' list */
    bool list_stalled;  /* service is now on 'services_stalled' list */ 
    bool list_full;     /* service is now on 'services_full' list */
    bool list_finishing;/* service is now on 'services_finishing' list */
    bool list_finished; /* service is now on 'services_finished' list */

    vector <char *> *UserArray;
    vector <char *> *PassArray;

    bool just_started;
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
    unsigned int supported_attempts;

    /* total auth attempts, including failed ones */
    unsigned int total_attempts;
    
    /* auth attempts that have finished up to the point of completing
     * all authentication steps and getting the results */
    unsigned int finished_attempts; 

		/* timing options that override global ones */
		long min_connection_limit;  /* minimum number of concurrent parallel connections */
    long max_connection_limit;  /* maximum number of concurrent parallel connections */
    long ideal_parallelism;     /* ideal number of concurrent parallel connections */
		long auth_tries;            /* authentication attempts per connections */
		long connection_delay;      /* number of milliseconds to wait between each connection */
		long connection_retries;    /* number of connection retries after connection failure */
		/* misc options */
		bool ssl;
		void *module_data; /* service/module-specific data */

    RateMeter auth_rate_meter;
    struct last_auth_rate { 
      double rate;
      struct timeval time;
    } last_auth_rate;

		list <Connection *> connections;

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
};



#endif 
