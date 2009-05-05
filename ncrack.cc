#include "ncrack.h"
#include "nsock.h"
#include "utils.h"


extern void call_module(m_data *);

void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_module_end(nsock_pool nsp, nsock_iod nsi, void *mydata);

static void usage(const char *name);


/* the most complex function of them all */
static void
usage(const char *name)
{
	(void) fprintf(stderr, "%s -p <port> <hostname>\n",
			name);
	exit(EX_USAGE);
}


/* 
 * It handles module endings
 */
void
ncrack_module_end(nsock_pool nsp, nsock_iod nsi, void *mydata)
{
		m_data *mdata = (m_data *) mydata;
		
		if (mdata->attempts < mdata->max_attempts) {
			call_module(mdata);
		}

}


void
ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
	nsock_iod nsi = nse_iod(nse);
	enum nse_status status = nse_status(nse);
	enum nse_type type = nse_type(nse);
	int nbytes;
	char *str;
	m_data *mdata = (m_data *) mydata;

	printf("%s: status %s\n", __func__, nse_status2str(status));

	str = nse_readbuf(nse, &nbytes);
	mdata->buf = (char *)malloc(nbytes);
	mdata->bufsize = nbytes;
	memcpy(mdata->buf, str, nbytes);

	call_module(mdata);

	return;
}




void
ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
	nsock_iod nsi = nse_iod(nse);
	enum nse_status status = nse_status(nse);
	enum nse_type type = nse_type(nse);

	m_data *mdata = (m_data *) mydata;

	printf("%s: status %s\n", __func__, nse_status2str(status));

	call_module(mdata);

	return;
}




void
ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
	nsock_iod nsi = nse_iod(nse);
	enum nse_status status = nse_status(nse);
	enum nse_type type = nse_type(nse);

	m_data *mdata = (m_data *) mydata;
	mdata->protocol = IPPROTO_TCP;
	mdata->state = 0;

	call_module(mdata);

	return;
}


int main(int argc, char **argv)
{
	int opt;
	char *name;
	socklen_t addrlen;
	struct in_addr target;
	uint16_t port;
	extern char *optarg;
	extern int optind, opterr, optopt;
	int tracelevel = 0;
	nsock_iod tcp_nsi;
	enum nsock_loopstatus loopret;
	struct sockaddr_in taddr;
	struct timeval now;
	m_data mdata; /* module specific data */

	nsock_pool nsp;
	nsock_event_id ev;

	name = argv[0];

	while ((opt = getopt(argc, argv, "p:h")) != -1)
	{
		switch (opt)
		{
			case 'p':   /* server listening port */
				port = atoi(optarg);
				break;
			case 'h':   /* help */
				usage(name);
				break;
			case '?':   /* error */
			  (void) fprintf(stderr, "option inconsistency:"
				" -%c\n", optopt);
				usage(name);
		}
	}

 if (argc - optind <= 0 || argc - optind > 2)
    usage(name);

	if (!inet_pton(AF_INET, argv[optind], &target))
		fatal("inet_pton\n");


	/* create nsock p00l */
	if (!(nsp = nsp_new(NULL))) 
		fatal("Can't create nsock pool.\n");
	
	gettimeofday(&now, NULL);
	nsp_settrace(nsp, tracelevel, &now);

	if ((tcp_nsi = nsi_new(nsp, NULL)) == NULL)
    fatal("Failed to create new nsock_iod.  QUITTING.\n");
	
	taddr.sin_family = AF_INET;
	taddr.sin_addr = target;
	taddr.sin_port = port;

	memset(&mdata, 0, sizeof(mdata));
	mdata.nsp = nsp;
	mdata.nsi = tcp_nsi;
	mdata.max_attempts = 4;

	ev = nsock_connect_tcp(nsp, tcp_nsi, ncrack_connect_handler, 10000, &mdata,
			(struct sockaddr *) &taddr, sizeof taddr, port);

	/* nsock loop */
	loopret = nsock_loop(nsp, -1);

	printf("nsock_loop returned %d\n", loopret);

	return 0;
}
