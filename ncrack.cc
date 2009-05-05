#include "ncrack.h"
#include "NcrackOps.h"
#include "utils.h"
#include "targets.h"
#include "TargetGroup.h"
#include "nsock.h"
#include "global_structures.h"


extern NcrackOps o;
using namespace std;


extern void call_module(m_data *);

void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_module_end(nsock_pool nsp, nsock_iod nsi, void *mydata);

static void printusage(void);



static void
printusage(void)
{
	printf("%s %s ( %s )\n"
			"Usage: ncrack [service name/port] [Options] {target specification}\n"
		  "TARGET SPECIFICATION:\n"
			"  Can pass hostnames, IP addresses, networks, etc.\n"
			"  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254\n"
			"  -iL <inputfilename>: Input from list of hosts/networks\n"
			"  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks\n"
			"  --excludefile <exclude_file>: Exclude list from file\n"
			"TIMING AND PERFORMANCE:\n"
			"  Options which take <time> are in milliseconds, unless you append 's'\n"
			"  (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).\n"
			"  --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes\n"
			"  --min-parallelism/max-parallelism <time>: Probe parallelization\n"
			"  --max-retries <tries>: Caps number of port scan probe retransmissions.\n"
			"  --scan-delay/--max-scan-delay <time>: Adjust delay between probes\n"
			"MISC:\n"
			"  -V: Print version number\n"
			"  -h: Print this help summary page.\n", NCRACK_NAME, NCRACK_VERSION, NCRACK_URL);
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
	socklen_t addrlen;
	struct in_addr target;
	uint16_t port;
	struct sockaddr_in taddr;
	struct timeval now;

	/* exclude-specific variables */
	FILE *excludefd = NULL;
	char *exclude_spec = NULL;
	TargetGroup *exclude_group = NULL;

	/* nsock variables */
	nsock_iod tcp_nsi;
	enum nsock_loopstatus loopret;
	nsock_pool nsp;
	nsock_event_id ev;
	int tracelevel = 0;

	/* module specific data */
	m_data mdata; 

	/* getopt-specific */
	int arg;
	int option_index;
	extern char *optarg;
	extern int optind;
	struct option long_options[] =
	{
		{"version", no_argument, 0, 'V'},
		{"verbose", no_argument, 0, 'v'},
		{"debug", optional_argument, 0, 'd'},
		{"help", no_argument, 0, 'h'},
		{"max_parallelism", required_argument, 0, 'M'},
		{"max-parallelism", required_argument, 0, 'M'},
		{"min_parallelism", required_argument, 0, 0},
		{"min-parallelism", required_argument, 0, 0},
		{"excludefile", required_argument, 0, 0},
		{"exclude", required_argument, 0, 0},
		{"max_hostgroup", required_argument, 0, 0},
		{"max-hostgroup", required_argument, 0, 0},
		{"min_hostgroup", required_argument, 0, 0},
		{"min-hostgroup", required_argument, 0, 0},
		{"scan_delay", required_argument, 0, 0},
		{"scan-delay", required_argument, 0, 0},
		{"max_scan_delay", required_argument, 0, 0},
		{"max-scan-delay", required_argument, 0, 0},
		{"max_retries", required_argument, 0, 0},
		{"max-retries", required_argument, 0, 0},
		{0, 0, 0, 0}
	};



	/* Argument parsing */
	optind = 1; 
	while((arg = getopt_long_only(argc, argv, "p:hvV", long_options, &option_index)) != EOF) {
		switch(arg) {
			case 0:
				if (strcmp(long_options[option_index].name, "excludefile") == 0) {
					if (exclude_spec)
						fatal("--excludefile and --exclude options are mutually exclusive.");
					excludefd = fopen(optarg, "r");
					if (!excludefd)
						fatal("Failed to open exclude file %s for reading", optarg);
				} else if (strcmp(long_options[option_index].name, "exclude") == 0) {
					if (excludefd)
						fatal("--excludefile and --exclude options are mutually exclusive.");
					exclude_spec = strdup(optarg);
				}
				break;
			case 'p':   /* service port */
				port = atoi(optarg);
				break;
			case 'V':
				printf("\n%s version %s ( %s )\n", NCRACK_NAME, NCRACK_VERSION, NCRACK_URL);
				break;
			case 'h':   /* help */
				printusage();
				break;
			case '?':   /* error */
				(void) fprintf(stderr, "option inconsistency: -%c\n", optopt);
				printusage();

		}
	}


 o.setaf(AF_INET);




	//if (argc - optind <= 0 || argc - optind > 2)
	//   printusage();



	/* lets load our exclude list */
	if ((NULL != excludefd) || (NULL != exclude_spec)) {
		exclude_group = load_exclude(excludefd, exclude_spec);

		//if (o.debugging > 3)
			dumpExclude(exclude_group);

		if ((FILE *)NULL != excludefd)
			fclose(excludefd);
		if ((char *)NULL != exclude_spec)
			free(exclude_spec);
	}




	exit(-1);








		if (!inet_pton(AF_INET, argv[optind], &target))
			fatal("inet_pton\n");
		// BEGIN MAIN


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
