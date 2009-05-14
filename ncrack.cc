#include "ncrack.h"
#include "NcrackOps.h"
#include "utils.h"
#include "targets.h"
#include "TargetGroup.h"
#include "nsock.h"
#include "global_structures.h"
#include <time.h>

#include <vector>

extern NcrackOps o;
using namespace std;


extern void call_module(m_data *);

void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_module_end(nsock_pool nsp, nsock_iod nsi, void *mydata);

static void printusage(void);
static char *grab_next_host_spec(FILE *inputfd, int argc, char **argv);
static int ncrack(vector <Target *> &Targets);


static void
printusage(void)
{
	printf("%s %s ( %s )\n"
			"Usage: ncrack [Options] -s <service_name> {target specification}\n"
			"SERVICE SPECIFICATION:\n"
			"  -s <service_name>: (required option) protocol name e.g ssh, telnet, ftp etc\n"
			"  -p <port>: for services that listen on non-default ports\n"
			"TARGET SPECIFICATION:\n"
			"  Can pass hostnames, IP addresses, networks, etc.\n"
			"  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254\n"
			"  -iL <inputfilename>: Input from list of hosts/networks\n"
			"  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks\n"
			"  --excludefile <exclude_file>: Exclude list from file\n"
			"TIMING AND PERFORMANCE:\n"
			"  Options which take <time> are in milliseconds, unless you append 's'\n"
			"  (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).\n"
			"  --min-hostgroup/max-hostgroup <size>: Parallel host crack group sizes\n"
			"  --min-parallelism/max-parallelism <time>: Probe parallelization\n"
			"  --max-retries <tries>: Caps number of service connection attempts.\n"
			"  --host-timeout <time>: Give up on target after this long\n"
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




static char *
grab_next_host_spec(FILE *inputfd, int argc, char **argv)
{
	static char host_spec[1024];
	unsigned int host_spec_index;
	int ch;

	if (!inputfd) {
		return ((optind < argc) ? argv[optind++] : NULL);
	} else { 
		host_spec_index = 0;
		while((ch = getc(inputfd)) != EOF) {
			if (ch == ' ' || ch == '\r' || ch == '\n' || ch == '\t' || ch == '\0') {
				if (host_spec_index == 0)
					continue;
				host_spec[host_spec_index] = '\0';
				return host_spec;
			} else if (host_spec_index < sizeof(host_spec) / sizeof(char) -1) {
				host_spec[host_spec_index++] = (char) ch;
			} else fatal("One of the host_specifications from your input file "
					"is too long (> %d chars)", (int) sizeof(host_spec));
		}
		host_spec[host_spec_index] = '\0';
	}
	if (!*host_spec) 
		return NULL;
	return host_spec;
}


static void
ncrack_service(void)
{
	//if (strcmp(o.service, "ftp"));

	// use lookup table 

}



int main(int argc, char **argv)
{
	struct in_addr target;
	uint16_t port;
	struct sockaddr_in taddr;
	FILE *inputfd = NULL;
	unsigned long l;

	struct tm *tm;
	time_t now;
	char tbuf[128];

	/* exclude-specific variables */
	FILE *excludefd = NULL;
	char *exclude_spec = NULL;
	TargetGroup *exclude_group = NULL;


	/* getopt-specific */
	int arg;
	int option_index;
	extern char *optarg;
	extern int optind;
	struct option long_options[] =
	{
		{"service", required_argument, 0, 's'},
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
		{"iL", required_argument, 0, 'i'},
		{"host_timeout", required_argument, 0, 0},
		{"host-timeout", required_argument, 0, 0},
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

	if (argc < 2)
		printusage();

	/* Argument parsing */
	optind = 1;
	while((arg = getopt_long_only(argc, argv, "hd::i:p:s:vV", long_options, &option_index)) != EOF) {
		switch(arg) {
			case 0:
				if (!strcmp(long_options[option_index].name, "excludefile")) {
					if (exclude_spec)
						fatal("--excludefile and --exclude options are mutually exclusive.");
					excludefd = fopen(optarg, "r");
					if (!excludefd)
						fatal("Failed to open exclude file %s for reading", optarg);
				} else if (!strcmp(long_options[option_index].name, "exclude")) {
					if (excludefd)
						fatal("--excludefile and --exclude options are mutually exclusive.");
					exclude_spec = strdup(optarg);

				} else if (!optcmp(long_options[option_index].name, "host-timeout")) {
					l = tval2msecs(optarg);
					if (l <= 1500)
							fatal("--host-timeout is specified in milliseconds unless you "
							"qualify it by appending 's', 'm', or 'h'. The value must be greater "
							"than 1500 milliseconds");
					o.host_timeout = l;
					if (l < 30000) 
						error("host-timeout is given in milliseconds, so you specified less "
								"than 30 seconds (%lims). This is allowed but not recommended.", l);
				} else if (!strcmp(long_options[option_index].name, "service")) {
					o.service = optarg;
				}
				break;
			case 'd': 
				if (optarg)
					o.debugging = o.verbose = atoi(optarg);
				else 
					o.debugging++; o.verbose++;
				break;
			case 'h':   /* help */
				printusage();
				break;
			case 'i': 
				if (inputfd)
					fatal("Only one input filename allowed");
				if (!strcmp(optarg, "-"))
					inputfd = stdin;
				else {    
					inputfd = fopen(optarg, "r");
					if (!inputfd) 
						fatal("Failed to open input file %s for reading", optarg);
				}
				break; 
			case 'p':   /* service port */
				port = atoi(optarg);
				break;
			case 's':		/* service - required option */
				if (o.service)
					fatal("Specify only one service, either with -s or --service.\n");
				o.service = optarg;
				break;
			case 'V':
				printf("\n%s version %s ( %s )\n", NCRACK_NAME, NCRACK_VERSION, NCRACK_URL);
				break;
			case 'v':
				o.verbose++;
				break;
			case '?':   /* error */
				printusage();
		}
	}

	if (!o.service)
		fatal("Specify one service, either with -s or --service.\n");

	ncrack_service();

	now = time(NULL);
	tm = localtime(&now);
	if (strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M %Z", tm) <= 0)
		fatal("Unable to properly format time");
	printf("\nStarting %s %s ( %s ) at %s\n", NCRACK_NAME, NCRACK_VERSION, NCRACK_URL, tbuf);


	o.setaf(AF_INET);

	char **host_exp_group;
	HostGroupState *hstate;
	Target *currenths;
	int num_host_exp_groups;
	char *host_spec = NULL;
	vector <Target *> Targets;

	/* lets load our exclude list */
	if ((NULL != excludefd) || (NULL != exclude_spec)) {
		exclude_group = load_exclude(excludefd, exclude_spec);

		if (o.debugging > 3)
			dumpExclude(exclude_group);

		if ((FILE *)NULL != excludefd)
			fclose(excludefd);
		if ((char *)NULL != exclude_spec)
			free(exclude_spec);
	}

	printf("service %s\n", o.service);


	host_exp_group = (char **) safe_malloc(o.max_group_size * sizeof(char *));
	num_host_exp_groups = 0;

	o.max_group_size = 4096;
	unsigned int ideal_scan_group_size = o.max_group_size;

	hstate = new HostGroupState(o.max_group_size, host_exp_group, num_host_exp_groups);


	do {
		while (Targets.size() < ideal_scan_group_size) {
			currenths = nexthost(hstate, exclude_group);
			if (!currenths) {
				/* Try to refill with any remaining expressions */
				/* First free the old ones */
				for(int i = 0; i < num_host_exp_groups; i++)
					free(host_exp_group[i]);

				num_host_exp_groups = 0;
				/* Now grab any new expressions */
				while (num_host_exp_groups < o.max_group_size && 
						(host_spec = grab_next_host_spec(inputfd, argc, argv))) {
					// For purposes of random scan - TODO: see this
					host_exp_group[num_host_exp_groups++] = strdup(host_spec);
				}

				if (num_host_exp_groups == 0)
					break;
				delete hstate;
				hstate = new HostGroupState(o.max_group_size, host_exp_group, num_host_exp_groups);

				/* Try one last time -- with new expressions */
				currenths = nexthost(hstate, exclude_group);
				if (!currenths)
					break;
			}
			Targets.push_back(currenths);
		}

		if (Targets.size() == 0)
			break; 

		for (unsigned int i = 0; i < Targets.size(); i++) {
			printf("%s\n", Targets[i]->NameIP());
		}


		/* Ncrack 'em all! */
		ncrack(Targets);

		/* Free all of the Targets */
		while(!Targets.empty()) {
			currenths = Targets.back();
			delete currenths;
			Targets.pop_back();
		}

	} while (1);

	printf("Ncrack finished.\n");
	exit(EXIT_SUCCESS);

}


static int
ncrack(vector <Target *> &Targets)
{
	/* nsock variables */
	nsock_iod tcp_nsi;
	enum nsock_loopstatus loopret;
	nsock_pool nsp;
	nsock_event_id ev;
	int tracelevel = 0;

	struct timeval now;

	/* module specific data */
	m_data mdata; 

	/* create nsock p00l */
	if (!(nsp = nsp_new(NULL))) 
		fatal("Can't create nsock pool.\n");

	gettimeofday(&now, NULL);
	nsp_settrace(nsp, tracelevel, &now);

	if ((tcp_nsi = nsi_new(nsp, NULL)) == NULL)
		fatal("Failed to create new nsock_iod.  QUITTING.\n");



	memset(&mdata, 0, sizeof(mdata));
	mdata.nsp = nsp;
	mdata.nsi = tcp_nsi;
	mdata.max_attempts = 4;

	//ev = nsock_connect_tcp(nsp, tcp_nsi, ncrack_connect_handler, 10000, &mdata,
	//		(struct sockaddr *) &taddr, sizeof taddr, port);

	/* nsock loop */
	loopret = nsock_loop(nsp, -1);

	printf("nsock_loop returned %d\n", loopret);

	return 0;

}
