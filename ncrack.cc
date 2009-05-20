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

/* global lookup table for available services */
vector <service_lookup> ServicesSupported; 

#define DEFAULT_CONNECT_TIMEOUT 5000

extern void call_module(m_data *);

/* callback handlers */
void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_module_end(nsock_pool nsp, nsock_iod nsi, void *mydata);

/* schedule additional connections */
int ncrack_probes(nsock_pool nsp, ServiceGroup *SG);
/* ncrack initialization */
static int ncrack(vector <Target *> &Targets);

static void print_usage(void);
static void lookup_init(const char *const filename);
static char *grab_next_host_spec(FILE *inputfd, int argc, char **argv);


static void
print_usage(void)
{
	printf("%s %s ( %s )\n"
			"Usage: ncrack [Options] {target specification}\n"
			"TARGET SPECIFICATION:\n"
			"  Can pass hostnames, IP addresses, networks, etc.\n"
			"  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254\n"
			"  -iL <inputfilename>: Input from list of hosts/networks\n"
			"  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks\n"
			"  --excludefile <exclude_file>: Exclude list from file\n"
			"SERVICE SPECIFICATION:\n"
			"  Can pass target specific services (after each hostgroup) or global ones\n"
			"  Services can be passed as names or default ports. For non-default ports\n"
			"  they must be specified it in form 'service_name:port'\n"
			"  Ex: scanme.nmap.org[ssh,ftp:310,25] 10.0.0.*://telnet -p ssh:2130\n"
			"  -p <service-list>: services that will be applied to all hosts (global)\n"
			"TIMING AND PERFORMANCE:\n"
			"  Options which take <time> are in milliseconds, unless you append 's'\n"
			"  (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).\n"
			"  --min-hostgroup/max-hostgroup <size>: Parallel host crack group sizes\n"
			"  --min-parallelism/max-parallelism <time>: Probe parallelization\n"
			"  --max-retries <tries>: Caps number of service connection attempts.\n"
			"  --host-timeout <time>: Give up on target after this long\n"
			"  --scan-delay/--max-scan-delay <time>: Adjust delay between probes\n"
			"OUTPUT:\n"
			"  -v: Increase verbosity level (use twice or more for greater effect)\n"
  		"  -d[level]: Set or increase debugging level (Up to 9 is meaningful)\n"
			"MISC:\n"
			"  --list or -sL: only list hosts and services\n"
			"  -V: Print version number\n"
			"  -h: Print this help summary page.\n", NCRACK_NAME, NCRACK_VERSION, NCRACK_URL);
	exit(EX_USAGE);
}


static void
lookup_init(const char *const filename)
{
	char line[1024];
	char servicename[128], proto[16];
	u16 portno;
	FILE *fp;
	vector <service_lookup>::iterator vi;
	service_lookup temp;

	fp = fopen(filename, "r");
	if (!fp) 
		fatal("%s: failed to open file %s for reading!\n", __func__, filename);

	while(fgets(line, sizeof(line), fp)) {
		if (*line == '\n' || *line == '#')
			continue;

		if (sscanf(line, "%127s %hu/%15s", servicename, &portno, proto) != 3)
			fatal("invalid ncrack-services file: %s\n", filename);

		temp.portno = portno;
		temp.proto = str2proto(proto);
		temp.name = strdup(servicename);

		for (vi = ServicesSupported.begin(); vi != ServicesSupported.end(); vi++) {
			if ((vi->portno == temp.portno) && (vi->proto == temp.proto)
					&& !(strcmp(vi->name, temp.name))) {
				if (o.debugging)
					error("Port %d proto %s is duplicated in services file %s\n", 
							portno, proto, filename);
				continue;
			}
		}
		ServicesSupported.push_back(temp);
	}

	fclose(fp);
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
					"is too long (> %d chars)\n", (int) sizeof(host_spec));
		}
		host_spec[host_spec_index] = '\0';
	}
	if (!*host_spec) 
		return NULL;
	return host_spec;
}





int main(int argc, char **argv)
{
	vector <service_lookup *> services_cmd;

	FILE *inputfd = NULL;
	unsigned long l;

	/* time variables */
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
		{"list", no_argument, 0, 0},
		{"services", required_argument, 0, 'p'},
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
		print_usage();

	/* Initialize available services' lookup table */
	lookup_init("ncrack-services");


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
				} else if (!strcmp(long_options[option_index].name, "services")) {
					parse_services_handler(optarg, services_cmd);
				} else if (!strcmp(long_options[option_index].name, "list")) {
					o.list_only++;
				}
				break;
			case 'd': 
				if (optarg)
					o.debugging = o.verbose = atoi(optarg);
				else 
					o.debugging++; o.verbose++;
				break;
			case 'h':   /* help */
				print_usage();
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
			case 'p':   /* services */
				parse_services_handler(optarg, services_cmd); 
				break;
			case 's':	/* only list hosts */
				if (*optarg == 'L')
					o.list_only++;
				else {
					error("Illegal argument for option '-s' Did you mean -sL?\n");
					print_usage();
				}
				break;
			case 'V':	
				printf("\n%s version %s ( %s )\n", NCRACK_NAME, NCRACK_VERSION, NCRACK_URL);
				break;
			case 'v':
				o.verbose++;
				break;
			case '?':   /* error */
				print_usage();
		}
	}


	// ncrack_service();

	now = time(NULL);
	tm = localtime(&now);
	if (strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M %Z", tm) <= 0)
		fatal("Unable to properly format time");
	printf("\nStarting %s %s ( %s ) at %s\n\n", NCRACK_NAME, NCRACK_VERSION, NCRACK_URL, tbuf);

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

	host_exp_group = (char **) safe_malloc(o.max_group_size * sizeof(char *));
	num_host_exp_groups = 0;

	o.max_group_size = 4096;
	unsigned int ideal_scan_group_size = o.max_group_size;

	hstate = new HostGroupState(o.max_group_size, host_exp_group, num_host_exp_groups);


	do {
		while (Targets.size() < ideal_scan_group_size) {
			currenths = nexthost(hstate, exclude_group, services_cmd);
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
				currenths = nexthost(hstate, exclude_group, services_cmd);
				if (!currenths)
					break;
			}
			Targets.push_back(currenths);
		}

		if (Targets.size() == 0)
			break; 

		if (o.list_only) {
			printf("\n=== Targets ===\n");
			for (unsigned int i = 0; i < Targets.size(); i++) {
				printf("Host: %s\n", Targets[i]->NameIP());
				for (unsigned int j = 0; j < Targets[i]->services.size(); j++) {
					printf("  %s:%hu\n", 
							Targets[i]->services[j]->name,
							Targets[i]->services[j]->portno);
				}
			}
		} else {
			/* Ncrack 'em all! */
			ncrack(Targets);
		}

		/* Free all of the Targets */
		while(!Targets.empty()) {
			currenths = Targets.back();
			while (!currenths->services.empty()) {
				free(currenths->services.back());
				currenths->services.pop_back();
			}		
			delete currenths;
			Targets.pop_back();
		}

	} while (1);

	printf("\nNcrack finished.\n");
	exit(EXIT_SUCCESS);

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

 //m_data *mdata = (m_data *) mydata;
 //mdata->protocol = IPPROTO_TCP;
 //mdata->state = 0;

 //call_module(mdata);

 return;
}




int
ncrack_probes(nsock_pool nsp, ServiceGroup *SG) {
  Service *serv;
	Connection *connection;
	struct sockaddr_storage ss;
	size_t ss_len;
	list <Service *>::iterator li;


	if (SG->last_accessed == SG->services_remaining.end())
		li = SG->services_remaining.begin();
	else 
		li = SG->last_accessed;

	int i = 0;

  while (SG->active_connections < SG->ideal_parallelism
			&& SG->services_finished.size() != SG->total_services) {
		serv = *li;
		if (serv->target->timedOut(nsock_gettimeofday())) {
      // end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, NULL);  TODO: HANDLE
      continue;
    }

		/* Schedule 1 connection for this service */
		connection = new Connection();
		if ((connection->niod = nsi_new(nsp, serv)) == NULL) {
      fatal("Failed to allocate Nsock I/O descriptor in %s()", __func__);
    }
		serv->connections.push_back(connection);

		serv->target->TargetSockAddr(&ss, &ss_len);
		if (serv->proto == IPPROTO_TCP)
      nsock_connect_tcp(nsp, connection->niod, ncrack_connect_handler, 
			DEFAULT_CONNECT_TIMEOUT, serv, 
			(struct sockaddr *)&ss, ss_len,
			serv->portno);
    else {
      assert(serv->proto == IPPROTO_UDP);
      nsock_connect_udp(nsp, connection->niod, ncrack_connect_handler, 
			serv, (struct sockaddr *) &ss, ss_len,
			serv->portno);
    }

		i++; // temporary
		if (i == 10)
			break;

		SG->last_accessed = li;
		if (++li == SG->services_remaining.end())
			li = SG->services_remaining.begin();

		// pop / push etc

	}
	return 0;
}





static int
ncrack(vector <Target *> &Targets)
{
	/* nsock variables */
	struct timeval now;
	enum nsock_loopstatus loopret;
	nsock_pool nsp;
	int tracelevel = 0;
	ServiceGroup *SG;

	SG = new ServiceGroup(Targets);

	/* create nsock p00l */
	if (!(nsp = nsp_new(SG))) 
		fatal("Can't create nsock pool.\n");

	gettimeofday(&now, NULL);
	nsp_settrace(nsp, tracelevel, &now);

	ncrack_probes(nsp, SG);

	/* nsock loop */
	loopret = nsock_loop(nsp, -1);
	if (o.debugging > 8)
		printf("nsock_loop returned %d\n", loopret);

	return 0;

}
