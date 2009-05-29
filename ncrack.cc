#include "ncrack.h"
#include "NcrackOps.h"
#include "utils.h"
#include "services.h"
#include "targets.h"
#include "TargetGroup.h"
#include "nsock.h"
#include "global_structures.h"
#include "modules.h"
#include <time.h>
#include <vector>

#define DEFAULT_CONNECT_TIMEOUT 5000

extern NcrackOps o;
using namespace std;

/* global lookup table for available services */
vector <global_service> ServicesTable;


/* callback handlers */
void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
/* module ending handler */
void ncrack_module_end(nsock_pool nsp, void *mydata);

/* schedule additional connections */
static int ncrack_probes(nsock_pool nsp, ServiceGroup *SG);
/* ncrack initialization */
static int ncrack(vector <Target *> &Targets, ServiceGroup *SG);
/* module name demultiplexor */
static void call_module(nsock_pool nsp, Connection* con);


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
  vector <global_service>::iterator vi;
  global_service temp;

  memset(&temp, 0, sizeof(temp));
  temp.timing.connection_limit = -1;
  temp.timing.auth_limit = -1;
  temp.timing.connection_delay = -1;
  temp.timing.retries = -1;

  fp = fopen(filename, "r");
  if (!fp) 
    fatal("%s: failed to open file %s for reading!\n", __func__, filename);

  while(fgets(line, sizeof(line), fp)) {
    if (*line == '\n' || *line == '#')
      continue;

    if (sscanf(line, "%127s %hu/%15s", servicename, &portno, proto) != 3)
      fatal("invalid ncrack-services file: %s\n", filename);

    temp.lookup.portno = portno;
    temp.lookup.proto = str2proto(proto);
    temp.lookup.name = strdup(servicename);

    for (vi = ServicesTable.begin(); vi != ServicesTable.end(); vi++) {
      if ((vi->lookup.portno == temp.lookup.portno) && (vi->lookup.proto == temp.lookup.proto)
          && !(strcmp(vi->lookup.name, temp.lookup.name))) {
        if (o.debugging)
          error("Port %d proto %s is duplicated in services file %s\n", 
              portno, proto, filename);
        continue;
      }
    }

    ServicesTable.push_back(temp);
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



static void
call_module(nsock_pool nsp, Connection *con)
{
        char *name = con->service->name;

        if (!strcmp(name, "ftp"))
                ncrack_ftp(nsp, con);
        else if (!strcmp(name, "ssh"))
                ;//ncrack_ssh(nsp, nsi, con);
        else if (!strcmp(name, "telnet"))
                ;//ncrack_telnet(nsp, nsi, con);
        else
                fatal("Invalid service module: %s\n", name);
}



int main(int argc, char **argv)
{
  ts_spec spec;

  FILE *inputfd = NULL;
  unsigned long l;

  char *host_spec = NULL;
  Target *currenths = NULL;
  vector <Target *> Targets;  /* targets to be ncracked */
  vector <Target *>::iterator Tvi;

  ServiceGroup *SG;           /* all services to be cracked */
  list <Service *>::iterator li;

  vector <Service *>Services; /* temporary services vector */
  vector <Service *>::iterator Svi; /* iterator for services vector */
  Service *service;

  vector <service_lookup *> services_cmd;
  vector <service_lookup *>::iterator SCvi;

  char  *glob_options;  /* -g option */
  timing_options timing;



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
    {"timing", required_argument, 0, 'T'},
    {"max_parallelism", required_argument, 0, 'M'},
    {"max-parallelism", required_argument, 0, 'M'},
    {"min_parallelism", required_argument, 0, 0},
    {"min-parallelism", required_argument, 0, 0},
    {"excludefile", required_argument, 0, 0},
    {"exclude", required_argument, 0, 0},
    {"iL", required_argument, 0, 'i'},
    {"host_timeout", required_argument, 0, 0},
    {"host-timeout", required_argument, 0, 0},
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
  while((arg = getopt_long_only(argc, argv, "d:g:h:i:m:p:s:T:vV", long_options, &option_index)) != EOF) {
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
          parse_services(optarg, services_cmd);
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
      case 'g':
        glob_options = strdup(optarg);
        o.global_options = true;
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
      case 'm':
        parse_module_options(optarg);
        break;
      case 'p':   /* services */
        parse_services(optarg, services_cmd); 
        break;
      case 's': /* only list hosts */
        if (*optarg == 'L')
          o.list_only = true;
        else {
          error("Illegal argument for option '-s' Did you mean -sL?\n");
          print_usage();
        }
        break;
      case 'T': /* timing template */
        if (*optarg == '0' || (strcasecmp(optarg, "Paranoid") == 0)) {
          o.timing_level = 0;
        } else if (*optarg == '1' || (strcasecmp(optarg, "Sneaky") == 0)) {
          o.timing_level = 1;
        } else if (*optarg == '2' || (strcasecmp(optarg, "Polite") == 0)) {
          o.timing_level = 2;
        } else if (*optarg == '3' || (strcasecmp(optarg, "Normal") == 0)) {
        } else if (*optarg == '4' || (strcasecmp(optarg, "Aggressive") == 0)) {
          o.timing_level = 4;
        } else if (*optarg == '5' || (strcasecmp(optarg, "Insane") == 0)) {
          o.timing_level = 5;
        } else {
          fatal("Unknown timing mode (-T argument).  Use either \"Paranoid\", \"Sneaky\", "
              "\"Polite\", \"Normal\", \"Aggressive\", \"Insane\" or a number from 0 "
              " (Paranoid) to 5 (Insane)");
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
  
  /* Prepare -T option (3 is default) */
  prepare_timing_template(&timing);

  now = time(NULL);
  tm = localtime(&now);
  if (strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M %Z", tm) <= 0)
    fatal("Unable to properly format time");
  printf("\nStarting %s %s ( %s ) at %s\n\n", NCRACK_NAME, NCRACK_VERSION, NCRACK_URL, tbuf);

  o.setaf(AF_INET);



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


  SG = new ServiceGroup();

  while ((host_spec = grab_next_host_spec(inputfd, argc, argv))) {

    /* preparse and separate host - service */
    spec = parse_services_target(host_spec);

    // printf("%s://%s:%s?%s\n", spec.service_name, spec.host_expr, spec.portno, spec.service_options);

    if (spec.service_name) {
      service = new Service();
      service->name = strdup(spec.service_name);
      Services.push_back(service);
    } else {
      for (SCvi = services_cmd.begin(); SCvi != services_cmd.end(); SCvi++) {
        service = new Service();
        service->name = (*SCvi)->name;
        service->portno = (*SCvi)->portno;
        service->proto = (*SCvi)->proto;
        Services.push_back(service);
      }
    }


    for (Svi = Services.begin(); Svi != Services.end(); Svi++) {
      /* first apply timing template */
      apply_timing_template(*Svi, &timing);
      /* then apply global options -g if they exist */
      if (o.global_options) 
        apply_host_options(*Svi, glob_options);
      /* then apply options from ServiceTable (-m option) */
      apply_service_options(*Svi);
    }

    /* finally, if they have been specified, apply options from host */
    if (spec.service_options)
      apply_host_options(Services[0], spec.service_options);
    if (spec.portno)
      Services[0]->portno = str2port(spec.portno);

    while ((currenths = nexthost(spec.host_expr, exclude_group))) {
      for (Tvi = Targets.begin(); Tvi != Targets.end(); Tvi++) {
        if (!(strcmp((*Tvi)->NameIP(), currenths->NameIP())))
          break;
        }
      if (Tvi == Targets.end())
        Targets.push_back(currenths);
      else 
        currenths = *Tvi;

      for (Svi = Services.begin(); Svi != Services.end(); Svi++) {
        service = new Service(**Svi);

        service->target = currenths;
        /* check for duplicates */
        for (li = SG->services_remaining.begin(); li != SG->services_remaining.end(); li++) {
          if (!strcmp((*li)->target->NameIP(), currenths->NameIP()) &&
              (!strcmp((*li)->name, service->name)) && ((*li)->portno == service->portno))
            fatal("Duplicate service %s for target %s !\n", service->name, currenths->NameIP());
        }
        SG->services_remaining.push_back(service);
        SG->total_services++;
      }
    }
    Services.clear();
    clean_spec(&spec);
  }

  if (o.list_only) {
    if (o.debugging > 3) {
      printf("\n=== Timing Template ===\n");
      printf("cl=%ld, al=%ld, cd=%ld, mr=%ld\n", timing.connection_limit,
          timing.auth_limit, timing.connection_delay, timing.retries);
      printf("\n=== ServicesTable ===\n");
      for (unsigned int i = 0; i < ServicesTable.size(); i++) {
        printf("%s:%hu cl=%ld, al=%ld, cd=%ld, mr=%ld\n", 
            ServicesTable[i].lookup.name,
            ServicesTable[i].lookup.portno,
            ServicesTable[i].timing.connection_limit,
            ServicesTable[i].timing.auth_limit,
            ServicesTable[i].timing.connection_delay,
            ServicesTable[i].timing.retries);
      }
    }
    printf("\n=== Targets ===\n");
    for (unsigned int i = 0; i < Targets.size(); i++) {
      printf("Host: %s", Targets[i]->NameIP());
      if (Targets[i]->targetname)
        printf(" ( %s ) ", Targets[i]->targetname);
      printf("\n");
      for (li = SG->services_remaining.begin(); li != SG->services_remaining.end(); li++) {
        if ((*li)->target == Targets[i])
          printf("  %s:%hu cl=%ld, al=%ld, cd=%ld, mr=%ld\n", 
              (*li)->name, (*li)->portno, (*li)->connection_limit,
              (*li)->auth_limit, (*li)->connection_delay, (*li)->retries);
      }
    }
  } else {
    if (!SG->total_services)
      fatal("No services specified!\n");

    SG->last_accessed = SG->services_remaining.end();
    /* Ncrack 'em all! */
    ncrack(Targets, SG);
  }

  /* Free all of the Targets */
  while(!Targets.empty()) {
    currenths = Targets.back();
    delete currenths;
    Targets.pop_back();
  }
  delete SG;


  printf("\nNcrack finished.\n");
  exit(EXIT_SUCCESS);
}


/* 
 * It handles module endings
 */
void
ncrack_module_end(nsock_pool nsp, void *mydata)
{
        Connection *con = (Connection *) mydata;
  Service *serv = con->service;
  nsock_iod nsi = con->niod;
        ServiceGroup *SG = (ServiceGroup *) nsp_getud(nsp);
        list <Connection *>::iterator li;

  for (li = serv->connections.begin(); li != serv->connections.end(); li++) {
    if ((*li)->niod == nsi)
      break;
  } 
  if (li == serv->connections.end()) /* this shouldn't happen */
    fatal("%s: invalid niod!\n", __func__);

  serv->connections.erase(li);
  SG->active_connections--;

        /* see if we can initiate some more connections */
        ncrack_probes(nsp, SG);  

}


void
ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
  nsock_iod nsi = nse_iod(nse);
  enum nse_status status = nse_status(nse);
  enum nse_type type = nse_type(nse);
        ServiceGroup *SG = (ServiceGroup *) nsp_getud(nsp);
        Connection *con = (Connection *) mydata;
  int nbytes;
        char *str;

        //assert(type == NSE_TYPE_READ);


        if (status == NSE_STATUS_SUCCESS) {

                str = nse_readbuf(nse, &nbytes);
                con->buf = (char *)safe_malloc(nbytes);
                con->bufsize = nbytes;
                memcpy(con->buf, str, nbytes);


                call_module(nsp, con);

        }

        /* see if we can initiate some more connections */
        ncrack_probes(nsp, SG);

        return;
}




void
ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
        nsock_iod nsi = nse_iod(nse);
        enum nse_status status = nse_status(nse);
        enum nse_type type = nse_type(nse);
        ServiceGroup *SG = (ServiceGroup *) nsp_getud(nsp);
        Connection *con = (Connection *) mydata;



        call_module(nsp, con);

        /* see if we can initiate some more connections */
        ncrack_probes(nsp, SG);

        return;
}







void
ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
        nsock_iod nsi = nse_iod(nse);
        enum nse_status status = nse_status(nse);
        enum nse_type type = nse_type(nse);
        ServiceGroup *SG = (ServiceGroup *) nsp_getud(nsp);
        Connection *con = (Connection *) mydata;

        assert(type == NSE_TYPE_CONNECT || type == NSE_TYPE_CONNECT_SSL);

        // if (svc->target->timedOut(nsock_gettimeofday())) {
        //end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
        if (status == NSE_STATUS_SUCCESS) {

#if HAVE_OPENSSL
                // TODO: handle ossl

#endif

                call_module(nsp, con);

        } else if (status == NSE_STATUS_TIMEOUT || status == NSE_STATUS_ERROR) {
                // This is not good.  The connect() really shouldn't generally
                // be timing out like that.  We'll mark this svc as incomplete
                // and move it to the finished bin.
                if (o.debugging)
                        error("Got nsock CONNECT response with status %s - aborting this service", nse_status2str(status));
                  ncrack_module_end(nsp, con);
        } else if (status == NSE_STATUS_KILL) {
                /* User probablby specified host_timeout and so the service scan is
                         shutting down */
                  ncrack_module_end(nsp, con);
                  //return;
        } else
                fatal("Unexpected nsock status (%d) returned for connection attempt", (int) status);


        /* see if we can initiate some more connections */
        ncrack_probes(nsp, SG);

        return;
}




static int
ncrack_probes(nsock_pool nsp, ServiceGroup *SG) {
        Service *serv;
        Connection *con;
        struct sockaddr_storage ss;
        size_t ss_len;
        list <Service *>::iterator li;


        if (SG->last_accessed == SG->services_remaining.end())
                li = SG->services_remaining.begin();
        else 
                li = SG->last_accessed;

        while (SG->active_connections < SG->ideal_parallelism
                        && SG->services_finished.size() != SG->total_services) {
                serv = *li;
                if (serv->target->timedOut(nsock_gettimeofday())) {
                        // end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, NULL);  TODO: HANDLE
                        continue;
                }


                /* Schedule 1 connection for this service */
                con = new Connection(serv);
                if ((con->niod = nsi_new(nsp, serv)) == NULL) {
                        fatal("Failed to allocate Nsock I/O descriptor in %s()", __func__);
                }
                serv->connections.push_back(con);

                serv->target->TargetSockAddr(&ss, &ss_len);
                if (serv->proto == IPPROTO_TCP)
                        nsock_connect_tcp(nsp, con->niod, ncrack_connect_handler, 
                                        DEFAULT_CONNECT_TIMEOUT, con,
                                        (struct sockaddr *)&ss, ss_len,
                                        serv->portno);
                else {
                        assert(serv->proto == IPPROTO_UDP);
                        nsock_connect_udp(nsp, con->niod, ncrack_connect_handler, 
                                        serv, (struct sockaddr *) &ss, ss_len,
                                        serv->portno);
                }

                SG->active_connections++;


                SG->last_accessed = li;
                if (++li == SG->services_remaining.end())
                        li = SG->services_remaining.begin();

                // pop / push etc

        }
        return 0;
}





static int
ncrack(vector <Target *> &Targets, ServiceGroup *SG)
{
        /* nsock variables */
        struct timeval now;
        enum nsock_loopstatus loopret;
        nsock_pool nsp;
        int tracelevel = 0;

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
