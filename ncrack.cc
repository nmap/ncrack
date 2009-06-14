#include "ncrack.h"
#include "NcrackOps.h"
#include "utils.h"
#include "services.h"
#include "targets.h"
#include "TargetGroup.h"
#include "ServiceGroup.h"
#include "nsock.h"
#include "global_structures.h"
#include "modules.h"
#include <time.h>
#include <vector>

#define DEFAULT_CONNECT_TIMEOUT 5000
#define DEFAULT_USERNAME_FILE "./username.lst"
#define DEFAULT_PASSWORD_FILE "./password.lst"

extern NcrackOps o;
using namespace std;

/* global lookup table for available services */
vector <global_service> ServicesTable;
/* global login and pass array */
vector <char *> UserArray;
vector <char *> PassArray;


/* callback handlers */
void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
void ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
/* module ending handler */
void ncrack_module_end(nsock_pool nsp, void *mydata);

/* schedule additional connections */
static int ncrack_probes(nsock_pool nsp, ServiceGroup *SG);
/* ncrack initialization */
static int ncrack(ServiceGroup *SG);
/* module name demultiplexor */
static void call_module(nsock_pool nsp, Connection* con);

static void load_login_file(const char *filename, int mode);
enum mode { USER, PASS };


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
      "  Can pass target specific services in <service>://target (standard) notation or\n"
      "  using -p which will be applied to all hosts in non-standard notation.\n"
      "  Service arguments can be specified to be host-specific, type of service-specific\n"
      "  (-m) or global (-g). Ex: ssh://10.0.0.10,al=10,cl=30 -m ssh:at=50 -g cd=3000\n"
      "  Ex2: ncrack -p ssh,ftp:3500,25 10.0.0.10 scanme.nmap.org\n"
      "  -p <service-list>: services will be applied to all non-standard notation hosts\n"
      "  -m <service>:<options>: options will be applied to all services of this type\n"
      "  -g <options>: options will be applied to every service globally\n"
      "  Available Options:\n"
      "   Timing:\n"
      "    cl (min connection limit): minimum number of concurrent parallel connections\n"
      "    CL (max connection limit): maximum number of concurrent parallel connections\n"
      "    at (authentication tries): authentication attempts per connection\n"
      "    cd (connection delay): delay between each connection initiation (in milliseconds)\n"
      "    cr (connection retries): caps number of service connection attempts\n"
      "TIMING AND PERFORMANCE:\n"
      "  Options which take <time> are in milliseconds, unless you append 's'\n"
      "  (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).\n"
      "  -T<0-5>: Set timing template (higher is faster)\n"
      "  --connection-limit <number>: threshold for total concurrent connections\n"
  //    "  --host-timeout <time>: Give up on target after this long\n"
      "AUTHENTICATION:\n"
      "  -U <filename>: username file\n"
      "  -P <filename>: password file\n"
      "  --passwords-first: Iterate password list for each username. Default is opposite.\n"
      "OUTPUT:\n"
      "  -v: Increase verbosity level (use twice or more for greater effect)\n"
      "  -d[level]: Set or increase debugging level (Up to 9 is meaningful)\n"
      "MISC:\n"
      "  -sL or --list: only list hosts and services\n"
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
  temp.timing.min_connection_limit = -1;
  temp.timing.max_connection_limit = -1;
  temp.timing.auth_tries = -1;
  temp.timing.connection_delay = -1;
  temp.timing.connection_retries = -1;

  fp = fopen(filename, "r");
  if (!fp) 
    fatal("%s: failed to open file %s for reading!\n", __func__, filename);

  while (fgets(line, sizeof(line), fp)) {
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
load_login_file(const char *filename, int mode)
{
  char line[1024];
  char *tmp;
  FILE *fd;
  vector <char *> *p = NULL;

  if (!strcmp(filename, "-"))
    fd = stdin;
  else {    
    fd = fopen(filename, "r");
    if (!fd) 
      fatal("Failed to open input file %s for reading\n", filename);
  }

  if (mode == USER)
    p = &UserArray;
  else if (mode == PASS)
    p = &PassArray;
  else 
    fatal("%s invalid mode specified!\n", __func__);

  while (fgets(line, sizeof(line), fd)) {
    if (*line == '\n')
      continue;
    tmp = Strndup(line, strlen(line) - 1);
    p->push_back(tmp);
  }
}



static void
call_module(nsock_pool nsp, Connection *con)
{
  char *name = con->service->name;

  /* initialize connection state variables */
  con->check_closed = false;
  con->auth_complete = false;

  if (!strcmp(name, "ftp"))
    ncrack_ftp(nsp, con);
  else if (!strcmp(name, "telnet"))
    ncrack_telnet(nsp, con);
  else if (!strcmp(name, "ssh"))
    ;//ncrack_ssh(nsp, nsi, con);
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

  char  *glob_options = NULL;  /* for -g option */
  timing_options timing; /* for -T option */

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
    {"excludefile", required_argument, 0, 0},
    {"exclude", required_argument, 0, 0},
    {"iL", required_argument, 0, 'i'},
    {"host_timeout", required_argument, 0, 0},
    {"host-timeout", required_argument, 0, 0},
    {"connection_limit", required_argument, 0, 0},
    {"connection-limit", required_argument, 0, 0},
    {"passwords_first", no_argument, 0, 0},
    {"passwords-first", no_argument, 0, 0},
    {0, 0, 0, 0}
  };

  if (argc < 2)
    print_usage();

  /* Initialize available services' lookup table */
  lookup_init("ncrack-services");


  /* Argument parsing */
  optind = 1;
  while((arg = getopt_long_only(argc, argv, "d:g:hi:U:P:m:p:s:T:vV", long_options,
          &option_index)) != EOF) {
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
        } else if (!optcmp(long_options[option_index].name, "connection-limit")) {
          o.connection_limit = atoi(optarg);
        } else if (!optcmp(long_options[option_index].name, "passwords-first")) {
          o.passwords_first = true;
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
      case 'U':
        load_login_file(optarg, USER);
        break;
      case 'P':
        load_login_file(optarg, PASS);
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
          o.timing_level = 3;
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

  if (UserArray.empty())
    load_login_file(DEFAULT_USERNAME_FILE, USER);
  if (PassArray.empty())
    load_login_file(DEFAULT_PASSWORD_FILE, PASS);

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
  SG->connection_limit = o.connection_limit;

  while ((host_spec = grab_next_host_spec(inputfd, argc, argv))) {

    /* preparse and separate host - service */
    spec = parse_services_target(host_spec);

    // printf("%s://%s:%s?%s\n", spec.service_name, spec.host_expr, spec.portno, spec.service_options);

    if (spec.service_name) {
      service = new Service();
      service->name = strdup(spec.service_name);
      service->UserArray = &UserArray;
      service->PassArray = &PassArray;
      Services.push_back(service);
    } else {  /* -p option */
      for (SCvi = services_cmd.begin(); SCvi != services_cmd.end(); SCvi++) {
        service = new Service();
        service->name = (*SCvi)->name;
        service->portno = (*SCvi)->portno;
        service->proto = (*SCvi)->proto;
        service->UserArray = &UserArray;
        service->PassArray = &PassArray;
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
        for (li = SG->services_active.begin(); li != SG->services_active.end(); li++) {
          if (!strcmp((*li)->target->NameIP(), currenths->NameIP()) &&
              (!strcmp((*li)->name, service->name)) && ((*li)->portno == service->portno))
            fatal("Duplicate service %s for target %s !\n", service->name, currenths->NameIP());
        }
        SG->services_active.push_back(service);
        SG->total_services++;
      }
    }
    Services.clear();
    clean_spec(&spec);
  }

  if (o.list_only) {
    if (o.debugging > 3) {
      printf("\n=== Timing Template ===\n");
      printf("cl=%ld, CL=%ld, at=%ld, cd=%ld, cr=%ld\n", timing.min_connection_limit,
          timing.max_connection_limit, timing.auth_tries, timing.connection_delay,
          timing.connection_retries);
      printf("\n=== ServicesTable ===\n");
      for (unsigned int i = 0; i < ServicesTable.size(); i++) {
        printf("%s:%hu cl=%ld, CL=%ld, at=%ld, cd=%ld, cr=%ld\n", 
            ServicesTable[i].lookup.name,
            ServicesTable[i].lookup.portno,
            ServicesTable[i].timing.min_connection_limit,
            ServicesTable[i].timing.max_connection_limit,
            ServicesTable[i].timing.auth_tries,
            ServicesTable[i].timing.connection_delay,
            ServicesTable[i].timing.connection_retries);
      }
    }
    printf("\n=== Targets ===\n");
    for (unsigned int i = 0; i < Targets.size(); i++) {
      printf("Host: %s", Targets[i]->NameIP());
      if (Targets[i]->targetname)
        printf(" ( %s ) ", Targets[i]->targetname);
      printf("\n");
      for (li = SG->services_active.begin(); li != SG->services_active.end(); li++) {
        if ((*li)->target == Targets[i]) 
          printf("  %s:%hu cl=%ld, CL=%ld, at=%ld, cd=%ld, cr=%ld\n", 
              (*li)->name, (*li)->portno, (*li)->min_connection_limit,
              (*li)->max_connection_limit, (*li)->auth_tries, 
              (*li)->connection_delay, (*li)->connection_retries);
      }
    }
  } else {
    if (!SG->total_services)
      fatal("No services specified!\n");

    SG->last_accessed = SG->services_active.end();
    /* Ncrack 'em all! */
    ncrack(SG);
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
  struct timeval now;

  con->login_attempts++;
  con->auth_complete = true;
  serv->total_attempts++;
  serv->finished_attempts++;
  
  /* 
   * If that was our first connection and successfully made it up to the point of
   * completing an authentication, then calculate initial ideal_parallelism (which
   * was 1 previously) based on the box of min_connection_limit, max_connection_limit
   * and a default desired parallelism for each timing template.
   */
  if (serv->just_started == true) {
    long desired_par = 1;
    if (o.timing_level == 0)
      desired_par = 1;
    else if (o.timing_level == 1)
      desired_par = 1;
    else if (o.timing_level == 2)
      desired_par = 4;
    else if (o.timing_level == 3)
      desired_par = 10;
    else if (o.timing_level == 4)
      desired_par = 30;
    else if (o.timing_level == 5)
      desired_par = 50;

    serv->ideal_parallelism = box(serv->min_connection_limit, serv->max_connection_limit, desired_par);
    serv->just_started = false;
  }

  serv->auth_rate_meter.update(1, NULL);

  gettimeofday(&now, NULL);
  if (TIMEVAL_MSEC_SUBTRACT(now, serv->last_auth_rate.time) >= 500) {
    double current_rate = serv->auth_rate_meter.getCurrentRate();
    printf("%s last: %.2f  current %.2f parallelism %ld\n", serv->HostInfo(),
        serv->last_auth_rate.rate, current_rate, serv->ideal_parallelism);
    if (current_rate < serv->last_auth_rate.rate + 3) {
      //serv->connection_limit++;
      //printf("%s Increasing connection limit %ld\n", serv->HostInfo(), serv->connection_limit);
    }
    serv->last_auth_rate.time = now;
    serv->last_auth_rate.rate = current_rate;
 }


  /* If login pair was extracted from pool, permanently remove it from it. */
  if (con->from_pool && !serv->isMirrorPoolEmpty()) {
    serv->RemoveFromPool(con->user, con->pass);
    con->from_pool = false;
  }

  /* 
   * Since there is no portable way to check if the peer has closed the
   * connection or not (hence we are in CLOSE_WAIT state), issue a read call
   * with a very small timeout and check if nsock timed out (host hasn't closed
   * connection yet) or returned an EOF (host sent FIN making active close)
   */
  con->check_closed = true;
  nsock_read(nsp, nsi, ncrack_read_handler, 10, con);
  return;
}


void
ncrack_connection_end(nsock_pool nsp, void *mydata)
{
  Connection *con = (Connection *) mydata;
  Service *serv = con->service;
  nsock_iod nsi = con->niod;
  ServiceGroup *SG = (ServiceGroup *) nsp_getud(nsp);
  list <Connection *>::iterator li;

  if (!con->auth_complete) {
    serv->total_attempts++;
    printf("%s Dropping connection limit due to connection error!\n", serv->HostInfo());
    //if (serv->connection_limit - 5 >= 1)
    //  serv->connection_limit -= 5;
  }

  for (li = serv->connections.begin(); li != serv->connections.end(); li++) {
    if ((*li)->niod == nsi)
      break;
  } 
  if (li == serv->connections.end()) /* this shouldn't happen */
    fatal("%s: invalid niod!\n", __func__);

  SG->auth_rate_meter.update(con->login_attempts, NULL);

  nsi_delete(nsi, NSOCK_PENDING_SILENT);
  serv->connections.erase(li);

  serv->active_connections--;
  SG->active_connections--;


  /*
   * Check if we had previously surpassed imposed connection limit so that
   * we remove service from 'services_full' list to 'services_active' list.
   */
  if (serv->list_full && serv->active_connections < serv->ideal_parallelism)
    SG->MoveServiceToList(serv, &SG->services_active);


  /*
   * If service was on 'services_finishing' (username list finished, pool empty
   * but still pending connections) then:
   * - if new pairs arrived into pool, move to 'services_active' again
   * - else if no more connections are pending, move to 'services_finished'
   */
  if (serv->list_finishing) {
    if (!serv->isMirrorPoolEmpty())
      SG->MoveServiceToList(serv, &SG->services_active);
    else if (!serv->active_connections)
      SG->MoveServiceToList(serv, &SG->services_finished);
  }

  printf("%s Attempts: total %d completed %d --- rate %.2f \n", 
      serv->HostInfo(), serv->total_attempts, serv->finished_attempts,
      SG->auth_rate_meter.getCurrentRate());

  /* Check if service finished for good. */
  if (serv->loginlist_fini && serv->isMirrorPoolEmpty() && !serv->active_connections && !serv->list_finished)
    SG->MoveServiceToList(serv, &SG->services_finished);

  /* see if we can initiate some more connections */
  ncrack_probes(nsp, SG);
}


void
ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
  enum nse_status status = nse_status(nse);
  enum nse_type type = nse_type(nse);
  ServiceGroup *SG = (ServiceGroup *) nsp_getud(nsp);
  Connection *con = (Connection *) mydata;
  Service *serv = con->service;
  int pair_ret;
  int nbytes;
  char *str;
  const char *hostinfo = serv->HostInfo();

  assert(type == NSE_TYPE_READ);

  if (status == NSE_STATUS_SUCCESS) {

    str = nse_readbuf(nse, &nbytes);
    /* don't forget to free possibly previous allocated memory */
    if (con->buf) {
      free(con->buf);
      con->buf = NULL;
    }
    con->buf = Strndup(str, nbytes);  /* warning: we may need memcpy instead of strncpy */
    con->bufsize = nbytes;
    call_module(nsp, con);

  } else if (status == NSE_STATUS_TIMEOUT) {

    /* First check if we are just making sure the host hasn't closed
     * on us, and so we are still in ESTABLISHED state, instead of
     * CLOSE_WAIT - we do this by issuing a read call with a tiny timeout.
     * If we are still connected, then we can go on checking if we can make
     * another authentication attempt in this particular connection.
     */
    if (con->check_closed) {
      /* Make another authentication attempt only if:
       * 1. we hanen't surpassed the authentication limit per connection for this service
       * 2. we still have enough login pairs from the pool
       */
      if (con->login_attempts < serv->auth_tries
          && (pair_ret = serv->NextPair(&con->user, &con->pass)) != -1) {
        if (pair_ret == 1)
          con->from_pool = true;
        call_module(nsp, con);
      } else
        ncrack_connection_end(nsp, con);
    /* This is a normal timeout */
    } else {
      if (o.debugging)
        printf("%s read: nse_status_timeout\n", hostinfo);
      serv->AppendToPool(con->user, con->pass);
      if (serv->list_stalled)
        SG->MoveServiceToList(serv, &SG->services_active);
      ncrack_connection_end(nsp, con);  // should we always close connection or try to wait?
    }

  } else if (status == NSE_STATUS_EOF) {

    if (!con->auth_complete) {
      printf("%s Peer closed on us in the middle of authentication!\n", hostinfo);
      serv->AppendToPool(con->user, con->pass);
      if (serv->list_stalled)
        SG->MoveServiceToList(serv, &SG->services_active);
    }
    if (o.debugging > 5)
      printf("%s Connection closed by peer\n", hostinfo);
    ncrack_connection_end(nsp, con);

  }  else if (status == NSE_STATUS_ERROR) {

    if (o.debugging)
      printf("read: nse_status_error\n");
    serv->AppendToPool(con->user, con->pass);
    if (serv->list_stalled)
      SG->MoveServiceToList(serv, &SG->services_active);
    ncrack_connection_end(nsp, con);

  } else if (status == NSE_STATUS_KILL) {
    printf("read: nse_status_kill\n");

  } else
    fatal("Unexpected status (%d) in NSE_TYPE_READ callback.", (int) status);

  return;
}




void
ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
  enum nse_status status = nse_status(nse);
  Connection *con = (Connection *) mydata;
  int err;

  if (status == NSE_STATUS_SUCCESS)
    call_module(nsp, con);
  else if (status == NSE_STATUS_KILL)
    printf("write: nse_status_kill\n");
  else if (status == NSE_STATUS_ERROR) {
    err = nse_errorcode(nse);
    printf("Got nsock WRITE error #%d (%s)", err, strerror(err));
  } else
    printf("Got nsock WRITE response with status %s\n", nse_status2str(status));

  return;
}





void
ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
  enum nse_status status = nse_status(nse);
  enum nse_type type = nse_type(nse);
  ServiceGroup *SG = (ServiceGroup *) nsp_getud(nsp);
  Connection *con = (Connection *) mydata;
  Service *serv = con->service;
  int err;

  assert(type == NSE_TYPE_CONNECT || type == NSE_TYPE_CONNECT_SSL);

  // if (svc->target->timedOut(nsock_gettimeofday())) {
  //end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
  if (status == NSE_STATUS_SUCCESS) {

#if HAVE_OPENSSL
    // TODO: handle ossl

#endif
    call_module(nsp, con);

  } else if (status == NSE_STATUS_TIMEOUT || status == NSE_STATUS_ERROR) {

    /* This is not good. connect() really shouldn't generally be timing out. */
    if (o.debugging) {
      err = nse_errorcode(nse);
      printf("%s got nsock CONNECT response with status %s error: %s\n", serv->HostInfo(),
          nse_status2str(status), strerror(err));
    }
    serv->failed_connections++;
    serv->AppendToPool(con->user, con->pass);
    /* Failure of connecting on first attempt means we should probably drop
     * the service for good. */
    if (serv->just_started) {
      // serv->finish_reason = 
      SG->MoveServiceToList(serv, &SG->services_finished);
    }
    if (serv->list_stalled)
      SG->MoveServiceToList(serv, &SG->services_active);
    ncrack_connection_end(nsp, con);

  } else if (status == NSE_STATUS_KILL) {

    printf("connect: nse_status_kill\n");
    serv->AppendToPool(con->user, con->pass);
    if (serv->list_stalled)
      SG->MoveServiceToList(serv, &SG->services_active);
    ncrack_connection_end(nsp, con);

  } else
    fatal("Unexpected nsock status (%d) returned for connection attempt", (int) status);

  return;
}




static int
ncrack_probes(nsock_pool nsp, ServiceGroup *SG) {
  Service *serv;
  Connection *con;
  struct sockaddr_storage ss;
  size_t ss_len;
  list <Service *>::iterator li;
  struct timeval now;
  int pair_ret;
  char *login, *pass;
  const char *hostinfo;


  /* First check for every service if connection_delay time has already
   * passed since its last connection and move them back to 'services_active'
   * list if it has.
   */
  gettimeofday(&now, NULL);
  for (li = SG->services_wait.begin(); li != SG->services_wait.end(); li++) {
    if (TIMEVAL_MSEC_SUBTRACT(now, (*li)->last) >= (*li)->connection_delay) {
      li = SG->MoveServiceToList(*li, &SG->services_active);
    }
  }

  if (SG->last_accessed == SG->services_active.end()) 
    li = SG->services_active.begin();
  else 
    li = SG->last_accessed++;

  while (SG->active_connections < SG->connection_limit
      && SG->services_finished.size() != SG->total_services
      && SG->services_active.size() != 0) {

    serv = *li;
    hostinfo = serv->HostInfo();

    //if (serv->target->timedOut(nsock_gettimeofday())) {
    // end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, NULL);  TODO: HANDLE
    //  goto next;
    // }

    /*
     * If the service's last connection was earlier than 'connection_delay'
     * milliseconds ago, then temporarily move service to 'services_wait' list
     */
    gettimeofday(&now, NULL);
    if (TIMEVAL_MSEC_SUBTRACT(now, serv->last) < serv->connection_delay) {
      li = SG->MoveServiceToList(serv, &SG->services_wait);
      goto next;
    }

    /* If the service's active connections surpass its imposed connection limit
     * then don't initiate any more connections for it and also move service in
     * the services_full list so that it won't be reaccessed in this loop.
     */
    if (serv->active_connections >= serv->ideal_parallelism) {
      li = SG->MoveServiceToList(serv, &SG->services_full);
      goto next;
    }


    /* 
     * To mark a service as completely finished, first make sure:
     * a) that the username list has finished being iterated through once
     * b) that the mirror pair pool, which holds temporary login pairs which
     *    are currently being used, is empty
     * c) that no pending connections are left
     * d) that the service hasn't already finished 
     */
    if (serv->loginlist_fini && serv->isMirrorPoolEmpty() && !serv->list_finished) {
      if (!serv->active_connections) {
        li = SG->MoveServiceToList(serv, &SG->services_finished);
        goto next;
      } else {
        li = SG->MoveServiceToList(serv, &SG->services_finishing);
        goto next;
      }
    }

    /* 
     * If the username list iteration has finished, then don't initiate another
     * connection until our pair_pool has at least one element to grab another
     * pair from.
     */
    if (serv->loginlist_fini && serv->isPoolEmpty() && !serv->isMirrorPoolEmpty()) {
      li = SG->MoveServiceToList(serv, &SG->services_stalled);
      goto next;
    }

    if ((pair_ret = serv->NextPair(&login, &pass)) == -1) {
      goto next;
    }

    if (o.debugging > 4)
      printf("%s Initiating new Connection\n", hostinfo);

    /* Schedule 1 connection for this service */
    con = new Connection(serv);

    if (pair_ret == 1)
      con->from_pool = true;
    con->user = login;
    con->pass = pass;

    if ((con->niod = nsi_new(nsp, serv)) == NULL) {
      fatal("Failed to allocate Nsock I/O descriptor in %s()", __func__);
    }
    gettimeofday(&now, NULL);
    serv->last = now;
    serv->connections.push_back(con);
    serv->active_connections++;
    SG->active_connections++;

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

next:

    SG->last_accessed = li;
    if (++li == SG->services_active.end()) 
      li = SG->services_active.begin();

  }
  return 0;
}





static int
ncrack(ServiceGroup *SG)
{
  /* nsock variables */
  struct timeval now;
  enum nsock_loopstatus loopret;
  list <Service *>::iterator li;
  nsock_pool nsp;
  int tracelevel = 0;
  int err;

  /* create nsock p00l */
  if (!(nsp = nsp_new(SG))) 
    fatal("Can't create nsock pool.\n");

  gettimeofday(&now, NULL);
  nsp_settrace(nsp, tracelevel, &now);


  SG->MinDelay();
  /* initiate all authentication rate meters */
  SG->auth_rate_meter.start();
  for (li = SG->services_active.begin(); li != SG->services_active.end(); li++)
    (*li)->auth_rate_meter.start();

  ncrack_probes(nsp, SG);

  /* nsock loop */
  do {
    loopret = nsock_loop(nsp, (int) SG->min_connection_delay);
    if (loopret == NSOCK_LOOP_ERROR) {
      err = nsp_geterrorcode(nsp);
      fatal("Unexpected nsock_loop error. Error code %d (%s)\n", err, strerror(err));
    }
    ncrack_probes(nsp, SG);

  } while (loopret == NSOCK_LOOP_TIMEOUT);

  if (o.debugging > 4)
    printf("nsock_loop returned %d\n", loopret);

  return 0;
}
