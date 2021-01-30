
/***************************************************************************
 * ncrack.cc -- ncrack's core engine along with all nsock callback         *
 * handlers reside in here. Simple options' (not host or service-options   *
 * specification handling) parsing also happens in main() here.            *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2019 Insecure.Com LLC ("The Nmap  *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed Nmap technology into proprietary      *
 * software, we sell alternative licenses (contact sales@nmap.com).        *
 * Dozens of software vendors already license Nmap technology such as      *
 * host discovery, port scanning, OS detection, version detection, and     *
 * the Nmap Scripting Engine.                                              *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, the Nmap Project grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * The Nmap Project has permission to redistribute Npcap, a packet         *
 * capturing driver and library for the Microsoft Windows platform.        *
 * Npcap is a separate work with it's own license rather than this Nmap    *
 * license.  Since the Npcap license does not permit redistribution        *
 * without special permission, our Nmap Windows binary packages which      *
 * contain Npcap may not be redistributed without special permission.      *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, we are happy to help.  As mentioned above, we also *
 * offer an alternative license to integrate Nmap into proprietary         *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing support and updates.  They also fund the continued         *
 * development of Nmap.  Please email sales@nmap.com for further           *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify            *
 * otherwise) that you are offering the Nmap Project the unlimited,        *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because     *
 * the inability to relicense code has caused devastating problems for     *
 * other Free Software projects (such as KDE and NASM).  We also           *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/


#include "ncrack.h"
#include "NcrackOps.h"
#include "utils.h"
#include "services.h"
#include "targets.h"
#include "TargetGroup.h"
#include "ServiceGroup.h"
#include "nsock.h"
#include "global_structures.h"
#include "NcrackOutputTable.h"
#include "modules.h"
#include "ncrack_error.h"
#include "output.h"
#include "ncrack_tty.h"
#include "ncrack_input.h"
#include "ncrack_resume.h"
#include "xml.h"
#include <time.h>
#include <vector>

#if HAVE_SIGNAL
  #include <signal.h>
#endif

#if HAVE_OPENSSL
  #include <openssl/ssl.h>
#endif

#ifdef WIN32
  #include "winfix.h"
#endif

#define DEFAULT_CONNECT_TIMEOUT 5000
/* includes connect() + ssl negotiation */
#define DEFAULT_CONNECT_SSL_TIMEOUT 8000  
#define DEFAULT_USERNAME_FILE "default.usr"
#define DEFAULT_PASSWORD_FILE "default.pwd"

/* (in milliseconds) every such interval we poll for interactive user input */
#define KEYPRESSED_INTERVAL 500 

/* (in milliseconds) every such interval check for pending signals */
#define SIGNAL_CHECK_INTERVAL 1000

#define SERVICE_TIMEDOUT "Service timed-out as specified by user option."

extern NcrackOps o;
using namespace std;

/* global lookup table for available services */
vector <global_service> ServicesTable;
/* global login and pass array */
vector <char *> UserArray;
vector <char *> PassArray;
struct tm local_time;

/* schedule additional connections */
static void ncrack_probes(nsock_pool nsp, ServiceGroup *SG);
/* ncrack initialization */
static int ncrack(ServiceGroup *SG);
/* Poll for interactive user input every time this timer is called. */
static void status_timer_handler(nsock_pool nsp, nsock_event nse,
    void *mydata);
static void signal_timer_handler(nsock_pool nsp, nsock_event nse,
    void *mydata);

/* module name demultiplexor */
static void call_module(nsock_pool nsp, Connection* con);

static void parse_login_list(char *const arg, int mode);
static void load_login_file(const char *filename, int mode);
enum mode { USER, PASS };


static void print_usage(void);
static void lookup_init(const char *const filename);
static int file_readable(const char *pathname);
static int ncrack_fetchfile(char *filename_returned, int bufferlen,
  const char *file, int useroption = 0);
static char *grab_next_host_spec(FILE *inputfd, int argc, char **argv);
static void startTimeOutClocks(ServiceGroup *SG);
static void sigcatch(int signo);
static void sigcheck(ServiceGroup *SG);
static int ncrack_main(int argc, char **argv);


static void
print_usage(void)
{
  log_write(LOG_STDOUT, "%s %s ( %s )\n"
      "Usage: ncrack [Options] {target and service specification}\n"
      "TARGET SPECIFICATION:\n"
      "  Can pass hostnames, IP addresses, networks, etc.\n"
      "  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; "
         "10.0.0-255.1-254\n"
      "  -iX <inputfilename>: Input from Nmap's -oX XML output format\n"
      "  -iN <inputfilename>: Input from Nmap's -oN Normal output format\n"
      "  -iL <inputfilename>: Input from list of hosts/networks\n"
      "  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks\n"
      "  --excludefile <exclude_file>: Exclude list from file\n"
      "SERVICE SPECIFICATION:\n"
      "  Can pass target specific services in <service>://target (standard) "
         "notation or\n"
      "  using -p which will be applied to all hosts in non-standard "
         "notation.\n"
      "  Service arguments can be specified to be host-specific, type of "
         "service-specific\n"
      "  (-m) or global (-g). Ex: ssh://10.0.0.10,at=10,cl=30 -m ssh:at=50 "
         "-g cd=3000\n"
      "  Ex2: ncrack -p ssh,ftp:3500,25 10.0.0.10 scanme.nmap.org "
         "google.com:80,ssl\n"
      "  -p <service-list>: services will be applied to all non-standard "
         "notation hosts\n"
      "  -m <service>:<options>: options will be applied to all services "
         "of this type\n"
      "  -g <options>: options will be applied to every service globally\n"
      "  Misc options:\n"
      "    ssl: enable SSL over this service\n"
      "    path <name>: used in modules like HTTP ('=' needs escaping if "
           "used)\n"
      "    db <name>: used in modules like MongoDB to specify the database\n"
      "    domain <name>: used in modules like WinRM to specify the domain\n"
      "TIMING AND PERFORMANCE:\n"
      "  Options which take <time> are in seconds, unless you append 'ms'\n"
      "  (miliseconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m)."
      "\n"
      "  Service-specific options:\n"
      "    cl (min connection limit): minimum number of concurrent parallel "
           "connections\n"
      "    CL (max connection limit): maximum number of concurrent parallel "
           "connections\n"
      "    at (authentication tries): authentication attempts per connection\n"
      "    cd (connection delay): delay <time> between each connection "
           "initiation\n"
      "    cr (connection retries): caps number of service connection "
           "attempts\n"
      "    to (time-out): maximum cracking <time> for service, regardless "
           "of success so far\n"
      "  -T<0-5>: Set timing template (higher is faster)\n"
      "  --connection-limit <number>: threshold for total concurrent "
        "connections\n"
      "  --stealthy-linear: try credentials using only one connection against "
        "each specified host \n    until you hit the same host again. "
        "Overrides all other timing options.\n"
      "AUTHENTICATION:\n"
      "  -U <filename>: username file\n"
      "  -P <filename>: password file\n"
      "  --user <username_list>: comma-separated username list\n"
      "  --pass <password_list>: comma-separated password list\n"
      "  --passwords-first: Iterate password list for each username. "
        "Default is opposite.\n"
      "  --pairwise: Choose usernames and passwords in pairs.\n"
      "OUTPUT:\n"
      "  -oN/-oX <file>: Output scan in normal and XML format, respectively, "
         "to the given filename.\n"
      "  -oA <basename>: Output in the two major formats at once\n"
      "  -v: Increase verbosity level (use twice or more for greater effect)\n"
      "  -d[level]: Set or increase debugging level (Up to 10 is meaningful)\n"
      "  --nsock-trace <level>: Set nsock trace level (Valid range: 0 - 10)\n"
      "  --log-errors: Log errors/warnings to the normal-format output file\n"
      "  --append-output: Append to rather than clobber specified output "
         "files\n"
      "MISC:\n"
      "  --resume <file>: Continue previously saved session\n"
      "  --save <file>: Save restoration file with specific filename\n"
      "  -f: quit cracking service after one found credential\n"
      "  -6: Enable IPv6 cracking\n"
      "  -sL or --list: only list hosts and services\n"
      "  --datadir <dirname>: Specify custom Ncrack data file location\n"
      "  --proxy <type://proxy:port>: Make connections via socks4, 4a, http.\n"
      "  -V: Print version number\n"
      "  -h: Print this help summary page.\n"
      "MODULES:\n"
      "  SSH, RDP, FTP, Telnet, HTTP(S), Wordpress, POP3(S), IMAP, CVS, SMB, VNC, SIP, Redis, "
      "PostgreSQL, MQTT, MySQL, MSSQL, MongoDB, Cassandra, WinRM, OWA, DICOM\n"
      "EXAMPLES:\n"
      "  ncrack -v --user root localhost:22\n"
      "  ncrack -v -T5 https://192.168.0.1\n"
      "  ncrack -v -iX ~/nmap.xml -g CL=5,to=1h\n"
      "SEE THE MAN PAGE (http://nmap.org/ncrack/man.html) FOR MORE OPTIONS "
      "AND EXAMPLES\n",
      NCRACK_NAME, NCRACK_VERSION, NCRACK_URL);
  exit(EXIT_FAILURE);
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
  temp.timing.timeout = -1;

  fp = fopen(filename, "r");
  if (!fp) 
    fatal("%s: failed to open file %s for reading!", __func__, filename);

  while (fgets(line, sizeof(line), fp)) {
    if (*line == '\n' || *line == '#')
      continue;

    temp.misc.ssl = false;
    temp.misc.db = NULL;
    temp.misc.domain = NULL;

    if (sscanf(line, "%127s %hu/%15s", servicename, &portno, proto) != 3)
      fatal("invalid ncrack-services file: %s", filename);

    temp.lookup.portno = portno;
    temp.lookup.proto = str2proto(proto);
    temp.lookup.name = strdup(servicename);
    /* 
     * When more ssl-services are going to be added, this will probably
     * need a more generic scheme
     */
    if (!strncmp(servicename, "https", sizeof("https"))
      || !strncmp(servicename, "pop3s", sizeof("pop3s"))
      || !strncmp(servicename, "owa", sizeof("owa"))
      || !strncmp(servicename, "wordpress-tls", sizeof("wordpress-tls")) 
      || !strncmp(servicename, "wp-tls", sizeof("wp-tls"))
      || !strncmp(servicename, "webform-tls", sizeof("webform-tls")) 
      || !strncmp(servicename, "web-tls", sizeof("web-tls"))) 
      temp.misc.ssl = true;

    if (!strncmp(servicename, "mongodb", sizeof("mongodb")))
        temp.misc.db = Strndup("admin", sizeof("admin"));

    if (!strncmp(servicename, "winrm", sizeof("winrm")))
        temp.misc.domain = Strndup("Workstation", sizeof("Workstation"));

    for (vi = ServicesTable.begin(); vi != ServicesTable.end(); vi++) {
      if ((vi->lookup.portno == temp.lookup.portno) 
          && (vi->lookup.proto == temp.lookup.proto)
          && !(strcmp(vi->lookup.name, temp.lookup.name))) {
        if (o.debugging)
          error("Port %d proto %s is duplicated in services file %s", 
              portno, proto, filename);
        continue;
      }
    }

    ServicesTable.push_back(temp);
  }

  fclose(fp);
}


/* Returns one if the file pathname given exists, is not a directory and
 * is readable by the executing process.  Returns two if it is readable
 * and is a directory.  Otherwise returns 0.
 */
static int
file_readable(const char *pathname) {
  char *pathname_buf = strdup(pathname);
  int status = 0;

#ifdef WIN32
  /* stat on windows only works for "dir_name" not for "dir_name/"
   * or "dir_name\\"
   */
  int pathname_len = strlen(pathname_buf);
  char last_char = pathname_buf[pathname_len - 1];

  if( last_char == '/'
    || last_char == '\\')
    pathname_buf[pathname_len - 1] = '\0';

#endif

  struct stat st;

  if (stat(pathname_buf, &st) == -1)
    status = 0;
  else if (access(pathname_buf, R_OK) != -1)
    status = S_ISDIR(st.st_mode) ? 2 : 1;

  free(pathname_buf);
  return status;
}

/*
 * useroption should be 1 if either -U or -P has been specified.
 * by default it is 0
 */
int
ncrack_fetchfile(char *filename_returned, int bufferlen, const char *file,
    int useroption) {
  char *dirptr;
  int res;
  int foundsomething = 0;
  struct passwd *pw;
  static int warningcount = 0;
  char dot_buffer[512];

  /* -U or -P has been specified */
  if (useroption) {
    res = Snprintf(filename_returned, bufferlen, "%s", file);
    if (res > 0 && res < bufferlen) {
      foundsomething = file_readable(filename_returned);
    }
  }


  /* First, check the map of requested data file names. If there's an entry for
     file, use it and return.
     Otherwise, we try [--datadir]/file, then $NCRACKDIR/file
     next we try ~user/.ncrack/file
     then we try NCRACKDATADIR/file <--NCRACKDATADIR 
     finally we try ./file

     -- or on Windows --

     --datadir -> $NCRACKDIR -> ncrack.exe directory -> NCRACKDATADIR -> .
  */

  if (o.datadir && !foundsomething) {
    res = Snprintf(filename_returned, bufferlen, "%s/%s", o.datadir, file);
    if (res > 0 && res < bufferlen) {
      foundsomething = file_readable(filename_returned);
    }
  }

  if (!foundsomething && (dirptr = getenv("NCRACKDIR"))) {
    res = Snprintf(filename_returned, bufferlen, "%s/%s", dirptr, file);
    if (res > 0 && res < bufferlen) {
      foundsomething = file_readable(filename_returned);
    }
  }

#ifndef WIN32
  if (!foundsomething) {
    pw = getpwuid(getuid());
    if (pw) {
      res = Snprintf(filename_returned, bufferlen, "%s/.ncrack/%s",
          pw->pw_dir, file);
      if (res > 0 && res < bufferlen) {
        foundsomething = file_readable(filename_returned);
      }
    }
    if (!foundsomething && getuid() != geteuid()) {
      pw = getpwuid(geteuid());
      if (pw) {
        res = Snprintf(filename_returned, bufferlen, "%s/.ncrack/%s",
            pw->pw_dir, file);
        if (res > 0 && res < bufferlen) {
          foundsomething = file_readable(filename_returned);
        }
      }
    }
  }
#else
  if (!foundsomething) { /* Try the Ncrack directory */
    char fnbuf[MAX_PATH];
    int i;
    res = GetModuleFileName(GetModuleHandle(0), fnbuf, 1024);
    if(!res) fatal("GetModuleFileName failed (!)\n");

    /*  Strip it */
    for(i = res - 1; i >= 0 && fnbuf[i] != '/' && fnbuf[i] != '\\'; i--);
    if(i >= 0) /* we found it */
      fnbuf[i] = 0;
    res = Snprintf(filename_returned, bufferlen, "%s\\%s", fnbuf, file);
    if(res > 0 && res < bufferlen)
      foundsomething = file_readable(filename_returned);
    
    /* Now try under 'lists' for the installed directory */
    if (!foundsomething) {
    res = Snprintf(filename_returned, bufferlen, "%s\\lists\\%s", fnbuf, file);
    if(res > 0 && res < bufferlen)
      foundsomething = file_readable(filename_returned);
    }
  }
#endif

  if (!foundsomething) {
    res = Snprintf(filename_returned, bufferlen, "%s/%s", NCRACKDATADIR, file);
    if (res > 0 && res < bufferlen) {
      foundsomething = file_readable(filename_returned);
    }
  }

  if (foundsomething && (*filename_returned != '.') && !useroption) {    
    res = Snprintf(dot_buffer, sizeof(dot_buffer), "./%s", file);
    if (res > 0 && res < bufferlen) {
      if (file_readable(dot_buffer)) {
#ifdef WIN32
        if (warningcount++ < 1 && o.debugging)
#else
          if(warningcount++ < 1)
#endif
            error("Warning: File %s exists, but Ncrack is using %s for "
                "security and consistency reasons. Set NCRACKDIR=. to give "
                "priority to files in your local directory (may affect the "
                "other data files too).", dot_buffer, filename_returned);
      }
    }
  }

  if (!foundsomething) {
    res = Snprintf(filename_returned, bufferlen, "./%s", file);
    if (res > 0 && res < bufferlen)
      foundsomething = file_readable(filename_returned);
  }
    
  /* For username/password lists also search ./lists */
  if (!foundsomething) {
    res = Snprintf(filename_returned, bufferlen, "./lists/%s", file);
    if (res > 0 && res < bufferlen)
      foundsomething = file_readable(filename_returned);
  }

  if (!foundsomething) {
    Snprintf(filename_returned, bufferlen, "%s", file);
  }

  if (foundsomething && o.debugging > 1)
    log_write(LOG_PLAIN, "Fetchfile found %s\n", filename_returned);

  return foundsomething;

}

/* 
 * The only thing that a safe and generic signal handler should do, is to set a
 * flag that will be later checked by the main program. Ncrack will
 * periodically check this variable, and take appropriate action to exit
 * cleanly and also possibly save the current state into a file that can be
 * used later with --resume.
 */
static void
sigcatch(int signo)
{
  o.saved_signal = signo;
  return;
}

static void
sigcheck(ServiceGroup *SG)
{
  if (o.saved_signal == -1)
    return;

  fflush(stdout);
  switch (o.saved_signal) {
    case SIGINT:
      error("caught SIGINT signal, cleaning up");
      break;

#ifdef SIGTERM
    case SIGTERM:
      error("caught SIGTERM signal, cleaning up");
      break;
#endif

#ifdef SIGHUP
    case SIGHUP:
      error("caught SIGHUP signal, cleaning up");
      break;
#endif

#ifdef SIGBUS
    case SIGBUS:
      error("caught SIGBUS signal, cleaning up");
      break;
#endif

    default:
      error("caught signal %d, cleaning up", o.saved_signal);
      break;
  }

  log_close(LOG_NORMAL);
  /* Now try and save available information into a file that might be later
   * recalled with --resume.
   */
  ncrack_save(SG);

  exit(1);
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
    if (o.nmap_input_xml) {
      if (xml_input(inputfd, host_spec) < 0)
        return NULL;
    } else if (o.nmap_input_normal) {
      if (normal_input(inputfd, host_spec) < 0)
        return NULL;
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
  }
  if (!*host_spec) 
    return NULL;
  return host_spec;
}


/* 
 * Parses the username and password list that has been specified from the
 * command line through the --user and --pass options. The argument must be a
 * comma separated list of words for each case.
 */
static void
parse_login_list(char *const arg, int mode)
{
  vector <char *> *p = NULL;
  size_t i, j, arg_len;
  char *word;

  if (mode == USER)
    p = &UserArray;
  else if (mode == PASS)
    p = &PassArray;
  else 
    fatal("%s invalid mode specified!", __func__);

  arg_len = strlen(arg);
  j = i = 0;
  while (i < arg_len) {
    if (arg[i] == ',') {
      word = Strndup(&arg[j], i - j);
      p->push_back(word);
      j = i + 1;
    }

    i++;
 }

  /* In case, user just typed --user "," or --pass "," don't add two blank
   * passwords as there is no point in that.
   */
  if (arg[0] == ',' && arg_len == 1)
    return;

  word = Strndup(&arg[j], i - j);
  p->push_back(word);

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
      fatal("Failed to open input file %s for reading!", filename);
  }

  if (mode == USER)
    p = &UserArray;
  else if (mode == PASS)
    p = &PassArray;
  else 
    fatal("%s invalid mode specified!", __func__);

  while (fgets(line, sizeof(line), fd)) {
    /* Note that supporting comment lines starting with '#' automatically
     * entails not being able to get passwords that start with '#'.
     */
    if (*line == '#')
      continue;

    /* A blank line (just the '\n' char) in a wordlist file means that a
     * blank entry will be tested. Strndup allocates an entry that is at least
     * of 1 size ('\0'), so supplying it with the length of each line minus the
     * '\n' character of the line will universally work in all cases.
     * However, we need to take into account the possibility that the user
     * supplies Windows-derived wordlists which use CRLF termination.
     * In that case, just drop the 1 extra character.
     */
    if (strlen(line) == 2 && !strncmp(line, "\r\n", 2))
      line[1] = '\0';

    tmp = Strndup(line, strlen(line) - 1);
    p->push_back(tmp);
  }
}



static void
call_module(nsock_pool nsp, Connection *con)
{
  char *name = con->service->name;

  /* initialize connection state variables */
  con->auth_success = false;
  con->check_closed = false;
  con->auth_complete = false;
  con->peer_alive = false;
  con->finished_normally = false;
  con->close_reason = -1;
  con->force_close = false;


  if (!strcmp(name, "ftp"))
    ncrack_ftp(nsp, con);
  else if (!strcmp(name, "telnet"))
    ncrack_telnet(nsp, con);
  else if (!strcmp(name, "http"))
    ncrack_http(nsp, con);
  else if (!strcmp(name, "pop3"))
    ncrack_pop3(nsp, con);
  else if (!strcmp(name, "vnc"))
    ncrack_vnc(nsp, con);
  else if (!strcmp(name, "redis"))
    ncrack_redis(nsp, con);
  else if (!strcmp(name, "mqtt"))
    ncrack_mqtt(nsp, con);
  else if (!strcmp(name, "imap"))
    ncrack_imap(nsp, con);
  else if (!strcmp(name, "cassandra"))
    ncrack_cassandra(nsp, con);  
  else if (!strcmp(name,"cvs"))
    ncrack_cvs(nsp,con);
  else if (!strcmp(name, "joomla"))
    ncrack_joomla(nsp, con);  
  else if (!strcmp(name, "dicom"))
    ncrack_dicom(nsp, con);  
  else if (!strcmp(name, "couchbase"))
    ncrack_couchbase(nsp, con);
  else if (!strcmp(name, "wordpress") || !strcmp(name, "wp"))
    ncrack_wordpress(nsp, con);
  else if (!strcmp(name, "webform") || !strcmp(name, "web"))
    ncrack_webform(nsp, con);
#if HAVE_OPENSSL
  else if (!strcmp(name, "wordpress-tls") || !strcmp(name, "wp-tls"))
    ncrack_wordpress(nsp, con);
  else if (!strcmp(name, "webform-tls") || !strcmp(name, "web-tls"))
    ncrack_webform(nsp, con);
  else if (!strcmp(name, "winrm"))
    ncrack_winrm(nsp, con);
  else if (!strcmp(name, "mongodb"))
    ncrack_mongodb(nsp, con);
  else if (!strcmp(name, "pop3s"))
    ncrack_pop3(nsp, con);
  else if (!strcmp(name, "mysql"))
    ncrack_mysql(nsp, con);
  else if (!strcmp(name, "psql"))
    ncrack_psql(nsp, con);  
  else if (!strcmp(name, "mssql"))
    ncrack_mssql(nsp, con);
  else if (!strcmp(name, "ssh"))
    ncrack_ssh(nsp, con);
  else if (!strcmp(name, "owa"))
    ncrack_owa(nsp, con);
  else if (!strcmp(name, "https"))
    ncrack_http(nsp, con);
  else if (!strcmp(name, "sip"))
    ncrack_sip(nsp, con);
  else if (!strcmp(name, "rdp") || !strcmp(name, "ms-wbt-server"))
    ncrack_rdp(nsp, con);
  else if (!strcmp(name, "smb") || !strcmp(name, "netbios-ssn") || !strcmp(name, "microsoft-ds"))
    ncrack_smb(nsp, con);
  else if (!strcmp(name, "smb2"))
    ncrack_smb2(nsp, con);

#endif
  else
    fatal("Invalid service module: %s", name);
}


int
main(int argc, char **argv)
{
  char **myargv = NULL;
  int myargc = 0;

  if (argc == 3 && strcmp("--resume", argv[1]) == 0) {
    if (ncrack_resume(argv[2], &myargc, &myargv) == -1) {
      fatal("Cannot resume from (supposed) log file %s", argv[2]);
    }
    o.resume = true;
    return ncrack_main(myargc, myargv);
  }

  return ncrack_main(argc, argv);
}




static int
ncrack_main(int argc, char **argv)
{
  ts_spec spec;

  FILE *inputfd = NULL;
  char *normalfilename = NULL;
  char *xmlfilename = NULL;
  time_t timep;
  unsigned int i; /* iteration var */
  char services_file[256]; /* path name for "ncrack-services" file */
  char username_file[256];
  char password_file[256];
  /* strtok changes the first argument and we don't want to mess with
   * the argv stuff, as they hold important info for later. For this reason,
   * we copy optarg to tmp each time a function that calls strtok is going to
   * be invoked.
   */
  char *tmp = NULL;
  int err;

  char *host_spec = NULL;
  Target *currenths = NULL;
  vector <Target *> Targets;        /* targets to be ncracked */
  vector <Target *>::iterator Tvi;

  ServiceGroup *SG;                 /* all services to be ncracked */
  list <Service *>::iterator li;

  vector <Service *>Services;       /* temporary services vector */
  vector <Service *>::iterator Svi; /* iterator for services vector */
  Service *service;

  vector <service_lookup *> services_cmd;
  vector <service_lookup *>::iterator SCvi;

  char *glob_options = NULL;  /* for -g option */
  timing_options timing;      /* for -T option */

  /* time variables */
  time_t now;
  char tbuf[128];
  char mytime[128];

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
    {"resume", required_argument, 0, 0},
    {"save", required_argument, 0, 0},
    {"list", no_argument, 0, 0},
    {"services", required_argument, 0, 'p'},
    {"version", no_argument, 0, 'V'},
    {"verbose", no_argument, 0, 'v'},
    {"datadir", required_argument, 0, 0},
    {"debug", optional_argument, 0, 'd'},
    {"help", no_argument, 0, 'h'},
    {"timing", required_argument, 0, 'T'},
    {"excludefile", required_argument, 0, 0},
    {"exclude", required_argument, 0, 0},
    {"iL", required_argument, 0, 0},
    {"iX", required_argument, 0, 0},
    {"iN", required_argument, 0, 0},
    {"oA", required_argument, 0, 0},  
    {"oN", required_argument, 0, 0},
    {"oX", required_argument, 0, 0},  
    {"append_output", no_argument, 0, 0},
    {"append-output", no_argument, 0, 0},
    {"log_errors", no_argument, 0, 0},
    {"log-errors", no_argument, 0, 0},
    {"stealthy_linear", no_argument, 0, 0},
    {"stealthy-linear", no_argument, 0, 0},
    {"connection_limit", required_argument, 0, 0},
    {"connection-limit", required_argument, 0, 0},
    {"passwords_first", no_argument, 0, 0},
    {"passwords-first", no_argument, 0, 0},
    {"pairwise", no_argument, 0, 0},
    {"user", required_argument, 0, 0},
    {"pass", required_argument, 0, 0},
    {"nsock-trace", required_argument, 0, 0},
    {"nsock_trace", required_argument, 0, 0},
    {"proxy", required_argument, 0, 0},
    {"proxies", required_argument, 0, 0},
    {0, 0, 0, 0}
  };

  if (argc < 2)
    print_usage();

  ncrack_fetchfile(services_file, sizeof(services_file), "ncrack-services");
  /* Initialize available services' lookup table */
  lookup_init(services_file);

#if WIN32 
  win_init();
#endif


  now = time(NULL);
  err = n_localtime(&now, &local_time);
  if (err) {
    fatal("n_localtime failed: %s", strerror(err));
  }

  /* Argument parsing */
  optind = 1;
  while((arg = getopt_long_only(argc, argv, "6d::f::g:hU:P:m:o:p:s:T:v::V",
          long_options, &option_index)) != EOF) {
    switch(arg) {
      case 0:
        if (!strcmp(long_options[option_index].name, "excludefile")) {
          if (exclude_spec)
            fatal("--excludefile and --exclude options are mutually "
                "exclusive.");
          excludefd = fopen(optarg, "r");
          if (!excludefd)
            fatal("Failed to open exclude file %s for reading", optarg);
        } else if (!strcmp(long_options[option_index].name, "exclude")) {
          if (excludefd)
            fatal("--excludefile and --exclude options are mutually "
                "exclusive.");
          exclude_spec = strdup(optarg);

        } else if (!strcmp(long_options[option_index].name, "services")) {
          parse_services(optarg, services_cmd);
        } else if (!strcmp(long_options[option_index].name, "list")) {
          o.list_only = true;
        } else if (!strcmp(long_options[option_index].name,
              "connection-limit")) {
          o.connection_limit = atoi(optarg);
        } else if (!strcmp(long_options[option_index].name,
              "passwords-first")) {
          o.passwords_first = true;
        } else if (!strcmp(long_options[option_index].name,
              "pairwise")) {
          o.pairwise = true;
        } else if (!strcmp(long_options[option_index].name,
              "nsock-trace")) {
          int lvl;

          lvl = atoi(optarg);

          if (lvl >= 7)
            o.nsock_loglevel = NSOCK_LOG_DBG_ALL;
          else if (lvl >= 4)
            o.nsock_loglevel = NSOCK_LOG_DBG;
          else if (lvl >= 2)
            o.nsock_loglevel = NSOCK_LOG_INFO;
          else
            o.nsock_loglevel = NSOCK_LOG_ERROR;
        } else if (!strcmp(long_options[option_index].name, "proxy") ||
                   !strcmp(long_options[option_index].name, "proxies")) {
          if (nsock_proxychain_new(optarg, &o.proxychain, NULL) < 0)
            fatal("Invalid proxy chain specification.");
          if (strlen(optarg) >= 7 && !(strncmp(optarg, "socks4a", 7)))
            o.socks4a = true;
        } else if (!strcmp(long_options[option_index].name, "log-errors")) {
          o.log_errors = true;
        } else if (!strcmp(long_options[option_index].name, "stealthy-linear")) {
          o.stealthy_linear = true;
        } else if (!strcmp(long_options[option_index].name, "append-output")) {
          o.append_output = true;
        } else if (strcmp(long_options[option_index].name, "datadir") == 0) {
          o.datadir = strdup(optarg);
        } else if (strcmp(long_options[option_index].name, "iX") == 0) {
          if (inputfd)
            fatal("Only one input filename allowed");
          o.nmap_input_xml = true;
          inputfd = fopen(strdup(optarg), "r");
          if (!inputfd)
            fatal("Failed to open input file %s for reading", optarg);
        } else if (strcmp(long_options[option_index].name, "iN") == 0) {
          if (inputfd)
            fatal("Only one input filename allowed");
          o.nmap_input_normal = true;
          inputfd = fopen(strdup(optarg), "r");
          if (!inputfd)
            fatal("Failed to open input file %s for reading", optarg);
        } else if (strcmp(long_options[option_index].name, "iL") == 0) {
          if (inputfd)
            fatal("Only one input filename allowed");
          inputfd = fopen(strdup(optarg), "r");
          if (!inputfd)
            fatal("Failed to open input file %s for reading", optarg);
        } else if (strcmp(long_options[option_index].name, "oN") == 0) {
          normalfilename = logfilename(optarg, &local_time);
        } else if (strcmp(long_options[option_index].name, "oX") == 0) {
          xmlfilename = logfilename(optarg, &local_time);
        } else if (strcmp(long_options[option_index].name, "oA") == 0) {
          char buf[MAXPATHLEN];
          Snprintf(buf, sizeof(buf), "%s.ncrack", logfilename(optarg, &local_time));
          normalfilename = strdup(buf);
          Snprintf(buf, sizeof(buf), "%s.xml", logfilename(optarg, &local_time));
          xmlfilename = strdup(buf);
        } else if (strcmp(long_options[option_index].name, "user") == 0) {
          if (o.userlist_src)
            fatal("You have already specified the username list source!\n");
          o.userlist_src = 1;

          tmp = Strndup(optarg, strlen(optarg));
          parse_login_list(tmp, USER);
          free(tmp);
        } else if (strcmp(long_options[option_index].name, "pass") == 0) {
          if (o.passlist_src)
            fatal("You have already specified the password list source!\n");
          o.passlist_src = 1;
          tmp = Strndup(optarg, strlen(optarg));
          parse_login_list(tmp, PASS);
          free(tmp);
        } else if (strcmp(long_options[option_index].name, "resume") == 0) {
          fatal("--resume <file> can only be used as sole command-line "
              "option to Ncrack! Invoke Ncrack without any other "
              "arguments.\n");
        } else if (strcmp(long_options[option_index].name, "vv") == 0) {
          /* Compatability hack ... ugly */
          o.verbose += 2;  
        } else if (strcmp(long_options[option_index].name, "save") == 0) {
          o.save_file = logfilename(optarg, &local_time);
        } 
        break;
      case '6':
#if !HAVE_IPV6
        fatal("I am afraid IPv6 is not available because your host doesn't "
            "support it or you chose to compile Ncrack w/o IPv6 support.");
#else
        o.setaf(AF_INET6);
#endif /* !HAVE_IPV6 */
        break;
      case 'd': 
        if (optarg && isdigit(optarg[0])) {
          o.debugging = o.verbose = atoi(optarg);
        } else {
          const char *p;
          o.debugging++;
          o.verbose++;
          for (p = optarg != NULL ? optarg : ""; *p == 'd'; p++) {
            o.debugging++;
            o.verbose++;
          }
          if (*p != '\0')
            fatal("Invalid argument to -d: \"%s\".", optarg);
        }
        break;
      case 'f':
        if (optarg && isdigit(optarg[0])) {
          o.finish = atoi(optarg);
        } else {
          const char *p;
          o.finish++;
          for (p = optarg != NULL ? optarg : ""; *p == 'd'; p++) {
            o.finish++;
          }
          if (*p != '\0')
            fatal("Invalid argument to -f: \"%s\".", optarg);
        }
        break;
      case 'g':
        glob_options = strdup(optarg);
        o.global_options = true;
        break;
      case 'h':   /* help */
        print_usage();
        break;
#if 0
      case 'i': 
        if (inputfd)
          fatal("Only one input filename allowed");
        if (!strcmp(optarg, "-"))
          inputfd = stdin;
        else    
          fatal("You have to specify a specific input format for -i option: "
              "-iL, -iN or -iX\n");
        break;
#endif
      case 'U':
        if (o.userlist_src)
          fatal("You have already specified the username list source!\n");
        o.userlist_src = 2;
        ncrack_fetchfile(username_file, sizeof(username_file),
            optarg, 1);
        load_login_file(username_file, USER);
        break;
      case 'P':
        if (o.passlist_src)
          fatal("You have already specified the password list source!\n");
        o.passlist_src = 2;
        ncrack_fetchfile(password_file, sizeof(password_file),
            optarg, 1);
        load_login_file(password_file, PASS);
        break;
      case 'm':
        tmp = Strndup(optarg, strlen(optarg));
        parse_module_options(tmp);
        free(tmp);
        break;
      case 'o':
        normalfilename = logfilename(optarg, &local_time);
        break;
      case 'p':   /* services */
        tmp = Strndup(optarg, strlen(optarg));
        parse_services(tmp, services_cmd); 
        free(tmp);
        break;
      case 's': /* only list hosts */
        if (*optarg == 'L')
          o.list_only = true;
        else 
          fatal("Illegal argument for option '-s' Did you mean -sL?");
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
          fatal("Unknown timing mode (-T argument). Use either \"Paranoid\", "
              "\"Sneaky\", \"Polite\", \"Normal\", \"Aggressive\", "
              "\"Insane\" or a number from 0 (Paranoid) to 5 (Insane)");
        }
        break;
      case 'V': 
        log_write(LOG_STDOUT, "\n%s version %s ( %s )\n",
            NCRACK_NAME, NCRACK_VERSION, NCRACK_URL);
        log_write(LOG_STDOUT, "Modules: SSH, RDP, FTP, Telnet, HTTP(S), Wordpress, POP3(S), IMAP, CVS, "
            "SMB, VNC, SIP, Redis, PostgreSQL, MQTT, MySQL, MSSQL, MongoDB, Cassandra, WinRM, OWA, DICOM\n");
        exit(EXIT_SUCCESS);
        break;
      case 'v':
        if (optarg && isdigit(optarg[0])) {
          o.verbose = atoi(optarg);
        } else {
          const char *p;
          o.verbose++;
          for (p = optarg != NULL ? optarg : ""; *p == 'v'; p++)
            o.verbose++;
          if (*p != '\0')
            fatal("Invalid argument to -v: \"%s\".", optarg);
        }
        break;
      case '?':   /* error */
        print_usage();
    }
  }

  /* Initialize tty for interactive output */
  tty_init();

  /* Open the log files, now that we know whether the user wants them appended
     or overwritten */
  if (normalfilename) {
    log_open(LOG_NORMAL, normalfilename);
    free(normalfilename);
  }
  if (xmlfilename) {
    log_open(LOG_XML, xmlfilename);
    free(xmlfilename);
  }

  if (UserArray.empty()) {
    ncrack_fetchfile(username_file, sizeof(username_file),
        DEFAULT_USERNAME_FILE);
    load_login_file(username_file, USER);
  }
  if (PassArray.empty()) {
    ncrack_fetchfile(password_file, sizeof(password_file),
        DEFAULT_PASSWORD_FILE);
    load_login_file(password_file, PASS);
  }


  /* Now handle signals */

#if defined(HAVE_SIGNAL) && defined(SIGPIPE)
  signal(SIGPIPE, SIG_IGN);
  /* ignore SIGPIPE so our program doesn't crash because
   * of it, but we really shouldn't get an unsuspected SIGPIPE
   */
#endif

  /* The handler for the rest of the signals will be established after
   * ServiceGroup has been initialized, since the saved state that is going to
   * be written into the file used for --resume option, requires that
   * information. There is no point in catching the signals before, because
   * there is no benefit in doing anything special then (can't save the state
   * yet that is). The default actions are enough.
   */


  /* Prepare -T option (3 is default) */
  prepare_timing_template(&timing);

  if (strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M %Z", &local_time) <= 0)
    fatal("Unable to properly format time");
  log_write(LOG_STDOUT, "\nStarting %s %s ( %s ) at %s\n",
      NCRACK_NAME, NCRACK_VERSION, NCRACK_URL, tbuf);


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

  /* Brief info incase they forget what was scanned */
  timep = time(NULL);
  err = n_ctime(mytime, sizeof(mytime), &timep);
  if (err) {
    fatal("n_ctime failed: %s", strerror(err));
  }
  chomp(mytime);

  //char *xslfname = o.XSLStyleSheet();
  char *xslfname = NULL; // no stylesheet for now

  xml_start_document("ncrackrun");
  if (xslfname) {
    xml_open_pi("xml-stylesheet");
    xml_attribute("href", "%s", xslfname);
    xml_attribute("type", "text/xsl");
    xml_close_pi();
    xml_newline();
  }

  xml_start_comment();
  xml_write_escaped(" %s %s scan initiated %s as: %s ", NCRACK_NAME, NCRACK_VERSION, mytime, join_quoted(argv, argc).c_str());
  xml_end_comment();
  xml_newline();

  xml_open_start_tag("ncrackrun");
  xml_attribute("scanner", "ncrack");
  xml_attribute("args", "%s", join_quoted(argv, argc).c_str());
  xml_attribute("start", "%lu", (unsigned long) timep);
  xml_attribute("startstr", "%s", mytime);
  xml_attribute("version", "%s", NCRACK_VERSION);
  xml_attribute("xmloutputversion", NCRACK_XMLOUTPUTVERSION);
  xml_close_start_tag();
  xml_newline();

  xml_open_start_tag("verbose");
  xml_attribute("level", "%d", o.verbose);
  xml_close_empty_tag();
  xml_newline();
  xml_open_start_tag("debugging");
  xml_attribute("level", "%d", o.debugging);
  xml_close_empty_tag();
  xml_newline();

  std::string command;
  if (argc > 0)
    command += argv[0];
  for (i = 1; i < (unsigned int)argc; i++) {
    command += " ";
    command += argv[i];
  }

  log_write(LOG_NORMAL, "# ");
  log_write(LOG_NORMAL, "%s %s scan initiated %s as: ", NCRACK_NAME, NCRACK_VERSION, mytime);
  log_write(LOG_NORMAL, "%s", command.c_str());
  log_write(LOG_NORMAL, "\n");

  /* 
   * These will later be used by ncrack_save() to write the way Ncrack was
   * called to the restore file.
   */
  o.saved_argv = argv;
  o.saved_argc = argc;


  SG = new ServiceGroup();
  SG->connection_limit = o.connection_limit;


  while ((host_spec = grab_next_host_spec(inputfd, argc, argv))) {

    /* preparse and separate host - service */
    spec = parse_services_target(host_spec);
    if (spec.error)
      continue;

    // log_write(LOG_STDOUT,"%s://%s:%s?%s\n",spec.service_name,
    // spec.host_expr, spec.portno, spec.service_options);

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

    Svi = Services.begin();
    while (Svi != Services.end()) {
      /* first apply timing template */
      apply_timing_template(*Svi, &timing);
      /* then apply global options -g if they exist */
      if (o.global_options) 
        apply_host_options(*Svi, glob_options);
      /* then apply options from ServiceTable (-m option) */
      if (apply_service_options(*Svi) < 0) {
        /* If service is not supported, remove it from list */
        Svi = Services.erase(Svi);
      } else 
        Svi++;
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
        for (li = SG->services_all.begin(); li != SG->services_all.end();
            li++) {
          if (!strcmp((*li)->target->NameIP(), currenths->NameIP())
              && (!strcmp((*li)->name, service->name))
              && ((*li)->portno == service->portno))
            fatal("Duplicate service %s for target %s !",
                service->name, currenths->NameIP());
        }

        /* 
         * Push service to both 'services_all' (every service resides there)
         * and to 'services_active' list (every service starts with
         * 1 connection)
         */
        SG->services_all.push_back(service);
        SG->services_active.push_back(service);
        SG->total_services++;
      }
    }
    Services.clear();
    clean_spec(&spec);
  }

  if (o.list_only) {
    if (o.debugging) {
      log_write(LOG_PLAIN, "----- [ Timing Template ] -----\n");
      log_write(LOG_PLAIN, "cl=%ld, CL=%ld, at=%ld, cd=%ld, cr=%ld, to=%lld\n",
          timing.min_connection_limit, timing.max_connection_limit,
          timing.auth_tries, timing.connection_delay,
          timing.connection_retries, timing.timeout);

      log_write(LOG_PLAIN, "\n----- [ ServicesTable ] -----\n");

      int colno = 0;
      int col_port = colno++;
      int col_cl = colno++;
      int col_CL = colno++;
      int col_at = colno++;
      int col_cd = colno++;
      int col_cr = colno++;
      int col_to = colno++;
      int col_ssl = colno++;
      int col_path = colno++;
      int col_db = colno++;
      int col_domain = colno++;
      int numrows = ServicesTable.size() + 1;
      NcrackOutputTable *Tbl = new NcrackOutputTable(numrows, colno);

      Tbl->addItem(0, col_port, false, "SERVICE", sizeof("SERVICE") - 1);
      Tbl->addItem(0, col_cl, false, "cl", sizeof("cl") - 1);
      Tbl->addItem(0, col_CL, false, "CL", sizeof("CL") - 1);
      Tbl->addItem(0, col_at, false, "at", sizeof("at") - 1);
      Tbl->addItem(0, col_cd, false, "cd", sizeof("cd") - 1);
      Tbl->addItem(0, col_cr, false, "cr", sizeof("cr") - 1);
      Tbl->addItem(0, col_to, false, "to", sizeof("to") - 1);
      Tbl->addItem(0, col_ssl, false, "ssl", sizeof("ssl") - 1);
      Tbl->addItem(0, col_path, false, "path", sizeof("path") - 1);
      Tbl->addItem(0, col_db, false, "db", sizeof("db") - 1);
      Tbl->addItem(0, col_domain, false, "domain", sizeof("domain") - 1);

      int rowno = 1;

      for (i = 0; i < ServicesTable.size(); i++) {

        Tbl->addItemFormatted(rowno, col_port, false, "%s:%hu",
            ServicesTable[i].lookup.name, ServicesTable[i].lookup.portno);

        if (ServicesTable[i].timing.min_connection_limit != NOT_ASSIGNED)
          Tbl->addItemFormatted(rowno, col_cl, false, "%ld",
              ServicesTable[i].timing.min_connection_limit);
        else 
          Tbl->addItem(rowno, col_cl, false, "N/A");

        if (ServicesTable[i].timing.max_connection_limit != NOT_ASSIGNED)
          Tbl->addItemFormatted(rowno, col_CL, false, "%ld",
              ServicesTable[i].timing.max_connection_limit);
        else 
          Tbl->addItem(rowno, col_CL, false, "N/A");

        if (ServicesTable[i].timing.auth_tries != NOT_ASSIGNED)
          Tbl->addItemFormatted(rowno, col_at, false, "%ld",
              ServicesTable[i].timing.auth_tries);
        else 
          Tbl->addItem(rowno, col_at, false, "N/A");

        if (ServicesTable[i].timing.connection_delay != NOT_ASSIGNED)
          Tbl->addItemFormatted(rowno, col_cd, false, "%ld",
              ServicesTable[i].timing.connection_delay);
        else 
          Tbl->addItem(rowno, col_cd, false, "N/A");

        if (ServicesTable[i].timing.connection_retries != NOT_ASSIGNED)
          Tbl->addItemFormatted(rowno, col_cr, false, "%ld",
              ServicesTable[i].timing.connection_retries);
        else 
          Tbl->addItem(rowno, col_cr, false, "N/A");

        if (ServicesTable[i].timing.timeout != NOT_ASSIGNED)
          Tbl->addItemFormatted(rowno, col_to, false, "%ld",
              ServicesTable[i].timing.timeout);
        else 
          Tbl->addItem(rowno, col_to, false, "N/A");

        Tbl->addItem(rowno, col_ssl, false,
            ServicesTable[i].misc.ssl ? "yes" : "no");

        Tbl->addItem(rowno, col_path, false, ServicesTable[i].misc.path ?
            ServicesTable[i].misc.path : "null");

        Tbl->addItem(rowno, col_db, false, ServicesTable[i].misc.db ?
            ServicesTable[i].misc.db : "null");

        Tbl->addItem(rowno, col_domain, false, ServicesTable[i].misc.domain ?
            ServicesTable[i].misc.domain : "null");

        rowno++;
      }      
      log_write(LOG_PLAIN, "%s", Tbl->printableTable(NULL));
      delete Tbl;

    }
    log_write(LOG_PLAIN, "\n----- [ Targets ] -----\n");
    for (i = 0; i < Targets.size(); i++) {
      log_write(LOG_PLAIN, "Host: %s", Targets[i]->NameIP());
      if (Targets[i]->targetname)
        log_write(LOG_PLAIN, " ( %s ) ", Targets[i]->targetname);
      log_write(LOG_PLAIN, "\n");
      for (li = SG->services_all.begin(); li != SG->services_all.end(); li++) {
        if ((*li)->target == Targets[i]) 
          log_write(LOG_PLAIN, "  %s:%hu cl=%ld, CL=%ld, at=%ld, cd=%ld, "
              "cr=%ld, to=%lldms, ssl=%s, path=%s, db=%s, domain=%s\n",
              (*li)->name, (*li)->portno, (*li)->min_connection_limit,
              (*li)->max_connection_limit, (*li)->auth_tries, 
              (*li)->connection_delay, (*li)->connection_retries,
              (*li)->timeout, (*li)->ssl ? "yes" : "no", (*li)->path,
              (*li)->db, (*li)->domain);
      }
    }
  } else {
    if (!SG->total_services)
      fatal("No services specified!");

    /* If --resume had been specified, it is time to copy the saved session
     * info into our ServiceGroup.
     */
    if (o.resume) {

      map<uint32_t, struct saved_info>::iterator mi;
      list <Service *>::iterator li;
      vector <loginpair>::iterator vi;

      for (mi = o.resume_map.begin(); mi != o.resume_map.end(); mi++) {

        for (li = SG->services_all.begin(); li != SG->services_all.end();
            li++) {
          if ((*li)->uid == mi->first)
            break;
        }

        (*li)->setUserlistIndex(mi->second.user_index);
        (*li)->setPasslistIndex(mi->second.pass_index);

        for (vi = mi->second.credentials_found.begin();
            vi != mi->second.credentials_found.end(); vi++) {
          (*li)->addCredential(vi->user, vi->pass);
        }

      }
    }

    /* Now is the right time to establish the signal handlers, since
     * ServiceGroup has been initialized */
#if HAVE_SIGNAL
    signal(SIGINT, sigcatch);
    signal(SIGTERM, sigcatch);
#ifndef WIN32
    signal(SIGHUP, sigcatch); 
#endif
#endif

    if (o.stealthy_linear)
      SG->connection_limit = SG->services_all.size();


    SG->last_accessed = SG->services_active.end();
    SG->prev_modified = SG->services_active.end();
    /* Ncrack 'em all! */
    ncrack(SG);
  }


  log_write(LOG_STDOUT, "\n");
  /* Now print the final results for each service 
   * In addition, check if any of the services timed out so that 
   * we can save a .restore file in case the user needs to resume the session
   * another time. 
   */
  bool save_state = false;
  for (li = SG->services_all.begin(); li != SG->services_all.end(); li++) {

     xml_open_start_tag("service");
     xml_attribute("starttime", "%lu", (unsigned long) (*li)->StartTime());
     xml_attribute("endtime", "%lu", (unsigned long) (*li)->EndTime());
     xml_close_start_tag();
     xml_newline();

     xml_open_start_tag("address");
     xml_attribute("addr", "%s", (*li)->target->NameIP());
     xml_attribute("addrtype", "%s", (o.af() == AF_INET) ? "ipv4" : "ipv6");
     xml_close_empty_tag();
     xml_newline();

     xml_open_start_tag("port");
     xml_attribute("protocol", IPPROTO2STR((*li)->proto));
     xml_attribute("portid", "%d", (*li)->portno);
     xml_attribute("name", (*li)->name);
     xml_close_start_tag();
     xml_end_tag(); /* </port> */
     xml_newline();

    if ((*li)->end.reason != NULL && !strncmp((*li)->end.reason, SERVICE_TIMEDOUT, sizeof(SERVICE_TIMEDOUT)))
      save_state = true;

    if ((*li)->credentials_found.size() != 0)
      print_service_output(*li);

    xml_end_tag(); /* </service> */
    xml_newline();
  }

  /* Print final output information */
  print_final_output(SG);
  log_flush_all();

  /* If any service timed out, then save a .restore file */
  if (save_state)
    ncrack_save(SG);

  /* Free all of the Targets */
  while(!Targets.empty()) {
    currenths = Targets.back();
    delete currenths;
    Targets.pop_back();
  }
  delete SG;

  log_write(LOG_STDOUT, "\nNcrack finished.\n");
  exit(EXIT_SUCCESS);
}


/* Start the timeout clocks of any targets that aren't already timedout */
static void
startTimeOutClocks(ServiceGroup *SG)
{
  struct timeval tv;
  list<Service *>::iterator li;

  gettimeofday(&tv, NULL);
  for (li = SG->services_all.begin(); li != SG->services_all.end(); li++) {
    if (!(*li)->timedOut(NULL))
      (*li)->startTimeOutClock(&tv);
  }
}


/* 
 * It handles module endings
 */
void
ncrack_module_end(nsock_pool nsp, void *mydata)
{
  Connection *con = (Connection *) mydata;
  ServiceGroup *SG = (ServiceGroup *) nsock_pool_get_udata(nsp);
  Service *serv = con->service;
  nsock_iod nsi = con->niod;
  struct timeval now;
  int pair_ret;
  const char *hostinfo = serv->HostInfo();

  con->login_attempts++;
  con->auth_complete = true;
  serv->total_attempts++;
  serv->finished_attempts++;

  /* First check if the module reported that it can no longer continue to
   * crack the assigned service, in which case we should place it in the
   * finished services.
   */
  if (serv->end.orly) {
    if (o.debugging) {
      if (serv->end.reason) {
        chomp(serv->end.reason);
        log_write(LOG_STDOUT, "%s will no longer be cracked because module "
            "reported that:\n %s\n", hostinfo, serv->end.reason);
      } else {
        log_write(LOG_STDOUT, "%s will no longer be cracked. No reason was "
            "reported from module.\n", hostinfo);
      }
    }
    SG->pushServiceToList(serv, &SG->services_finished);
    if (o.verbose)
      log_write(LOG_STDOUT, "%s finished.\n", hostinfo);
    return ncrack_connection_end(nsp, con);
  }

  if (con->auth_success) {
    serv->addCredential(con->user, con->pass);
    SG->credentials_found++;

    if (o.verbose)
      log_write(LOG_PLAIN, "Discovered credentials on %s '%s' '%s'\n",
          hostinfo, con->user, con->pass);

    /* Quit cracking service if '-f' has been specified. */
    if (o.finish == 1) {

      SG->pushServiceToList(serv, &SG->services_finished);
      if (o.verbose)
        log_write(LOG_STDOUT, "%s finished.\n", hostinfo);
      return ncrack_connection_end(nsp, con);

    } else if (o.finish > 1) {
      /* Quit cracking every service if '-f -f' or greater has been
       * specified.
       */
      list <Service *>::iterator li;
      for (li = SG->services_all.begin(); li != SG->services_all.end(); li++) {
        SG->pushServiceToList(*li, &SG->services_finished);
        if (o.verbose)
          log_write(LOG_STDOUT, "%s finished.\n", hostinfo);
      }
      /* Now quit nsock_loop */
      nsock_loop_quit(nsp);
      return ncrack_connection_end(nsp, con);
    }

  } else {
    if (!serv->more_rounds) {
      if (o.debugging > 6) {
        if (!strcmp(serv->name, "redis"))
          log_write(LOG_STDOUT, "%s (EID %li) Login failed: '%s'\n",
              hostinfo, nsock_iod_id(con->niod), con->pass);
        else 
          log_write(LOG_STDOUT, "%s (EID %li) Login failed: '%s' '%s'\n",
              hostinfo, nsock_iod_id(con->niod), con->user, con->pass);
      }
    } else {
      serv->appendToPool(con->user, con->pass);
    }
  }

  if (serv->just_started && !serv->more_rounds 
      && con->close_reason != MODULE_ERR) {
    serv->supported_attempts++;
    serv->auth_rate_meter.update(1, NULL);
  }

  gettimeofday(&now, NULL);
  if (!serv->just_started && !serv->more_rounds
      && timeval_msec_subtract(now, serv->last_auth_rate.time) >= 500) {
    double current_rate = serv->auth_rate_meter.getCurrentRate();
    if (o.debugging) 
      log_write(LOG_STDOUT, "%s last: %.2f current %.2f parallelism %ld\n",
          hostinfo, serv->last_auth_rate.rate, current_rate,
          serv->ideal_parallelism);
    if (current_rate < serv->last_auth_rate.rate + 3) {
      if (serv->ideal_parallelism + 3 < serv->max_connection_limit)
        serv->ideal_parallelism += 3;
      else 
        serv->ideal_parallelism = serv->max_connection_limit;
      if (o.debugging)
        log_write(LOG_STDOUT, "%s Increasing connection limit to: %ld\n", 
            hostinfo, serv->ideal_parallelism);
    }
    serv->last_auth_rate.time = now;
    serv->last_auth_rate.rate = current_rate;
  }

  /* If login pair was extracted from pool, permanently remove it from it. */
  if (con->from_pool && !serv->isMirrorPoolEmpty()) {
    serv->removeFromPool(con->user, con->pass);
    con->from_pool = false;
  }

  if (serv->isMirrorPoolEmpty() && !serv->active_connections
      && serv->getListFinishing()) {
    SG->pushServiceToList(serv, &SG->services_finished);
    if (o.verbose)
      log_write(LOG_STDOUT, "%s finished.\n", hostinfo);
    return ncrack_connection_end(nsp, con);
  }

  /*
   * Check if we had previously surpassed imposed connection limit so that
   * we remove service from 'services_full' list 
   */
  if (serv->getListFull() 
      && serv->active_connections < serv->ideal_parallelism)
    SG->popServiceFromList(serv, &SG->services_full);

  /* Initiate new connections if service gets active again */
  if (serv->getListActive())
    ncrack_probes(nsp, SG);

  /* If module itself reported an error in the connection, then mark the flag
   * auth_complete as false.
   */
  if (con->close_reason == MODULE_ERR)
    con->auth_complete = false;

  /* If module instructed to close the connection by force, then do so
   * here.
   */
  if (con->force_close)
    return ncrack_connection_end(nsp, con);

  /* 
   * If we need to check whether peer is alive or not we do the following:
   * Since there is no portable way to check if the peer has closed the
   * connection or not (hence we are in CLOSE_WAIT state), issue a read call
   * with a very small timeout and check if nsock timed out (host hasn't closed
   * connection yet) or returned an EOF (host sent FIN making active close)
   * Note, however that the connection might have already indicated that the
   * peer is alive (for example telnetd sends the next login prompt along with
   * the authentication results, denoting that it immediately expects another
   * authentication attempt), so in that case we need to get the next login
   * pair only and make no additional check.
   */
  if (con->peer_alive) {
    if ((!serv->auth_tries
          || con->login_attempts < (unsigned long)serv->auth_tries)
        && (pair_ret = serv->getNextPair(&con->user, &con->pass)) != -1) {
      if (pair_ret == 1)
        con->from_pool = true;
      nsock_timer_create(nsp, ncrack_timer_handler, 0, con);
    } else
      return ncrack_connection_end(nsp, con);
  } else {
    /* 
     * We need to check if host is alive only on first timing
     * probe. Thereafter we can use the 'supported_attempts'.
     */
    if (serv->just_started && serv->more_rounds) {
      ncrack_connection_end(nsp, con);
    } else if (serv->just_started) {
      con->check_closed = true;
      nsock_read(nsp, nsi, ncrack_read_handler, 10, con);
    } else if ((!serv->auth_tries
          || con->login_attempts < (unsigned long)serv->auth_tries)
        && con->login_attempts < serv->supported_attempts
        && (pair_ret = serv->getNextPair(&con->user, &con->pass)) != -1) {
      if (pair_ret == 1)
        con->from_pool = true;


      call_module(nsp, con);
    } else {
      /* We end the connection if:
       * (we are not the first timing probe) AND 
       * (we are either at the server's imposed authentication limit OR
       * we are at the user's imposed authentication limit) 
       */
      ncrack_connection_end(nsp, con);
    }
  }
  return;
}


void
ncrack_connection_end(nsock_pool nsp, void *mydata)
{
  Connection *con = (Connection *) mydata;
  Service *serv = con->service;
  nsock_iod nsi = con->niod;
  ServiceGroup *SG = (ServiceGroup *) nsock_pool_get_udata(nsp);
  list <Connection *>::iterator li;
  const char *hostinfo = serv->HostInfo();
  unsigned long eid = nsock_iod_id(con->niod);


  if (con->close_reason == CON_ERR)
    SG->connections_timedout++;

  if (con->close_reason == READ_TIMEOUT) {

    if (!con->auth_complete) {
      serv->appendToPool(con->user, con->pass);
    }

    if (serv->getListPairfini())
      SG->popServiceFromList(serv, &SG->services_pairfini);
    if (o.debugging)
      error("%s (EID %li) nsock READ timeout!", hostinfo, eid);

  } else if (con->close_reason == READ_EOF || con->close_reason == MODULE_ERR) {
    /* 
     * Check if we are on the point where peer might close at any moment
     * (usually we set 'peer_might_close' after writing the password on the
     * network and before issuing the next read call), so that this connection
     * ending was actually expected.
     */
    if (con->peer_might_close) {
      /* If we are the first special timing probe, then increment the number of
       * server-allowed authentication attempts per connection.
       */
      if (serv->just_started)
        serv->supported_attempts++;

      serv->total_attempts++;
      serv->finished_attempts++;

      if (o.debugging > 6)
        log_write(LOG_STDOUT, "%s (EID %li) Failed '%s' '%s'\n", hostinfo, eid,
            con->user, con->pass);

    } else if (serv->more_rounds) {
      /* We are still checking timing of the host, so don't do anything yet. */

    } else if (!con->auth_complete) {
      serv->appendToPool(con->user, con->pass);
      if (serv->getListPairfini())
        SG->popServiceFromList(serv, &SG->services_pairfini);

      /* Now this is strange: peer closed on us in the middle of
       * authentication. This shouldn't happen, unless extreme network
       * conditions are happening!
       */
      if (!serv->just_started 
          && con->login_attempts < serv->supported_attempts) {
        if (o.debugging > 3)
          error("%s (EID %li) closed on us in the middle of authentication!", hostinfo, eid);
        SG->connections_closed++;
      }
    }
    if (o.debugging > 5)
      error("%s (EID %li) Connection closed by peer", hostinfo, eid);
  }
  con->close_reason = -1;


  /* 
   * If we are not the first timing probe and the authentication wasn't
   * completed (we double check that by seeing if we are inside the supported
   * -by the server- threshold of authentication attempts per connection), then
   *  we take drastic action and drop the connection limit.
   */
  if (!serv->just_started && !serv->more_rounds && !con->auth_complete
      && !con->peer_might_close
      && con->login_attempts < serv->supported_attempts) {
    serv->total_attempts++;
    // TODO:perhaps here we might want to differentiate between the two errors:
    // timeout and premature close, giving a unique drop value to each
    if (serv->ideal_parallelism - 5 >= serv->min_connection_limit)
      serv->ideal_parallelism -= 5;
    else 
      serv->ideal_parallelism = serv->min_connection_limit;

    if (o.debugging)
      log_write(LOG_STDOUT, "%s (EID %li) Dropping connection limit due to connection "
          "error to: %ld\n", hostinfo, eid, serv->ideal_parallelism);
  }


  /* 
   * If that was our first connection, then calculate initial ideal_parallelism
   * (which was 1 previously) based on the box of min_connection_limit,
   * max_connection_limit and a default desired parallelism for each timing
   * template.
   */
  if (serv->just_started == true && !serv->more_rounds) {
    serv->just_started = false;
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

    serv->ideal_parallelism = box(serv->min_connection_limit,
        serv->max_connection_limit, desired_par);
  }


  for (li = serv->connections.begin(); li != serv->connections.end(); li++) {
    if ((*li)->niod == nsi)
      break;
  }
  if (li == serv->connections.end()) /* this shouldn't happen */
    fatal("%s: invalid niod!", __func__);

  SG->auth_rate_meter.update(con->login_attempts, NULL);

  nsock_iod_delete(nsi, NSOCK_PENDING_SILENT);
  serv->connections.erase(li);
  delete con;

  serv->active_connections--;
  SG->active_connections--;


  /*
   * Check if we had previously surpassed imposed connection limit so that
   * we remove service from 'services_full' list
   */
  if (serv->getListFull()
      && serv->active_connections < serv->ideal_parallelism)
    SG->popServiceFromList(serv, &SG->services_full);


  /* 
   * If linear stealthy mode is enabled, then mark the corresponding state as DONE
   * since the connection just ended. If all connections from all services are done,
   * then the next active connection can start.
   */
  if (serv->getLinearState() == LINEAR_ACTIVE) {
    serv->setLinearState(LINEAR_DONE);
    serv->ideal_parallelism = 1;
  }


  /*
   * If service was on 'services_finishing' (credential list finished, pool
   * empty but still pending connections) then:
   * - if new pairs arrived into pool, remove from 'services_finishing'
   * - else if no more connections are pending, move to 'services_finished'
   */
  if (serv->getListFinishing()) {
    if (!serv->isMirrorPoolEmpty())
      SG->popServiceFromList(serv, &SG->services_finishing);
    else if (!serv->active_connections) {
      SG->pushServiceToList(serv, &SG->services_finished);
      if (o.verbose)
        log_write(LOG_STDOUT, "%s finished.\n", hostinfo);
    }
  }

  if (o.debugging)
    log_write(LOG_STDOUT, "%s (EID %li) Attempts: total %lu completed %lu supported %lu "
        "--- rate %.2f \n", hostinfo, eid, serv->total_attempts,
        serv->finished_attempts, serv->supported_attempts,
        SG->auth_rate_meter.getCurrentRate());

  /* Check if service finished for good. */
  if (serv->loginlist_fini && serv->isMirrorPoolEmpty()
      && !serv->active_connections && !serv->getListFinished()) {
    SG->pushServiceToList(serv, &SG->services_finished);
    if (o.verbose)
      log_write(LOG_STDOUT, "%s finished.\n", hostinfo);
  }


  /* see if we can initiate some more connections */
  if (serv->getListActive())
    return ncrack_probes(nsp, SG);

  return;
}


void
ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
  enum nse_status status = nse_status(nse);
  enum nse_type type = nse_type(nse);
  ServiceGroup *SG = (ServiceGroup *) nsock_pool_get_udata(nsp);
  Connection *con = (Connection *) mydata;
  Service *serv = con->service;
  int pair_ret;
  int nbytes;
  int err;
  char *str;
  const char *hostinfo = serv->HostInfo();
  unsigned long eid = nsock_iod_id(con->niod);

  assert(type == NSE_TYPE_READ);


  /* If service has already finished (probably due to the -f option), then
   * cancel this event and return immediately. The same happens with the rest
   * of the event handlers.
   */
  if (serv->getListFinished()) {
    nsock_event_cancel(nsp, nse_id(nse), 0);
    return;
  }

  if (serv->timedOut(NULL)) {
    serv->end.reason = Strndup(SERVICE_TIMEDOUT, sizeof(SERVICE_TIMEDOUT));
    SG->pushServiceToList(serv, &SG->services_finished);
    if (o.verbose)
      log_write(LOG_STDOUT, "%s finished.\n", hostinfo);
    return ncrack_connection_end(nsp, con);

  } else if (status == NSE_STATUS_SUCCESS) {

    str = nse_readbuf(nse, &nbytes);

    if (con->inbuf == NULL)
      con->inbuf = new Buf();

    con->inbuf->append(str, nbytes);

    return call_module(nsp, con);

  } else if (status == NSE_STATUS_TIMEOUT) {

    /* First check if we are just making sure the host hasn't closed
     * on us, and so we are still in ESTABLISHED state, instead of
     * CLOSE_WAIT - we do this by issuing a read call with a tiny timeout.
     * If we are still connected, then we can go on checking if we can make
     * another authentication attempt in this particular connection.
     */
    if (con->check_closed) {
      /* Make another authentication attempt only if:
       * 1. we hanen't surpassed the authentication limit per connection for
       *    this service
       * 2. we still have enough login pairs from the pool
       */
      if ((!serv->auth_tries 
            || con->login_attempts < (unsigned long)serv->auth_tries)
          && (pair_ret = serv->getNextPair(&con->user, &con->pass)) != -1) {
        if (pair_ret == 1)
          con->from_pool = true;
        return call_module(nsp, con);
      } else {
        con->close_reason = READ_EOF;
      }
    } else {
      /* This is a normal timeout */
      con->close_reason = READ_TIMEOUT;
    }

  } else if (status == NSE_STATUS_EOF) {
    con->close_reason = READ_EOF;

  } else if (status == NSE_STATUS_ERROR || status == NSE_STATUS_PROXYERROR) {

    err = nse_errorcode(nse);
    if (o.debugging > 2)
      error("%s (EID %li) nsock READ error #%d (%s)", hostinfo, eid, err, strerror(err));
    serv->appendToPool(con->user, con->pass);
    if (serv->getListPairfini())
      SG->popServiceFromList(serv, &SG->services_pairfini);

  } else if (status == NSE_STATUS_KILL) {
    if (o.debugging > 2)
      error("%s (EID %li) nsock READ nse_status_kill", hostinfo, eid);

  } else
    if (o.debugging > 2)
      error("%s (EID %li) WARNING: nsock READ unexpected status %d", hostinfo,
          eid, (int) status);

  return ncrack_connection_end(nsp, con);
}




void
ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
  enum nse_status status = nse_status(nse);
  Connection *con = (Connection *) mydata;
  ServiceGroup *SG = (ServiceGroup *) nsock_pool_get_udata(nsp);
  Service *serv = con->service;
  const char *hostinfo = serv->HostInfo();
  int err;
  unsigned long eid = nsock_iod_id(con->niod);

  if (serv->getListFinished()) {
    nsock_event_cancel(nsp, nse_id(nse), 0);
    return;
  }

  if (serv->timedOut(NULL)) {
    serv->end.reason = Strndup(SERVICE_TIMEDOUT, sizeof(SERVICE_TIMEDOUT));
    SG->pushServiceToList(serv, &SG->services_finished);
    if (o.verbose)
      log_write(LOG_STDOUT, "%s finished.\n", hostinfo);
    return ncrack_connection_end(nsp, con);

  } else if (status == NSE_STATUS_SUCCESS)
    call_module(nsp, con);
  else if (status == NSE_STATUS_ERROR || status == NSE_STATUS_PROXYERROR) {
    err = nse_errorcode(nse);
    if (o.debugging > 2)
      error("%s (EID %li) nsock WRITE error #%d (%s)", hostinfo, eid, err, strerror(err));
  } else if (status == NSE_STATUS_KILL) {
    error("%s (EID %li) nsock WRITE nse_status_kill\n", hostinfo, eid);
  } else
    error("%s (EID %li) WARNING: nsock WRITE unexpected status %d", 
        hostinfo, eid, (int) (status));

  return;
}


void
ncrack_timer_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
  enum nse_status status = nse_status(nse);
  Connection *con = (Connection *) mydata;
  Service *serv = con->service;
  const char *hostinfo = serv->HostInfo();

  if (serv->getListFinished()) {
    nsock_event_cancel(nsp, nse_id(nse), 0);
    return;
  }

  if (status == NSE_STATUS_SUCCESS) {
    call_module(nsp, con);
  }
  else 
    error("%s nsock Timer handler error!", hostinfo);

  return;
}




void
ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
  nsock_iod nsi = nse_iod(nse);
  enum nse_status status = nse_status(nse);
  enum nse_type type = nse_type(nse);
  ServiceGroup *SG = (ServiceGroup *) nsock_pool_get_udata(nsp);
  Connection *con = (Connection *) mydata;
  Service *serv = con->service;
  const char *hostinfo = serv->HostInfo();
  int err;
  unsigned long eid = nsock_iod_id(con->niod);

  assert(type == NSE_TYPE_CONNECT || type == NSE_TYPE_CONNECT_SSL);

  if (serv->getListFinished()) {
    nsock_event_cancel(nsp, nse_id(nse), 0);
    return;
  }

  if (serv->timedOut(NULL)) {
    serv->end.reason = Strndup(SERVICE_TIMEDOUT, sizeof(SERVICE_TIMEDOUT));
    SG->pushServiceToList(serv, &SG->services_finished);
    if (o.verbose)
      log_write(LOG_STDOUT, "%s finished.\n", hostinfo);
    return ncrack_connection_end(nsp, con);

  } else if (status == NSE_STATUS_SUCCESS) {

    serv->failed_connections = 0;

#if HAVE_OPENSSL
    // Snag our SSL_SESSION from the nsi for use in subsequent connections.
    if (nsock_iod_check_ssl(nsi)) {
      if (con->ssl_session) {
        if (con->ssl_session == (SSL_SESSION *)(nsock_iod_get_ssl_session(nsi, 0))) {
          //nada
        } else {
          SSL_SESSION_free((SSL_SESSION*)con->ssl_session);
          con->ssl_session = (SSL_SESSION *)(nsock_iod_get_ssl_session(nsi, 1));
        }
      } else {
        con->ssl_session = (SSL_SESSION *)(nsock_iod_get_ssl_session(nsi, 1));
      }
    }
#endif

    return call_module(nsp, con);

  } else if (status == NSE_STATUS_TIMEOUT || status == NSE_STATUS_ERROR
      || status == NSE_STATUS_PROXYERROR) {

    /* This is not good. connect() really shouldn't generally be timing out. */
    if (o.debugging > 2) {
      err = nse_errorcode(nse);
      error("%s (EID %li) nsock CONNECT response with status %s error: %s", hostinfo,
          eid, nse_status2str(status), strerror(err));
    }
    serv->failed_connections++;
    serv->appendToPool(con->user, con->pass);

    if (serv->failed_connections > serv->connection_retries) {
      SG->pushServiceToList(serv, &SG->services_finished);
      if (o.verbose)
        log_write(LOG_STDOUT, "%s finished. Too many failed attemps. \n", hostinfo);
    }
    /* Failure of connecting on first attempt means we should probably drop
     * the service for good. */
    if (serv->just_started) {
      SG->pushServiceToList(serv, &SG->services_finished);
      if (o.verbose)
        log_write(LOG_STDOUT, "%s finished.\n", hostinfo);
    }
    if (serv->getListPairfini())
      SG->popServiceFromList(serv, &SG->services_pairfini);

    con->close_reason = CON_ERR;

  } else if (status == NSE_STATUS_KILL) {

    if (o.debugging)
      error("%s (EID %li) nsock CONNECT nse_status_kill", hostinfo, eid);
    serv->appendToPool(con->user, con->pass);
    if (serv->getListPairfini())
      SG->popServiceFromList(serv, &SG->services_pairfini);

  } else
    error("%s (EID %li) WARNING: nsock CONNECT unexpected status %d", 
        hostinfo, eid, (int) status);

  return ncrack_connection_end(nsp, con);
}


/*
 * Poll for interactive user input every time this timer is called.
 */
static void
status_timer_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
  int key_ret;
  enum nse_status status = nse_status(nse);
  ServiceGroup *SG = (ServiceGroup *) nsock_pool_get_udata(nsp);
  mydata = NULL; /* nothing in there */

  key_ret = keyWasPressed();
  if (key_ret == KEYPRESS_STATUS)
    printStatusMessage(SG);
  else if (key_ret == KEYPRESS_CREDS)
    print_creds(SG);

  if (status != NSE_STATUS_SUCCESS) {
    /* Don't reschedule timer again, since nsp seems to have been
     * deleted (NSE_STATUS_KILL sent) and we are done. */
    if (status == NSE_STATUS_KILL)
      return;
    else
      error("Nsock status timer handler error: %s\n", nse_status2str(status));
  }

  /* Reschedule timer for the next polling. */
  nsock_timer_create(nsp, status_timer_handler, KEYPRESSED_INTERVAL, NULL);

}

static void
signal_timer_handler(nsock_pool nsp, nsock_event nse, void *mydata)
{
  enum nse_status status = nse_status(nse);
  ServiceGroup *SG = (ServiceGroup *) nsock_pool_get_udata(nsp);
  mydata = NULL; /* nothing in there */

  if (status != NSE_STATUS_SUCCESS) {
    /* Don't reschedule timer again, since nsp seems to have been
     * deleted (NSE_STATUS_KILL sent) and we are done. */
    if (status == NSE_STATUS_KILL) {
      sigcheck(SG);
      return;
    }
    else
      error("Nsock status timer handler error: %s\n", nse_status2str(status));
  }

  /* Reschedule timer for the next polling. */
  nsock_timer_create(nsp, signal_timer_handler, SIGNAL_CHECK_INTERVAL, NULL);

  /* Check for pending signals */
  sigcheck(SG);
}


static void
ncrack_probes(nsock_pool nsp, ServiceGroup *SG)
{
  Service *serv;
  Connection *con;
  struct sockaddr_storage ss;
  size_t ss_len;
  list <Service *>::iterator li;
  struct timeval now;
  int pair_ret;
  char *login, *pass;
  const char *hostinfo;
  size_t i = 0;


  /* First check for every service if connection_delay time has already
   * passed since its last connection and move them back to 'services_active'
   * list if it has.
   */
  gettimeofday(&now, NULL);
  for (li = SG->services_wait.begin(); li != SG->services_wait.end(); li++) {
    if (timeval_msec_subtract(now, (*li)->last) 
        >= (long long)(*li)->connection_delay) {
      li = SG->popServiceFromList(*li, &SG->services_wait);
    }
  }

  if (SG->last_accessed == SG->services_active.end()) {
    li = SG->services_active.begin();
  } else {
    li = SG->last_accessed++;
  }



  while (SG->active_connections < SG->connection_limit
      && SG->services_finished.size() != SG->total_services
      && SG->services_active.size() != 0) {

    serv = *li;
    hostinfo = serv->HostInfo();

    if (serv->timedOut(NULL)) {
      serv->end.reason = Strndup(SERVICE_TIMEDOUT, sizeof(SERVICE_TIMEDOUT));
      SG->pushServiceToList(serv, &SG->services_finished);
      if (o.verbose)
        log_write(LOG_STDOUT, "%s finished.\n", hostinfo);
      goto next;
    }

    /*
     * If the service's last connection was earlier than 'connection_delay'
     * milliseconds ago, then temporarily move service to 'services_wait' list
     */
    gettimeofday(&now, NULL);
    if (timeval_msec_subtract(now, serv->last) 
        < (long long)serv->connection_delay) {
      li = SG->pushServiceToList(serv, &SG->services_wait);
      goto next;
    }


    /* If the service's active connections surpass its imposed connection limit
     * then don't initiate any more connections for it and also move service in
     * the services_full list so that it won't be reaccessed in this loop.
     */
    if (serv->active_connections >= serv->ideal_parallelism) {
      li = SG->pushServiceToList(serv, &SG->services_full);
      goto next;
    }


    /*
     * To mark a service as completely  finished, first make sure:
     * a) that the username list has finished being iterated through once
     * b) that the mirror pair pool, which holds temporary login pairs which
     *    are currently being used, is empty
     * c) that no pending connections are left
     * d) that the service hasn't already finished
     */
    if (serv->loginlist_fini && serv->isMirrorPoolEmpty()
        && !serv->getListFinished()) {
      if (!serv->active_connections) {
        li = SG->pushServiceToList(serv, &SG->services_finished);
        if (o.verbose)
          log_write(LOG_STDOUT, "%s finished.\n", hostinfo);
        goto next;
      } else {
        li = SG->pushServiceToList(serv, &SG->services_finishing);
        goto next;
      }
    }

    /*
     * If the username list iteration has finished, then don't initiate another
     * connection until our pair_pool has at least one element to grab another
     * pair from.
     */
    if (serv->loginlist_fini && serv->isPoolEmpty()
        && !serv->isMirrorPoolEmpty()) {
      li = SG->pushServiceToList(serv, &SG->services_pairfini);
      goto next;
    }

    if ((pair_ret = serv->getNextPair(&login, &pass)) == -1)
      goto next;


    /* 
     * If service belongs to list linear, then we have to wait until all others have
     * first iterated.
     */
    if ((serv->getLinearState() != LINEAR_INIT)
        && (serv->getLinearState() == LINEAR_ACTIVE || SG->checkLinearPending() == true)) {
      goto next;
    }

    /* Schedule 1 connection for this service */
    con = new Connection(serv);
    SG->connections_total++;

    if (o.stealthy_linear) {
      serv->setLinearState(LINEAR_ACTIVE);
    }

    if (pair_ret == 1)
      con->from_pool = true;
    con->user = login;
    con->pass = pass;

    if ((con->niod = nsock_iod_new(nsp, serv)) == NULL) {
      fatal("Failed to allocate Nsock I/O descriptor in %s()", __func__);
    }

    if (o.debugging > 8)
      log_write(LOG_STDOUT, "%s (EID %li) Initiating new Connection\n", hostinfo, nsock_iod_id(con->niod));

    gettimeofday(&now, NULL);
    serv->last = now;
    serv->connections.push_back(con);
    serv->active_connections++;
    SG->active_connections++;

    serv->target->TargetSockAddr(&ss, &ss_len);
    if (serv->proto == IPPROTO_TCP) {
      if (!serv->ssl) {
        if (o.proxychain && o.socks4a) {
          if (!serv->target->targetname)
            fatal("Socks4a requires a hostname. Use socks4 for IPv4.");
          nsock_connect_tcp_socks4a(nsp, con->niod, ncrack_connect_handler,
              DEFAULT_CONNECT_TIMEOUT, con, serv->target->targetname,
              serv->portno);
        } else {
          nsock_connect_tcp(nsp, con->niod, ncrack_connect_handler,
              DEFAULT_CONNECT_TIMEOUT, con,
              (struct sockaddr *)&ss, ss_len,
              serv->portno);
        }
      } else {
        nsock_connect_ssl(nsp, con->niod, ncrack_connect_handler,
            DEFAULT_CONNECT_SSL_TIMEOUT, con,
            (struct sockaddr *) &ss, ss_len, serv->proto,
            serv->portno, con->ssl_session);
      }
    } else {
      assert(serv->proto == IPPROTO_UDP);
      nsock_connect_udp(nsp, con->niod, ncrack_connect_handler,
          serv, (struct sockaddr *) &ss, ss_len,
          serv->portno);
    }

next:

    /* 
     * this will take care of the case where the state of the services_active list
     * has been modified in the meantime by any pushToList or popFromList without
     * saving the state to the current li iterator thus showing to a non-valid
     * service 
     */
    if (SG->prev_modified != li) {
      li = SG->services_active.end();
    }

    SG->last_accessed = li;
    if (li == SG->services_active.end() || ++li == SG->services_active.end()) {
      li = SG->services_active.begin();
    }


    i++;
    if (o.stealthy_linear && i == SG->services_all.size())
      return;

  }

  return;
}



static int
ncrack(ServiceGroup *SG)
{
  /* nsock variables */
  struct timeval now;
  enum nsock_loopstatus loopret;
  list <Service *>::iterator li;
  nsock_pool nsp;
  int nsock_timeout = 3000;
  int err;

  /* create nsock p00l */
  if (!(nsp = nsock_pool_new(SG)))
    fatal("Can't create nsock pool.");

  if (o.proxychain) {
    if (nsock_pool_set_proxychain(nsp, o.proxychain) == -1)
      fatal("Unable to set proxychain for nsock pool");
  }

  gettimeofday(&now, NULL);
  nsock_set_loglevel(o.nsock_loglevel);

#if HAVE_OPENSSL
  /* We don't care about connection security, so cast Haste */
  nsock_pool_ssl_init(nsp, NSOCK_SSL_MAX_SPEED);
#endif

  SG->findMinDelay();
  /* We have to set the nsock_loop timeout to the minimum of the connection
   * delay, since we have to check every that time period for potential new
   * connection initiations. If the minimum connection delay is 0 however, we
   * don't need to do it, since that would make nsock_loop return immediately
   * and consume a lot of CPU.
   */
  if (SG->min_connection_delay != 0)
    nsock_timeout = SG->min_connection_delay;

  /* Initiate time-out clocks */
  startTimeOutClocks(SG);

  /* initiate all authentication rate meters */
  SG->auth_rate_meter.start();
  for (li = SG->services_all.begin(); li != SG->services_all.end(); li++)
    (*li)->auth_rate_meter.start();

  /*
   * Since nsock can delay between each event due to the targets being really
   * slow,  we need a way to make sure that we always poll for interactive user
   * input regardless of the above case. Thus we schedule a special timer event
   * that happens every KEYPRESSED_INTERVAL milliseconds and which reschedules
   * itself every time its handler is called.
   */
  nsock_timer_create(nsp, status_timer_handler, KEYPRESSED_INTERVAL, NULL);

  /*
   * We do the same for checking pending signals every SIGNAL_CHECK_INTERVAL
   */
  nsock_timer_create(nsp, signal_timer_handler, SIGNAL_CHECK_INTERVAL, NULL);

  ncrack_probes(nsp, SG);

  /* nsock loop */
  do {

    loopret = nsock_loop(nsp, nsock_timeout);

    if (loopret == NSOCK_LOOP_ERROR) {
      err = nsock_pool_get_error(nsp);
      fatal("Unexpected nsock_loop error. Error code %d (%s)",
          err, strerror(err));
    }

    ncrack_probes(nsp, SG);

  } while (SG->services_finished.size() != SG->total_services);

  nsock_pool_delete(nsp);

  if (o.debugging > 4)
    log_write(LOG_STDOUT, "nsock_loop returned %d\n", loopret);

  return 0;
}

