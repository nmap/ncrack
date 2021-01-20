
/***************************************************************************
 * services.cc -- parsing functions for command-line service and option    *
 * specification.                                                          *
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
 

#include "services.h"
#include "global_structures.h"
#include "Service.h"
#include "utils.h"
#include "NcrackOps.h"
#include <vector>

/* global supported services' lookup table from ncrak-services file */
extern vector <global_service> ServicesTable; 
extern NcrackOps o;
using namespace std;

static int check_duplicate_services(vector <service_lookup *> services,
    service_lookup *serv);
static void check_service_option(global_service *temp, char *argname,
    char *argval);
static int parse_service_argument(char *const arg, char **argname,
    char **argval);
static int check_duplicate_services(vector <service_lookup *> services,
    service_lookup *serv);
static global_service parse_services_options(char *const exp);
static int check_supported_services(service_lookup *serv);
char *port2name(char *portno);


/* 
 * Parse service/host/port/options information from target specification
 */
ts_spec
parse_services_target(char *const exp) 
{
  ts_spec temp;
  char *s, *h, *p, *o;
  size_t host_len;
  int num_colons = 0, lbrackets = 0, rbrackets = 0;

  memset(&temp, 0, sizeof(temp));

  /* Extract the service name */
  if ((s = strstr(exp, "://"))) {
      temp.service_name = Strndup(exp, s-exp);
      s += sizeof("://") - 1;
  } else {
      s = exp; /* no service name */
  }

  /* Determine if it's an IPv6 or not */
  for (h = s; *s && *s != ','; ++s) {
    if (*s == ':')
      ++num_colons;
    else if (*s == '[')
      ++lbrackets;
    else if (*s == ']')
      ++rbrackets;
  }
  if (!(lbrackets == rbrackets && lbrackets <= 1))
    fatal("Invalid number of brackets:%s", exp);

  /* Extract the host */
  if (lbrackets) { /* IPv6, potentially with a port */
    p = strchr(h, ']') + 1;
    h++;
    host_len = p-h-1;
  } else if (num_colons >= 2) { /* IPv6, no port */
    p = strchrnul(h, ',');
    host_len = p-h;
  } else { /* IPv4 or hostname, potentially with a port */
    p = strchr(h, ':');
    if (!p)
      p = strchrnul(h, ',');
    host_len = p-h;
  }
  temp.host_expr = Strndup(h, host_len);

  /* Extract the port */
  o = strchrnul(s, ',');
  if (*p == ':')
    temp.portno = Strndup(p+1, o-p-1);

  /* Extract the options */
  if (*o == ',')
    temp.service_options = strdup(o+1);

  if (!temp.service_name && !temp.portno && temp.service_options)
    fatal("You must specify either a service name or a port (or both): %s",
        exp);
  if (!temp.service_name && temp.portno) {
    if (!(temp.service_name = port2name(temp.portno)))
      temp.error = true;
  }

  return temp;
}


/*
 * Parsing for -p option
 */
void
parse_services(char *const exp, vector <service_lookup *> &services)
{
  unsigned int nports;
  char *temp, *s;
  service_lookup *serv;

  nports = 0;
  while (1) {
    if (nports == 0)
      temp = strtok(exp, ",");
    else
      temp = strtok(NULL, ",");

    if (temp == NULL)
      break;

    serv = (service_lookup *)safe_zalloc(sizeof(service_lookup));

    if (isdigit(temp[0])) { /* just port number */
      serv->portno = str2port(temp);
    } else {  /* service name and/or port number */
      if ((s = strchr(temp, ':'))) {  /* service name and port number */
        *s = '\0';
        serv->name = strdup(temp);
        serv->portno = str2port(++s);
      } else  /* service name only */
        serv->name = strdup(temp);
    } 
    nports++;

    /* check if service is supported */
    if (check_supported_services(serv))
      continue;

    /* check for duplicate services */
    if (check_duplicate_services(services, serv))
      continue;

    services.push_back(serv);
  }
}


/*
 * Parsing for -m option
 */
void
parse_module_options(char *const exp)
{
  char *name, *options;
  global_service temp;
  vector <global_service>::iterator vi;

  if (!(name = strtok(exp, ":"))) {
    error("No service name specified for option: -m %s . Ignoring...", exp);
    return;
  }
  if (!(options = strtok(NULL, ":"))) {
    error("No options specified for module: %s . Ignoring...", name);
    return;
  }

  /* retrieve struct with options specified for this module */
  temp = parse_services_options(options);

  for (vi = ServicesTable.begin(); vi != ServicesTable.end(); vi++) {
    if (!strcmp(vi->lookup.name, name))
      break;
  }
  if (vi == ServicesTable.end()) {
    error("Service with name '%s' not supported! Ignoring...", name);
    return;
  }

  /* apply any options (non-zero) to global ServicesTable */
  if (temp.timing.min_connection_limit)
    vi->timing.min_connection_limit = temp.timing.min_connection_limit;
  if (temp.timing.max_connection_limit)
    vi->timing.max_connection_limit = temp.timing.max_connection_limit;
  if (temp.timing.auth_tries)
    vi->timing.auth_tries = temp.timing.auth_tries;
  if (temp.timing.connection_delay)
    vi->timing.connection_delay = temp.timing.connection_delay;
  if (temp.timing.connection_retries)
    vi->timing.connection_retries = temp.timing.connection_retries;
  if (temp.timing.timeout)
    vi->timing.timeout = temp.timing.timeout;
  if (temp.misc.path) {
    vi->misc.path = Strndup(temp.misc.path, strlen(temp.misc.path)+1);
    free(temp.misc.path);
  }
  if (temp.misc.db) {
    vi->misc.db = Strndup(temp.misc.db, strlen(temp.misc.db)+1);
    free(temp.misc.db);
  }
  if (temp.misc.domain) {
    vi->misc.domain = Strndup(temp.misc.domain, strlen(temp.misc.domain)+1);
    free(temp.misc.domain);
  }
  if (temp.misc.ssl)
    vi->misc.ssl = temp.misc.ssl;
}



void
apply_host_options(Service *service, char *const options)
{
  global_service temp;

  /* retrieve struct with options specified for this service */
  temp = parse_services_options(options);

  /* apply any valid options to this service */
  if (temp.timing.min_connection_limit != NOT_ASSIGNED) {
    if (temp.timing.min_connection_limit > service->max_connection_limit)
      service->max_connection_limit = temp.timing.min_connection_limit;
    service->min_connection_limit = temp.timing.min_connection_limit;
  } 
  if (temp.timing.max_connection_limit != NOT_ASSIGNED) {
    if (temp.timing.max_connection_limit < service->min_connection_limit)
      service->min_connection_limit = temp.timing.max_connection_limit;    
    service->max_connection_limit = temp.timing.max_connection_limit;
  }
  if (temp.timing.auth_tries != NOT_ASSIGNED)
    service->auth_tries = temp.timing.auth_tries;
  if (temp.timing.connection_delay != NOT_ASSIGNED)
    service->connection_delay = temp.timing.connection_delay;
  if (temp.timing.connection_retries != NOT_ASSIGNED)
    service->connection_retries = temp.timing.connection_retries;
  if (temp.timing.timeout != NOT_ASSIGNED)
    service->timeout = temp.timing.timeout;
  if (temp.misc.path) {
    if (service->path)
      free(service->path);
    service->path = Strndup(temp.misc.path, strlen(temp.misc.path)+1);
    free(temp.misc.path);
  }
  if (temp.misc.db) {
    if (service->db)
      free(service->db);
    service->db = Strndup(temp.misc.db, strlen(temp.misc.db)+1);
    free(temp.misc.db);
  }
  if (temp.misc.domain) {
    if (service->domain)
      free(service->domain);
    service->domain = Strndup(temp.misc.domain, strlen(temp.misc.domain)+1);
    free(temp.misc.domain);
  }
  if (temp.misc.ssl)
    service->ssl = temp.misc.ssl;

}


int
apply_service_options(Service *service)
{
  vector <global_service>::iterator vi;

  for (vi = ServicesTable.begin(); vi != ServicesTable.end(); vi++) {
    if (!strcmp(vi->lookup.name, service->name))
      break;
  }
  if (vi == ServicesTable.end()) {
    error("Service with name '%s' not supported! Ignoring...", service->name);
    return -1;
  }
  
  if (!service->portno)
    service->portno = vi->lookup.portno;
  if (vi->timing.min_connection_limit != NOT_ASSIGNED)
    service->min_connection_limit = vi->timing.min_connection_limit;
  if (vi->timing.max_connection_limit != NOT_ASSIGNED)
    service->max_connection_limit = vi->timing.max_connection_limit;
  if (vi->timing.auth_tries != NOT_ASSIGNED)
    service->auth_tries = vi->timing.auth_tries;
  if (vi->timing.connection_delay != NOT_ASSIGNED)
    service->connection_delay = vi->timing.connection_delay;
  if (vi->timing.connection_retries != NOT_ASSIGNED)
    service->connection_retries = vi->timing.connection_retries;
  if (vi->timing.timeout != NOT_ASSIGNED)
    service->timeout = vi->timing.timeout;
  if (vi->misc.path) {
    if (service->path)
      free(service->path);
    service->path = Strndup(vi->misc.path, strlen(vi->misc.path));
  }
  if (vi->misc.db) {
    if (service->db)
      free(service->db);
    service->db = Strndup(vi->misc.db, strlen(vi->misc.db));
  }
  if (vi->misc.domain) {
    if (service->domain)
      free(service->domain);
    service->domain = Strndup(vi->misc.domain, strlen(vi->misc.domain));
  }
  if (vi->misc.ssl)
    service->ssl = vi->misc.ssl;

  return 0;
}


void
clean_spec(ts_spec *spec)
{
  if (spec->service_name) {
    free(spec->service_name);
    spec->service_name = NULL;
  }
  if (spec->host_expr) {
    free(spec->host_expr);
    spec->host_expr = NULL;
  }
  if (spec->service_options) {
    free(spec->service_options);
    spec->service_options = NULL;
  }
  if (spec->portno) {
    free(spec->portno);
    spec->portno = NULL;
  }
}


void
prepare_timing_template(timing_options *timing)
{ 
  if (!timing)
    fatal("%s invalid pointer!", __func__);

  /* Default timeout is 0 - which means no timeout */
  timing->timeout = 0;

  if (o.timing_level == 0) { /* Paranoid */
    timing->min_connection_limit = 1;
    timing->max_connection_limit = 1;
    timing->auth_tries = 1;
    timing->connection_delay = 10000; /* 10 secs */
    timing->connection_retries = 20;
    if (o.connection_limit == NOT_ASSIGNED)
      o.connection_limit = 50;
  } else if (o.timing_level == 1) { /* Sneaky */
    timing->min_connection_limit = 1;
    timing->max_connection_limit = 2;
    timing->auth_tries = 2;
    timing->connection_delay = 7500; 
    timing->connection_retries = 30;
    if (o.connection_limit == NOT_ASSIGNED)
      o.connection_limit = 150;
  } else if (o.timing_level == 2) { /* Polite */
    timing->min_connection_limit = 3;
    timing->max_connection_limit = 5;
    timing->auth_tries = 5;
    timing->connection_delay = 5000;
    timing->connection_retries = 30;
    if (o.connection_limit == NOT_ASSIGNED)
      o.connection_limit = 500;
  } else if (o.timing_level == 4) { /* Aggressive */
    timing->min_connection_limit = 10;
    timing->max_connection_limit = 150;
    timing->auth_tries = 0;
    timing->connection_delay = 0;
    timing->connection_retries = 40;
    if (o.connection_limit == NOT_ASSIGNED)
      o.connection_limit = 3000;
  } else if (o.timing_level == 5) { /* Insane */
    timing->min_connection_limit = 15;
    timing->max_connection_limit = 1000;
    timing->auth_tries = 0;
    timing->connection_delay = 0;
    timing->connection_retries = 50;
    if (o.connection_limit == NOT_ASSIGNED)
      o.connection_limit = 10000;
  } else { /* Normal */
    timing->min_connection_limit = 7;
    timing->max_connection_limit = 80;
    timing->auth_tries = 0;
    timing->connection_delay = 0;
    timing->connection_retries = 30;
    if (o.connection_limit == NOT_ASSIGNED)
      o.connection_limit = 1500;
  }
}


void
apply_timing_template(Service *service, timing_options *timing)
{
  service->min_connection_limit = timing->min_connection_limit;
  service->max_connection_limit = timing->max_connection_limit;
  service->auth_tries = timing->auth_tries;
  service->connection_delay = timing->connection_delay;
  service->connection_retries = timing->connection_retries;
  service->timeout = timing->timeout;
}




/**** Helper functions ****/


/*
 * Checks for duplicate services by looking at port number.
 */
static int
check_duplicate_services(vector <service_lookup *> services,
    service_lookup *serv)
{
  vector <service_lookup *>::iterator vi;

  for (vi = services.begin(); vi != services.end(); vi++) {
    if ((*vi)->portno == serv->portno) {
        error("Ignoring duplicate service: '%s:%hu' . Collides with "
            "'%s:%hu'", serv->name, serv->portno,
            (*vi)->name, (*vi)->portno);
      return -1;
    }
  }
  return 0;
}


/*
 * Checks if current service is supported by looking at
 * the global lookup table ServicesTable.
 * If a service name has no port, then a default is assigned.
 * If a port has no service name, then the corresponding service
 * name is assigned. Returns -1 if service is not supported.
 */
static int 
check_supported_services(service_lookup *serv)
{
  vector <global_service>::iterator vi;
  /*
   * If only port is specified make search based on port.
   * If only service OR if service:port is specified then
   * lookup based on service name.
   */
  if (!serv->name && serv->portno) {
    for (vi = ServicesTable.begin(); vi != ServicesTable.end(); vi++) {
      if (vi->lookup.portno == serv->portno) {
        serv->name = strdup(vi->lookup.name); /* assign service name */
        break;
      }
    }
    if (vi == ServicesTable.end()) {
      error("Service with default port '%hu' not supported! Ignoring..."
          "For non-default ports specify <service-name>:<non-default-port>",
          serv->portno);
      return -1;
    }
  } else if (serv->name) {
    for (vi = ServicesTable.begin(); vi != ServicesTable.end(); vi++) {
      if (!strcmp(vi->lookup.name, serv->name)) {
        if (!serv->portno) /* assign default port number */
          serv->portno = vi->lookup.portno;
        break;
      }
    }
    if (vi == ServicesTable.end()) {
      error("Service with name '%s' not supported! Ignoring...",
          serv->name);
      return -1;
    }
  } else 
    fatal("%s failed due to invalid parsing", __func__);

  serv->proto = vi->lookup.proto;  // TODO: check for UDP (duplicate etc)
  return 0;
}


/* 
 * Returns service name corresponding to the given port. It will first
 * check ServicesTable for the availability of support for the service with
 * that default port number.
 */
char *
port2name(char *port)
{
  vector <global_service>::iterator vi;
  u16 portno;
  char *name = NULL;

  if (!port)
    fatal("%s NULL port given!", __func__);

  portno = str2port(port);
  for (vi = ServicesTable.begin(); vi != ServicesTable.end(); vi++) {
    if (vi->lookup.portno == portno) {
      name = strdup(vi->lookup.name);
      break;
    }
  }
  if (vi == ServicesTable.end())
    error("Service with default port '%hu' not supported! Ignoring...", portno);
  return name;
}


/* 
 * Goes through the available options comparing them with 'argname'
 * and if it finds a match, it applies its value ('argval') into 
 * the struct 'temp'
 */
static void
check_service_option(global_service *temp, char *argname, char *argval)
{
  /* Timing options */
  if (!strcmp("cl", argname)) {
    long limit = Strtoul(argval, 1);
    if (limit < 0)
      fatal("Minimum connection limit (cl) '%ld' cannot be a negative number!",
          limit);
    if (temp->timing.max_connection_limit != NOT_ASSIGNED
        && temp->timing.max_connection_limit < limit)
      fatal("Minimum connection limit (cl) '%ld' cannot be larger than "
        "maximum connection limit (CL) '%ld'!", 
        limit, temp->timing.max_connection_limit);
    temp->timing.min_connection_limit = limit;
  } else if (!strcmp("CL", argname)) {
    long limit = Strtoul(argval, 1);
    if (limit < 0)
      fatal("Maximum connection limit (CL) '%ld' cannot be a negative number!",
          limit);
    if (temp->timing.min_connection_limit != NOT_ASSIGNED 
        && temp->timing.min_connection_limit > limit)
      fatal("Maximum connection limit (CL) '%ld' cannot be smaller than "
          "minimum connection limit (cl) '%ld'!",
          limit, temp->timing.min_connection_limit);
    temp->timing.max_connection_limit = limit;
  } else if (!strcmp("at", argname)) {
    long tries = Strtoul(argval, 1);
    if (tries < 0)
      fatal("Authentication tries (at) '%ld' cannot be a negative number!",
          tries);
    temp->timing.auth_tries = tries;
  } else if (!strcmp("cd", argname)) {
    if ((temp->timing.connection_delay = tval2msecs(argval)) < 0)
      fatal("Connection delay (cd) '%s' cannot be parsed correctly!",
          argval);
  } else if (!strcmp("cr", argname)) {
    long retries = Strtoul(argval, 1);
    if (retries < 0)
      fatal("Connection retries (cr) '%ld' cannot be a negative number!",
          retries);
    temp->timing.connection_retries = retries;
  } else if (!strcmp("to", argname)) {
    if ((temp->timing.timeout = tval2msecs(argval)) < 0)
      fatal("Timeout (to) '%s' cannot be parsed correctly!", argval);
  /* Miscalleneous options */
  } else if (!strcmp("path", argname)) {
    temp->misc.path = Strndup(argval, strlen(argval));
  } else if (!strcmp("ssl", argname)) {
    temp->misc.ssl = true;
  } else if (!strcmp("db", argname)) { 
    temp->misc.db = Strndup(argval, strlen(argval));
  } else if (!strcmp("domain", argname)) { 
    temp->misc.domain = Strndup(argval, strlen(argval));
  } else 
    error("Unknown service option: %s", argname);
}



static global_service
parse_services_options(char *const exp)
{
  char *arg, *argname, *argval;
  global_service temp;

  memset(&temp, 0, sizeof(temp));
  temp.timing.min_connection_limit = NOT_ASSIGNED;
  temp.timing.max_connection_limit = NOT_ASSIGNED;
  temp.timing.auth_tries = NOT_ASSIGNED;
  temp.timing.connection_delay = NOT_ASSIGNED;
  temp.timing.connection_retries = NOT_ASSIGNED;
  temp.timing.timeout = NOT_ASSIGNED;

  arg = argval = argname = NULL;

  /* check if we have only one option */
  if ((arg = strtok(exp, ","))) {
    if (!parse_service_argument(arg, &argname, &argval)) {
      check_service_option(&temp, argname, argval);
      if (argname) {
        free(argname);
        argname = NULL;
      }
      if (argval) {
        free(argval);
        argval = NULL;
      }
    }   
  }

  while ((arg = strtok(NULL, ","))) {
    /* Tokenize it on our own since we can't use strtok on 2 different
     * strings at the same time and strtok_r is unportable
     */
    if (!parse_service_argument(arg, &argname, &argval)) {
      check_service_option(&temp, argname, argval);
      if (argname) {
        free(argname);
        argname = NULL;
      }
      if (argval) {
        free(argval);
        argval = NULL;
      }
    }
  }
  return temp;
}



/* 
 * Helper parsing function. Will parse 'arg' which should be in form:
 * argname=argval and store strings into 'argname' and 'argval'.
 * Returns 0 for success.
 */
static int
parse_service_argument(char *const arg, char **argname, char **argval)
{
  size_t i, arg_len, argname_len, argval_len;

  i = 0;
  arg_len = strlen(arg);
  while (i < arg_len) {
    if (arg[i] == '=')
      break;
    i++;
  }
  if (i == arg_len) {
    /* Special case for ssl */
    if (!strcmp(arg, "ssl")) {
      *argname = Strndup(arg, i);
      *argval = NULL;
      return 0;
    }
    error("Invalid option argument (missing '='): %s", arg);
    return -1;
  }
  argname_len = i;
  *argname = Strndup(arg, argname_len);

  i++; /* arg[i] now points to '=' */
  while (i < arg_len) {
    if (arg[i] == '\0')
      break;
    i++;
  }
  if (i == argname_len + 1) {
    error("No value specified for option %s", *argname);
    free(*argname);
    argname = NULL;
    return -1;
  }
  /* allocate i - name_len - 1('=') */
  argval_len = i - argname_len - 1;
  *argval = Strndup(&arg[i - argval_len], argval_len);

  return 0;
}

