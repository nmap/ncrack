
/***************************************************************************
 * output.cc -- Handles the Ncrack output system.  This currently involves *
 * console-style human readable output and XML output                      *
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


#include "output.h"
#include "NcrackOps.h"
#include "ncrack_error.h"
#include "xml.h"

extern NcrackOps o;
static const char *logtypes[LOG_NUM_FILES]=LOG_NAMES;


void
memprint(const char *addr, size_t bytes)
{
  size_t i;
  for (i = 0; i < bytes; i++) {
    log_write(LOG_STDOUT, "%c", addr[i]);
  }
  fflush(stdout);
}



/* Write some information (printf style args) to the given log stream(s).
   Remember to watch out for format string bugs.  */
void
log_write(int logt, const char *fmt, ...)
{
  va_list ap;
  assert(logt > 0);

  if (!fmt || !*fmt)
    return;

  for (int l = 1; l <= LOG_MAX; l <<= 1) {
    if (logt & l) {
      va_start(ap, fmt);
      log_vwrite(l, fmt, ap);
      va_end(ap);
    }
  }
  return;
}



/* This is the workhorse of the logging functions.  Usually it is
   called through log_write(), but it can be called directly if you
   are dealing with a vfprintf-style va_list.  Unlike log_write, YOU
   CAN ONLY CALL THIS WITH ONE LOG TYPE (not a bitmask full of them).
   In addition, YOU MUST SANDWHICH EACH EXECUTION IF THIS CALL BETWEEN
   va_start() AND va_end() calls. */
void
log_vwrite(int logt, const char *fmt, va_list ap) {
  static char *writebuf = NULL;
  static int writebuflen = 8192;
  int rc = 0;
  int len;
  int fileidx = 0;
  int l;
  va_list apcopy;


  if (!writebuf)
    writebuf = (char *) safe_malloc(writebuflen);


  switch(logt) {
    case LOG_STDOUT: 
      vfprintf(o.ncrack_stdout, fmt, ap);
      break;

    case LOG_STDERR: 
      fflush(stdout); // Otherwise some systems will print stderr out of order
      vfprintf(stderr, fmt, ap);
      break;

    case LOG_NORMAL:
    case LOG_XML:
#ifdef WIN32
      apcopy = ap;
#else
      va_copy(apcopy, ap); /* Needed in case we need to do a second vsnprintf */
#endif
      l = logt;
      fileidx = 0;
      while ((l&1)==0) { fileidx++; l>>=1; }
      assert(fileidx < LOG_NUM_FILES);
      if (o.logfd[fileidx]) {
        len = Vsnprintf(writebuf, writebuflen, fmt, ap);
        if (len == 0) {
          va_end(apcopy);
          return;
        } else if (len < 0 || len >= writebuflen) {
          /* Didn't have enough space.  Expand writebuf and try again */
          if (len >= writebuflen) {
            writebuflen = len + 1024;
          } else {
            /* Windows seems to just give -1 rather than the amount of space we 
               would need.  So lets just gulp up a huge amount in the hope it
               will be enough */
            writebuflen *= 150;
          }
          writebuf = (char *) safe_realloc(writebuf, writebuflen);
          len = Vsnprintf(writebuf, writebuflen, fmt, apcopy);
          if (len <= 0 || len >= writebuflen) {
            fatal("%s: vsnprintf failed.  Even after increasing bufferlen "
                "to %d, Vsnprintf returned %d (logt == %d). "
                "Please email this message to fyodor@insecure.org.",
                __func__, writebuflen, len, logt);
          }
        }
        rc = fwrite(writebuf,len,1,o.logfd[fileidx]);
        if (rc != 1) {
          fatal("Failed to write %d bytes of data to (logt==%d) stream. "
              "fwrite returned %d.", len, logt, rc);
        }
        va_end(apcopy);
      }
      break;

    default:
      fatal("%s(): Passed unknown log type (%d).  Note that this function, "
          "unlike log_write, can only "
          "handle one log type at a time (no bitmasks)", __func__, logt);
  }

  return;
}


/* Close the given log stream(s) */
void
log_close(int logt)
{
  int i;
  if (logt<0 || logt>LOG_FILE_MASK) return;
  for (i=0;logt;logt>>=1,i++) if (o.logfd[i] && (logt&1)) fclose(o.logfd[i]);
}

/* Flush the given log stream(s).  In other words, all buffered output
   is written to the log immediately */
void
log_flush(int logt) {
  int i;

  if (logt & LOG_STDOUT) {
    fflush(o.ncrack_stdout);
    logt -= LOG_STDOUT;
  }

  if (logt & LOG_STDERR) {
    fflush(stderr);
    logt -= LOG_STDERR;
  }


  if (logt<0 || logt>LOG_FILE_MASK) return;

  for (i=0;logt;logt>>=1,i++)
  {
    if (!o.logfd[i] || !(logt&1)) continue;
    fflush(o.logfd[i]);
  }

}

/* Flush every single log stream -- all buffered output is written to the
   corresponding logs immediately */
void
log_flush_all() {
  int fileno;

  for(fileno = 0; fileno < LOG_NUM_FILES; fileno++) {
    if (o.logfd[fileno]) fflush(o.logfd[fileno]);
  }
  fflush(stdout);
  fflush(stderr);
}


/* Open a log descriptor of the type given to the filename given.  If 
   o.append_output is nonzero, the file will be appended instead of clobbered if
   it already exists.  If the file does not exist, it will be created */
int
log_open(int logt, char *filename)
{
  int i=0;
  if (logt<=0 || logt>LOG_FILE_MASK) return -1;
  while ((logt&1)==0) { i++; logt>>=1; }
  if (o.logfd[i]) fatal("Only one %s output filename allowed",logtypes[i]);
  if (*filename == '-' && *(filename + 1) == '\0')
  {
    o.logfd[i]=stdout;
    o.ncrack_stdout = fopen(DEVNULL, "w");
    if (!o.ncrack_stdout)
      fatal("Could not assign %s to stdout for writing", DEVNULL);
  }
  else
  {
    if (o.append_output)
      o.logfd[i] = fopen(filename, "a");
    else
      o.logfd[i] = fopen(filename, "w");
    if (!o.logfd[i])
      fatal("Failed to open %s output file %s for writing", logtypes[i],
          filename);
  }
  return 1;
}


char *
logfilename(const char *str, struct tm *tm)
{
  char *ret, *end, *p;
  char tbuf[10];
  int retlen = strlen(str) * 6 + 1;

  ret = (char *) safe_malloc(retlen);
  end = ret + retlen;

  for (p = ret; *str; str++) {
    if (*str == '%') {
      str++;

      if (!*str)
        break;

      switch (*str) {
        case 'H':
          strftime(tbuf, sizeof tbuf, "%H", tm);
          break;
        case 'M':
          strftime(tbuf, sizeof tbuf, "%M", tm);
          break;
        case 'S':
          strftime(tbuf, sizeof tbuf, "%S", tm);
          break;
        case 'T':
          strftime(tbuf, sizeof tbuf, "%H%M%S", tm);
          break;
        case 'R':
          strftime(tbuf, sizeof tbuf, "%H%M", tm);
          break;
        case 'm':
          strftime(tbuf, sizeof tbuf, "%m", tm);
          break;
        case 'd': 
          strftime(tbuf, sizeof tbuf, "%d", tm);
          break;
        case 'y': 
          strftime(tbuf, sizeof tbuf, "%y", tm);
          break;
        case 'Y': 
          strftime(tbuf, sizeof tbuf, "%Y", tm);
          break;
        case 'D': 
          strftime(tbuf, sizeof tbuf, "%m%d%y", tm);
          break;
        default:
          *p++ = *str;
          continue;
      }

      assert(end - p > 1);
      Strncpy(p, tbuf, end - p - 1);
      p += strlen(tbuf);
    } else {
      *p++ = *str;
    }
  }

  *p = 0;

  return (char *) safe_realloc(ret, strlen(ret) + 1);
}


static std::string quote(const char *s) {
  std::string result("");
  const char *p;
  bool space;

  space = false;
  for (p = s; *p != '\0'; p++) {
    if (isspace(*p))
      space = true;
    if (*p == '"' || *p == '\\')
      result += "\\";
    result += *p;
  }

  if (space)
    result = "\"" + result + "\"";

  return result;
}


/* Return a std::string containing all n strings separated by whitespace, and
   individually quoted if needed. */
std::string join_quoted(const char * const strings[], unsigned int n) {
  std::string result("");
  unsigned int i;

  for (i = 0; i < n; i++) {
    if (i > 0)
      result += " ";
    result += quote(strings[i]);
  }

  return result;
}


/* prints current status */
void
printStatusMessage(ServiceGroup *SG)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  long long time = (long long) (o.TimeSinceStartMS(&tv) / 1000.0);

  log_write(LOG_STDOUT, 
      "Stats: %lld:%02lld:%02lld elapsed; %lu services completed "
      "(%lu total)\n", 
      time/60/60, time/60 % 60, time % 60,
      (long unsigned) SG->services_finished.size(), SG->total_services);
  log_write(LOG_STDOUT, "Rate: %.2f; Found: %lu; ",
      SG->auth_rate_meter.getCurrentRate(), SG->credentials_found);
  SG->SPM->printStats(SG->getCompletionFraction(), &tv);
  if (SG->credentials_found)
    log_write(LOG_STDOUT, "(press 'p' to list discovered credentials)\n");
}


/* Prints all credentials found so far */
void
print_creds(ServiceGroup *SG)
{
  list <Service *>::iterator li;

  for (li = SG->services_all.begin(); li != SG->services_all.end(); li++) {
    if ((*li)->credentials_found.size() != 0)
      print_service_output(*li);
  }
}


void
print_service_output(Service *serv)
{
  vector <loginpair>::iterator vi;
  const char *ip = serv->target->NameIP();

  log_write(LOG_PLAIN, "Discovered credentials for %s on %s ",
      serv->name, ip);
  if (strncmp(serv->target->HostName(), "", 1))
    log_write(LOG_PLAIN, "(%s) ", serv->target->HostName());
  log_write(LOG_PLAIN, "%hu/%s:\n", serv->portno, proto2str(serv->proto));
  for (vi = serv->credentials_found.begin();
      vi != serv->credentials_found.end(); vi++) {
    log_write(LOG_PLAIN, "%s %hu/%s %s: '%s' '%s'\n",
        ip, serv->portno, proto2str(serv->proto), serv->name,
        vi->user, vi->pass);
    xml_open_start_tag("credentials");
    xml_attribute("username", "%s", vi->user);
    xml_attribute("password", "%s", vi->pass);
    xml_close_start_tag();
    xml_end_tag();
    xml_newline();
  }
}


void
print_final_output(ServiceGroup *SG)
{
  time_t now;
  char mytime[128];
  long long whole_t = 0, dec_t = 0;
  int err;

  /* Workaround for default rounding-up that is done when printing a .2f float.
   * Previously with a variable e.g 20999, printf (".2f", var/1000.0) would
   * show it as 21.00, something which isn't right. 
   */
  dec_t = whole_t = o.TimeSinceStartMS(NULL);
  if (whole_t)
    whole_t /= 1000;
  dec_t %= 1000;
  if (dec_t)
    dec_t /= 10;

  now = time(NULL);
  err = n_ctime(mytime, sizeof(mytime), &now);
  if (err) {
    fatal("n_ctime failed: %s", strerror(err));
  }
  chomp(mytime);
  
  if (o.list_only) 
    log_write(LOG_STDOUT, "\nNcrack done: %lu %s would be scanned.\n",
        SG->total_services, (SG->total_services == 1)? "service" : "services");
  else {
    log_write(LOG_STDOUT, "\nNcrack done: %lu %s scanned in %lld.%02lld "
        "seconds.\n", SG->total_services, (SG->total_services == 1)? "service"
        : "services", whole_t, dec_t);
    log_write(LOG_NORMAL, "\n# Ncrack done at %s -- %lu %s scanned in "
        "%lld.%02lld seconds.\n", mytime, SG->total_services,
        (SG->total_services == 1)? "service" : "services", whole_t, dec_t);
  }


  if (o.verbose)
    log_write(LOG_PLAIN, "Probes sent: %lu | timed-out: %lu |"
        " prematurely-closed: %lu\n", SG->connections_total,
        SG->connections_timedout, SG->connections_closed);

  xml_end_tag(); /* ncrackrun */
  xml_newline();
  log_flush_all();
}


