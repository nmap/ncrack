
/***************************************************************************
 * NcrackOps.h -- The NcrackOps class contains global options, mostly      *
 * based on user-provided command-line settings.                           *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                *
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/
 

#ifndef NCRACK_OPS_H
#define NCRACK_OPS_H 1

#include "ncrack.h"
#include "output.h"
#include <map>
using namespace std;

/* Each service has an associated saved_info struct that holds everything
 * needed to continue the session.
 */
struct saved_info {
  uint32_t user_index;
  uint32_t pass_index;
  vector <loginpair> credentials_found;
};

class NcrackOps {
  public:
    NcrackOps();
    ~NcrackOps();

    void setaf(int af) { addressfamily = af; }
    int af() { return addressfamily; }

    /* The time this obj. was instantiated */
    const struct timeval *getStartTime() { return &start_time; }

    /* Number of milliseconds since getStartTime().  The current time is an
     * optional argument to avoid an extra gettimeofday() call. */
    long long TimeSinceStartMS(struct timeval *now=NULL); 
    
    /* The requested auto stats printing interval, or 0.0 if unset. */
    float stats_interval; 
    bool log_errors;      /* write errors to log files */
    bool append_output;   /* append output to log files */

    int userlist_src;/* 0 -> unassigned (default),
                        1 -> username list from command line (--user option)
                        2 -> username list from file (-U option)
                      */
    int passlist_src;/* 0 -> unassigned (default),
                        1 -> password list from command line (--pass option)
                        2 -> username list from file (-P option)
                      */
    bool nmap_input_normal; /* true if host input from Nmap's -oN output */
    bool nmap_input_xml;    /* true if host input from Nmap's -oX output */
    /* iterate password list for each username instead of opposite */
    bool passwords_first;
    /* choose a username and a password from the username and password lists 
     * correspondingly in pairs */
    bool pairwise;
    bool global_options;  /* true if -g has been specified */
    bool list_only;       /* only list hosts and exit */
    int timing_level;     /* timing template number: T(0-5) */
    int debugging;        /* valid for range 0-10 */
    int finish;           /* 0 -> disabled
                           * 1 -> quit each service after one credential is found
                           * 2 -> quit after any credential is found on any
                           * service
                           */
    nsock_loglevel_t nsock_loglevel;
    int verbose;
    int numhosts_scanned;
    long connection_limit;/* global maximum total connections */
    unsigned long host_timeout;
    FILE *logfd[LOG_NUM_FILES];
    FILE *ncrack_stdout; /* Ncrack standard output */
    char *datadir;

    int saved_signal;    /* save caught signal here, -1 for no signal */
    char **saved_argv;    /* pointer to current argv array */
    int saved_argc;      /* saved argument count */
    /* This associative container holds the unique id of each service and the
     * corresponding saved_info struct which holds all the necessary
     * data to continue the session from where it had been previously stopped.
     */
    bool resume;
    map<uint32_t, struct saved_info> resume_map;
    
    char *save_file;

  private:
    struct timeval start_time;
    int addressfamily; /* Address family:  AF_INET or AF_INET6 */  
};

#endif
