
/***************************************************************************
 * NcrackOps.h -- The NcrackOps class contains global options, mostly      *
 * based on user-provided command-line settings.                           *
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

  saved_info() {
    user_index = 0;
    pass_index = 0;
  }
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
    FILE *logfd[LOG_NUM_FILES];
    FILE *ncrack_stdout; /* Ncrack standard output */
    char *datadir;

    nsock_proxychain proxychain; /* only assigned when --proxy is valid */
    bool socks4a; /* only true when first proxy is socks4a */
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

    bool stealthy_linear; /* true if stealty linear mode is enabled */

  private:
    struct timeval start_time;
    int addressfamily; /* Address family:  AF_INET or AF_INET6 */  
};

#endif
