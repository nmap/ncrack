
/***************************************************************************
 * Target.h -- The Target class is a stripped version of the equivalent    *
 * class of Nmap. It holds information and functions mainly pertaining to  *
 * hostnames and IP addresses of the targets.                              *
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

/* $Id: Target.h 12955 2009-04-15 00:37:03Z fyodor $ */

#ifndef TARGET_H
#define TARGET_H

#include "ncrack.h"

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#include <vector>
using namespace std;


class Target {
  public: /* For now ... a lot of the data members should be made private */
    Target();
    ~Target();
    /* Recycles the object by freeing internal objects and reinitializing
       to default state */
    void Recycle();
    /* Fills a sockaddr_storage with the AF_INET or AF_INET6 address
       information of the target.  This is a preferred way to get the
       address since it is portable for IPv6 hosts.  Returns 0 for
       success. ss_len must be provided.  It is not examined, but is set
       to the size of the sockaddr copied in. */
    int TargetSockAddr(struct sockaddr_storage *ss, size_t *ss_len);
    /* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
       to sockaddr_storage */
    void setTargetSockAddr(struct sockaddr_storage *ss, size_t ss_len);
    // Returns IPv4 target host address or {0} if unavailable.
    struct in_addr v4host();
    const struct in_addr *v4hostip() const;
    /* The IPv4 or IPv6 literal string for the target host */
    const char *targetipstr() { return targetipstring; }
    /* Give the name from the last setHostName() call, which should be
       the name obtained from reverse-resolution (PTR query) of the IP (v4
       or v6).  If the name has not been set, or was set to NULL, an empty
       string ("") is returned to make printing easier. */
    const char *HostName() { return hostname? hostname : "";  }
    /* You can set to NULL to erase a name or if it failed to resolve -- or 
       just don't call this if it fails to resolve.  The hostname is blown
       away when you setTargetSockAddr(), so make sure you do these in proper
       order
       */
    void setHostName(char *name);
    /* Generates a printable string consisting of the host's IP
       address and hostname (if available).  Eg "www.insecure.org
       (64.71.184.53)" or "fe80::202:e3ff:fe14:1102".  The name is
       written into the buffer provided, which is also returned.  Results
       that do not fit in buflen will be truncated. */
    const char *NameIP(char *buf, size_t buflen);
    /* This next version returns a STATIC buffer -- so no concurrency */
    const char *NameIP();

    /* Give the name from the last setTargetName() call, which is the 
       name of the target given on the command line if it's a named
       host. */
    const char *TargetName() { return targetname; }
    /* You can set to NULL to erase a name.  The targetname is blown
       away when you setTargetSockAddr(), so make sure you do these in proper
       order
     */
    void setTargetName(const char *name);

    char *hostname; // Null if unable to resolve or unset
    /* The name of the target host given on the commmand line if it is a
     * named host */
    char *targetname;

  private:
    void Initialize();
    void FreeInternal(); // Free memory allocated inside this object
    // Creates a "presentation" formatted string out of the IPv4/IPv6 address
    void GenerateIPString();
    struct sockaddr_storage targetsock;
    size_t targetsocklen;
    char targetipstring[INET6_ADDRSTRLEN];
    char *nameIPBuf; /* for the NameIP(void) function to return */

};

#endif /* TARGET_H */
