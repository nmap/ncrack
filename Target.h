
/***************************************************************************
 * Target.h -- The Target class is a stripped version of the equivalent    *
 * class of Nmap. It holds information and functions mainly pertaining to  *
 * hostnames and IP addresses of the targets.                              *
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
