
/***************************************************************************
 * targets.cc -- Functions related to determining the exact IPs to hit     *
 * based on CIDR and other input formats and handling the exclude-file     *
 * option. nexthost function is tailored to Ncrack's needs that avoids     *
 * using HostGroups.                                                       *
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

/* $Id: targets.cc 12955 2009-04-15 00:37:03Z fyodor $ */


#include "ncrack.h"
#include "targets.h"
#include "TargetGroup.h"
#include "Service.h"
#include "Target.h"
#include "NcrackOps.h"
#include "utils.h"

extern NcrackOps o;
using namespace std;

/* Gets the host number (index) of target in the hostbatch array of
   pointers.  Note that the target MUST EXIST in the array or all
   heck will break loose. */
static inline int gethostnum(Target *hostbatch[], Target *target) {
  int i = 0;
  do {
    if (hostbatch[i] == target)
      return i;
  } while(++i);

  fatal("fluxx0red");
  return 0; // Unreached
}



/* Is the host passed as Target to be excluded, much of this logic had  (mdmcl)
 * to be rewritten from wam's original code to allow for the objects */
static int hostInExclude(struct sockaddr *checksock, size_t checksocklen, 
    TargetGroup *exclude_group) {
  unsigned long tmpTarget; /* ip we examine */
  int i=0;                 /* a simple index */
  char targets_type;       /* what is the address type of the Target Group */
  struct sockaddr_storage ss; 
  struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
  size_t slen;             /* needed for funct but not used */
  unsigned long mask = 0;  /* our trusty netmask, which we convert to nbo */
  struct sockaddr_in *checkhost;

  if ((TargetGroup *)0 == exclude_group)
    return 0;

  assert(checksocklen >= sizeof(struct sockaddr_in));
  checkhost = (struct sockaddr_in *) checksock;
  if (checkhost->sin_family != AF_INET)
    checkhost = NULL;

  /* First find out what type of addresses are in the target group */
  targets_type = exclude_group[i].get_targets_type();

  /* Lets go through the targets until we reach our uninitialized placeholder */
  while (exclude_group[i].get_targets_type() != TargetGroup::TYPE_NONE)
  { 
    /* while there are still hosts in the target group */
    while (exclude_group[i].get_next_host(&ss, &slen) == 0) {
      tmpTarget = sin->sin_addr.s_addr; 

      /* For Netmasks simply compare the network bits and move to the next
       * group if it does not compare, we don't care about the individual addrs */
      if (targets_type == TargetGroup::IPV4_NETMASK) {
        mask = htonl((unsigned long) (0-1) << (32-exclude_group[i].get_mask()));
        if ((tmpTarget & mask) == (checkhost->sin_addr.s_addr & mask)) {
          exclude_group[i].rewind();
          return 1;
        }
        else {
          break;
        }
      } 
      /* For ranges we need to be a little more slick, if we don't find a match
       * we should skip the rest of the addrs in the octet, thank wam for this
       * optimization */
      else if (targets_type == TargetGroup::IPV4_RANGES) {
        if (tmpTarget == checkhost->sin_addr.s_addr) {
          exclude_group[i].rewind();
          return 1;
        }
        else { /* note these are in network byte order */
          if ((tmpTarget & 0x000000ff) != (checkhost->sin_addr.s_addr & 0x000000ff))
            exclude_group[i].skip_range(TargetGroup::FIRST_OCTET); 
          else if ((tmpTarget & 0x0000ff00) != (checkhost->sin_addr.s_addr & 0x0000ff00))
            exclude_group[i].skip_range(TargetGroup::SECOND_OCTET); 
          else if ((tmpTarget & 0x00ff0000) != (checkhost->sin_addr.s_addr & 0x00ff0000))
            exclude_group[i].skip_range(TargetGroup::THIRD_OCTET); 

          continue;
        }
      }
#if HAVE_IPV6
      else if (targets_type == TargetGroup::IPV6_ADDRESS) {
        fatal("exclude file not supported for IPV6 -- If it is important to you, send a mail to fyodor@insecure.org so I can gauge support\n");
      }
#endif
    }
    exclude_group[i++].rewind();
  }

  /* we did not find the host */
  return 0;
}

/* loads an exclude file into an exclude target list  (mdmcl) */
TargetGroup* load_exclude(FILE *fExclude, char *szExclude) {
  int i=0;      /* loop counter */
  int iLine=0;      /* line count */
  int iListSz=0;    /* size of our exclude target list. 
                     * It doubles in size as it gets
                     *  close to filling up
                     */
  char acBuf[512];
  char *p_acBuf;
  TargetGroup *excludelist; /* list of ptrs to excluded targets */
  char *pc;     /* the split out exclude expressions */
  char b_file = (char)0;        /* flag to indicate if we are using a file */

  /* If there are no params return now with a NULL list */
  if (((FILE *)0 == fExclude) && ((char *)0 == szExclude)) {
    excludelist=NULL;
    return excludelist;
  }

  if ((FILE *)0 != fExclude)
    b_file = (char)1;

  /* Since I don't know of a realloc equiv in C++, we will just count
   * the number of elements here. */

  /* If the input was given to us in a file, count the number of elements
   * in the file, and reset the file */
  if (1 == b_file) {
    while ((char *)0 != fgets(acBuf,sizeof(acBuf), fExclude)) {
      /* the last line can contain no newline, then we have to check for EOF */
      if ((char *)0 == strchr(acBuf, '\n') && !feof(fExclude)) {
        fatal("Exclude file line %d was too long to read.  Exiting.", iLine);
      }
      pc=strtok(acBuf, "\t\n ");  
      while (NULL != pc) {
        iListSz++;
        pc=strtok(NULL, "\t\n ");
      }
    }
    rewind(fExclude);
  } /* If the exclude file was provided via command line, count the elements here */
  else {
    p_acBuf=strdup(szExclude);
    pc=strtok(p_acBuf, ",");
    while (NULL != pc) {
      iListSz++;
      pc=strtok(NULL, ",");
    }
    free(p_acBuf);
    p_acBuf = NULL;
  }

  /* allocate enough TargetGroups to cover our entries, plus one that
   * remains uninitialized so we know we reached the end */
  excludelist = new TargetGroup[iListSz + 1];

  /* don't use a for loop since the counter isn't incremented if the 
   * exclude entry isn't parsed
   */
  i=0;
  if (1 == b_file) {
    /* If we are parsing a file load the exclude list from that */
    while ((char *)0 != fgets(acBuf, sizeof(acBuf), fExclude)) {
      ++iLine;
      if ((char *)0 == strchr(acBuf, '\n') && !feof(fExclude)) {
        fatal("Exclude file line %d was too long to read.  Exiting.", iLine);
      }

      pc=strtok(acBuf, "\t\n ");  

      while ((char *)0 != pc) {
        if(excludelist[i].parse_expr(pc,o.af()) == 0) {
          if (o.debugging > 1)
            error("Loaded exclude target of: %s", pc);
          ++i;
        } 
        pc=strtok(NULL, "\t\n ");
      }
    }
  }
  else {
    /* If we are parsing command line, load the exclude file from the string */
    p_acBuf=strdup(szExclude);
    pc=strtok(p_acBuf, ",");

    while (NULL != pc) {
      if(excludelist[i].parse_expr(pc,o.af()) == 0) {
        if (o.debugging >1)
          error("Loaded exclude target of: %s", pc);
        ++i;
      } 

      /* This is a totally cheezy hack, but since I can't use strtok_r...
       * If you can think of a better way to do this, feel free to change.
       * As for now, we will reset strtok each time we leave parse_expr */
      {
        int hack_i;
        char *hack_c = strdup(szExclude);

        pc=strtok(hack_c, ",");

        for (hack_i = 0; hack_i < i; hack_i++) 
          pc=strtok(NULL, ",");

        free(hack_c);
      }
    } 
  }
  return excludelist;
}

/* A debug routine to dump some information to stdout.                  (mdmcl)
 * Invoked if debugging is set to 3 or higher
 * I had to make signigicant changes from wam's code. Although wam
 * displayed much more detail, alot of this is now hidden inside
 * of the Target Group Object. Rather than writing a bunch of methods
 * to return private attributes, which would only be used for 
 * debugging, I went for the method below.
 */
int dumpExclude(TargetGroup *exclude_group) {
  int i=0, debug_save=0, type=TargetGroup::TYPE_NONE;
  unsigned int mask = 0;
  struct sockaddr_storage ss;
  struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
  size_t slen;

  /* shut off debugging for now, this is a debug routine in itself,
   * we don't want to see all the debug messages inside of the object */
  debug_save = o.debugging;
  o.debugging = 0;

  while ((type = exclude_group[i].get_targets_type()) != TargetGroup::TYPE_NONE)
  {
    switch (type) {
      case TargetGroup::IPV4_NETMASK:
        exclude_group[i].get_next_host(&ss, &slen);
        mask = exclude_group[i].get_mask();
        error("exclude host group %d is %s/%d\n", i, inet_ntoa(sin->sin_addr), mask);
        break;

      case TargetGroup::IPV4_RANGES:
        while (exclude_group[i].get_next_host(&ss, &slen) == 0) 
          error("exclude host group %d is %s\n", i, inet_ntoa(sin->sin_addr));
        break;

      case TargetGroup::IPV6_ADDRESS:
        fatal("IPV6 addresses are not supported in the exclude file\n");
        break;

      default:
        fatal("Unknown target type in exclude file.\n");
    }
    exclude_group[i++].rewind();
  }

  /* return debugging to what it was */
  o.debugging = debug_save; 
  return 1;
}



Target *
nexthost(const char *expr, TargetGroup *exclude_group)
{
  struct sockaddr_storage ss;
  size_t sslen;
  Target *host;
  static TargetGroup group;
  static bool newexp = true; /* true for new expression */

  if (newexp) {
    group = TargetGroup();
    group.parse_expr(expr, o.af());
    newexp = false;
  }

  /* Skip any hosts the user asked to exclude */
  do { 
    if (group.get_next_host(&ss, &sslen)) {  /* no more targets */
      newexp = true;
      return NULL;
    }
  } while (hostInExclude((struct sockaddr *)&ss, sslen, exclude_group));

  host = new Target();
  host->setTargetSockAddr(&ss, sslen);

  /* put target expression in target if we have a named host without netmask */
  if (group.get_targets_type() == TargetGroup::IPV4_NETMASK  &&
      group.get_namedhost() && !strchr(expr, '/' )) {
    host->setTargetName(expr);
  }

  return host;
}

