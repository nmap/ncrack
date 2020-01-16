
/***************************************************************************
 * TargetGroup.cc -- The "TargetGroup" class holds a group of IP addresses,*
 * such as those from a '/16' or '10.*.*.*' specification. It is a         *
 * stripped version of the equivalent class of Nmap.                       *
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

/* $Id: TargetGroup.cc 12955 2009-04-15 00:37:03Z fyodor $ */

#include "NcrackOps.h"
#include "TargetGroup.h"
#include "utils.h"

extern NcrackOps o;


TargetGroup::TargetGroup() {
  Initialize();
}

// Bring back (or start with) original state
void TargetGroup::Initialize() {
  targets_type = TYPE_NONE;
  memset(addresses, 0, sizeof(addresses));
  memset(current, 0, sizeof(current));
  memset(last, 0, sizeof(last));
  ipsleft = 0;
}

/* take the object back to the beginning without  (mdmcl)
 * reinitalizing the data structures */  
int TargetGroup::rewind() {

  /* For netmasks we must set the current address to the
   * starting address and calculate the ips by distance */
  if (targets_type == IPV4_NETMASK) {
    currentaddr = startaddr;
    if (startaddr.s_addr <= endaddr.s_addr) { 
      ipsleft = ((unsigned long long) (endaddr.s_addr - startaddr.s_addr)) + 1;
      return 0; 
    }
    else
      assert(0);
  }
  /* For ranges, we easily set current to zero and calculate
   * the ips by the number of values in the columns */
  else if (targets_type == IPV4_RANGES) {
    memset((char *)current, 0, sizeof(current));
    ipsleft = (unsigned long long) (last[0] + 1) *
      (unsigned long long) (last[1] + 1) *
      (unsigned long long) (last[2] + 1) *
      (unsigned long long) (last[3] + 1);
    return 0;
  }
#if HAVE_IPV6
  /* For IPV6 there is only one address, this function doesn't
   * make much sence for IPv6 does it? */
  else if (targets_type == IPV6_ADDRESS) {
    ipsleft = 1;
    return 0;
  }
#endif 

  /* If we got this far there must be an error, wrong type */
  return -1;
}



/* Initializes (or reinitializes) the object with a new expression, such
   as 192.168.0.0/16 , 10.1.0-5.1-254 , or fe80::202:e3ff:fe14:1102 .  
   Returns 0 for success */  
int TargetGroup::parse_expr(const char * const target_expr, int af) {

  int i=0,j=0,k=0;
  int start, end;
  char *r,*s, *target_net;
  char *addy[5];
  char *hostexp = strdup(target_expr);
  struct hostent *target;
  namedhost = 0;



  if (targets_type != TYPE_NONE)
    Initialize();
  ipsleft = 0;

  if (af == AF_INET) {

    /* separate service specification from host */
    if ((s = strchr(hostexp, '[')) || (s = strstr(hostexp, "::")) || (s = strstr(hostexp, "://")))
      *s = '\0';

    s = NULL;

    if (strchr(hostexp, ':'))
      fatal("Invalid host expression: %s -- colons only allowed in IPv6 addresses, and then you need the -6 switch", hostexp);


    /*struct in_addr current_in;*/
    addy[0] = addy[1] = addy[2] = addy[3] = addy[4] = NULL;
    addy[0] = r = hostexp;
    /* First we break the expression up into the four parts of the IP address
       + the optional '/mask' */
    target_net = hostexp;
    s = strchr(hostexp, '/'); /* Find the slash if there is one */
    if (s) {
      *s = '\0';  /* Make sure target_net is terminated before the /## */
      s++; /* Point s at the netmask */
    }
    netmask  = ( s ) ? atoi(s) : 32;
    if ((int) netmask < 0 || netmask > 32) {
      error("Illegal netmask value (%d), must be /0 - /32 . Assuming /32 (one host)", netmask);
      netmask = 32;
    }
    for(i=0; *(hostexp + i); i++) 
      if (isupper((int) *(hostexp +i)) || islower((int) *(hostexp +i))) {
        namedhost = 1;
        break;
      }
    if (netmask != 32 || namedhost) {
      targets_type = IPV4_NETMASK;
      if (!inet_pton(AF_INET, target_net, &(startaddr))) {
        if ((target = gethostbyname(target_net))) {
          int count=0;

          memcpy(&(startaddr), target->h_addr_list[0], sizeof(struct in_addr));

          while (target->h_addr_list[count]) count++;

          if (count > 1)
            error("Warning: Hostname %s resolves to %d IPs. Using %s.", 
                target_net, count, inet_ntoa(*((struct in_addr *)target->h_addr_list[0])));
        } else {
          error("Failed to resolve given hostname/IP: %s. "
              "Note that you can't use '/mask' AND '1-4,7,100-' style IP ranges", target_net);
          free(hostexp);
          return 1;
        }
      } 
      if (netmask) {
        unsigned long longtmp = ntohl(startaddr.s_addr);
        startaddr.s_addr = longtmp & (unsigned long) (0 - (1<<(32 - netmask)));
        endaddr.s_addr = longtmp | (unsigned long)  ((1<<(32 - netmask)) - 1);
      } else {
        /* The above calculations don't work for a /0 netmask, though at first
         * glance it appears that they would
         */
        startaddr.s_addr = 0;
        endaddr.s_addr = 0xffffffff;
      }
      currentaddr = startaddr;
      if (startaddr.s_addr <= endaddr.s_addr) { 
        ipsleft = ((unsigned long long) (endaddr.s_addr - startaddr.s_addr)) + 1;
        free(hostexp); 
        return 0; 
      }
      error("Host specification invalid");
      free(hostexp);
      return 1;
    }
    else {
      targets_type = IPV4_RANGES;
      i = 0;

      while(*++r) {
        if (*r == '.' && ++i < 4) {
          *r = '\0';
          addy[i] = r + 1;
        }
        else if (*r != '*' && *r != ',' && *r != '-' && !isdigit((int)*r)) 
          fatal("Invalid character in  host specification.  Note in particular that square brackets [] are no longer allowed. "
              "They were redundant and can simply be removed.");
      }
      if (i != 3) fatal("Invalid target host specification: %s", target_expr);

      for (i = 0; i < 4; i++) {
        j=0;
        do {
          s = strchr(addy[i],',');
          if (s) 
            *s = '\0';
          if (*addy[i] == '*') {
            start = 0;
            end = 255;
          } else if (*addy[i] == '-') {
            start = 0;
            if (*(addy[i] + 1) == '\0')
              end = 255;
            else 
              end = atoi(addy[i]+ 1);
          } else {
            start = end = atoi(addy[i]);
            if ((r = strchr(addy[i],'-')) && *(r+1) )
              end = atoi(r + 1);
            else if (r && !*(r+1))
              end = 255;
          }

          if (start < 0 || start > end || start > 255 || end > 255)
            fatal("Your host specifications are illegal!");
          if (j + (end - start) > 255) 
            fatal("Your host specifications are illegal!");

          for (k = start; k <= end; k++)
            addresses[i][j++] = k;

          last[i] = j - 1;
          if (s) 
            addy[i] = s + 1;
        } while (s);
      }
    }
    memset((char *)current, 0, sizeof(current));
    ipsleft = (unsigned long long) (last[0] + 1) *
      (unsigned long long) (last[1] + 1) *
      (unsigned long long) (last[2] + 1) *
      (unsigned long long) (last[3] + 1);
  }
  else {
#if HAVE_IPV6
    int rc = 0;
    assert(af == AF_INET6);
    if (strchr(hostexp, '/')) {
      fatal("Invalid host expression: %s -- slash not allowed.  IPv6 addresses can currently only be specified individually", hostexp);
    }
    targets_type = IPV6_ADDRESS;
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET6;
    rc = getaddrinfo(hostexp, NULL, &hints, &result);
    if (rc != 0 || result == NULL) {
      error("Failed to resolve given IPv6 hostname/IP: %s.  Note that you can't use '/mask' or '[1-4,7,100-]' style ranges for IPv6.  Error code %d: %s", hostexp, rc, gai_strerror(rc));
      free(hostexp);
      if (result) freeaddrinfo(result);
      return 1;
    }
    assert(result->ai_addrlen == sizeof(struct sockaddr_in6));
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) result->ai_addr;
    memcpy(&ip6, sin6, sizeof(struct sockaddr_in6));
    ipsleft = 1;
    freeaddrinfo(result);
#else // HAVE_IPV6
    fatal("IPv6 not supported on your platform");
#endif // HAVE_IPV6
  }

  free(hostexp);
  return 0;
}

/* For ranges, skip all hosts in an octet,                  (mdmcl)
 * get_next_host should be used for skipping the last octet :-) 
 * returns: number of hosts skipped */
int TargetGroup::skip_range(_octet_nums octet) {
  unsigned long hosts_skipped = 0, /* number of hosts skipped */
                oct = 0;           /* octect number */
  int i = 0;                 /* simple lcv */

  /* This function is only supported for RANGES! */
  if (targets_type != IPV4_RANGES)
    return -1;

  switch (octet) {
    case FIRST_OCTET:
      oct = 0;
      hosts_skipped = (unsigned long)(last[1] + 1) * (unsigned long)(last[2] + 1) * (unsigned long)(last[3] + 1);
      break;
    case SECOND_OCTET:
      oct = 1;
      hosts_skipped = (unsigned long)(last[2] + 1) * (unsigned long)(last[3] + 1);
      break;
    case THIRD_OCTET:
      oct = 2;
      hosts_skipped = (last[3] + 1);
      break;
    default:  /* Hmm, how'd you do that */
      return -1;
  }

  /* catch if we try to take more than are left */
  assert(ipsleft + 1>= hosts_skipped);

  /* increment the next octect that we can above us */
  for (i = oct; i >= 0; i--) {
    if (current[i] < last[i]) {
      current[i]++;
      break;
    }
    else
      current[i] = 0;
  }

  /* reset all the ones below us to zero */
  for (i = oct+1; i <= 3; i++) {
    current[i] = 0;
  }

  /* we actually don't skip the current, it was accounted for 
   * by get_next_host */
  ipsleft -= hosts_skipped - 1;

  return hosts_skipped;
}

/* Grab the next host from this expression (if any) and updates its internal
   state to reflect that the IP was given out.  Returns 0 and
   fills in ss if successful.  ss must point to a pre-allocated
   sockaddr_storage structure */
int TargetGroup::get_next_host(struct sockaddr_storage *ss, size_t *sslen) {

  int octet;
  struct sockaddr_in *sin = (struct sockaddr_in *) ss;
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) ss;
//startover: /* to handle nmap --resume where I have already
  //            scanned many of the IPs */  
  assert(ss);
  assert(sslen);


  if (ipsleft == 0)
    return -1;

  if (targets_type == IPV4_NETMASK) {
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    *sslen = sizeof(struct sockaddr_in);
#if HAVE_SOCKADDR_SA_LEN
    sin->sin_len = *sslen;
#endif

    if (currentaddr.s_addr <= endaddr.s_addr) {
      sin->sin_addr.s_addr = htonl(currentaddr.s_addr++);
    } else {
      error("Bogus target structure passed to %s", __func__);
      ipsleft = 0;
      return -1;
    }
  }
  else if (targets_type == IPV4_RANGES) {
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    *sslen = sizeof(struct sockaddr_in);

#if HAVE_SOCKADDR_SA_LEN
    sin->sin_len = *sslen;
#endif

    /* Set the IP to the current value of everything */
    sin->sin_addr.s_addr = htonl(addresses[0][current[0]] << 24 | 
        addresses[1][current[1]] << 16 |
        addresses[2][current[2]] << 8 | 
        addresses[3][current[3]]);

    /* Now we nudge up to the next IP */
    for(octet = 3; octet >= 0; octet--) {
      if (current[octet] < last[octet]) {
        /* OK, this is the column I have room to nudge upwards */
        current[octet]++;
        break;
      } else {
        /* This octet is finished so I reset it to the beginning */
        current[octet] = 0;
      }
    }
    if (octet == -1) {
      /* It didn't find anything to bump up, I must have taken the last IP */
      assert(ipsleft == 1);
      /* So I set current to last with the very final octet up one ... */
      /* Note that this may make current[3] == 256 */
      current[0] = last[0]; current[1] = last[1];
      current[2] = last[2]; current[3] = last[3] + 1;
    } else {
      assert(ipsleft > 1); /* There must be at least one more IP left */
    }
  } else {
    assert(targets_type == IPV6_ADDRESS);
    assert(ipsleft == 1);
#if HAVE_IPV6
    *sslen = sizeof(struct sockaddr_in6);
    memset(sin6, 0, *sslen);
    sin6->sin6_family = AF_INET6;
#ifdef SIN_LEN
    sin6->sin6_len = *sslen;
#endif /* SIN_LEN */
    memcpy(sin6->sin6_addr.s6_addr, ip6.sin6_addr.s6_addr, 16);
    sin6->sin6_scope_id = ip6.sin6_scope_id;
#else
    fatal("IPV6 not supported on this platform");
#endif // HAVE_IPV6
  }
  ipsleft--;

  return 0;
}

/* Returns the last given host, so that it will be given again next
   time get_next_host is called.  Obviously, you should only call
   this if you have fetched at least 1 host since parse_expr() was
   called */
int TargetGroup::return_last_host() {
  int octet;

  ipsleft++;
  if (targets_type == IPV4_NETMASK) {
    assert(currentaddr.s_addr > startaddr.s_addr);
    currentaddr.s_addr--;
  } else if (targets_type == IPV4_RANGES) {
    for(octet = 3; octet >= 0; octet--) {
      if (current[octet] > 0) {
        /* OK, this is the column I have room to nudge downwards */
        current[octet]--;
        break;
      } else {
        /* This octet is already at the beginning, so I set it to the end */
        current[octet] = last[octet];
      }
    }
    assert(octet != -1);
  } else {
    assert(targets_type == IPV6_ADDRESS);
    assert(ipsleft == 1);    
  }
  return 0;
}


