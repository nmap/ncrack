
/***************************************************************************
 * ncrack_input.cc -- Functions for parsing input from Nmap. Support for   *
 * Nmap's -oX and -oN output formats.                                      *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
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
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
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


#include "ncrack.h"
#include "utils.h"
#include "ncrack_input.h"


/* 
 * Responsible for parsing an Nmap XML output file (with the -oX option).
 * Returns 0 for success and host_spec is set with a host-service specification
 * in the form <service_name>://<IP-address>:<port-number>.
 * Returns -1 upon failure - which is usually when the EOF is reached. 
 * This function has to be called as many times as needed until it
 * returns -1 to signify the end of parsing. 
 */
int
xml_input(FILE *inputfd, char *host_spec)
{
  static bool begin = true;
  int ch;
  char buf[256];
  static char ip[16];
  char portnum[7];
  char service_name[64];

  /* check if file is indeed in Nmap's XML output format */
  if (begin) {

    /* First check if this is an XML file */
    if (!fgets(buf, 15, inputfd))
      fatal("-iX XML checking fgets failure!\n");
    if (strncmp(buf, "<?xml version=", 15))
      fatal("-iX file is not a XML file!\n");

    /* Now try to run the special string "nmaprun" to validate that this is
     * indeed a Nmap XML output file */
    bool ok = false;
    memset(buf, 0, sizeof(buf));
    while ((ch = getc(inputfd)) != EOF) {
      if (ch == '\n') {
        if (!fgets(buf, 9, inputfd))
          fatal("-iX corrupted file: cannot find string \"<nmaprun\"\n");
        if (!strncmp(buf, "<nmaprun", 8)) {
          ok = true;
          break;
        }
      }
    }
    if (!ok)
      fatal("-iX file doesn't seem to be in Nmap's XML output format "
        "option -oX <filename>!\n");

    //memset(ip, '\0', sizeof(ip));
    begin = false;
  }

  memset(buf, 0, sizeof(buf));

  /* Ready to search for hosts and open ports */

  while ((ch = getc(inputfd)) != EOF) {
    if (ch == '\n') {

      /* If you have already got an address from a previous invokation, then
       * search only for open ports, else go look for a new IP */
      if (!strncmp(ip, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", sizeof(ip))) {

        /* Search for string "<address" */
        if (!fgets(buf, 8, inputfd))
          fatal("-iX <address> section searching fgets failure!\n");

        if (!strncmp(buf, "<addres", 7)) {
          /* Now get the rest of the line which is in the following format:
           * <address addr="10.0.0.100" addrtype="ipv4" /> */
          unsigned int i = 0;
          while ((ch = getc(inputfd)) != EOF) {
            if (ch == '>')
              break;
            if (i < sizeof(buf) / sizeof(char) - 1)
              buf[i++] = (char) ch;
            else 
              fatal("-iX possible buffer overflow!\n");
          }
          if (i < 12) 
            fatal("-iX corrupted Nmap XML output file!\n");
          i--;
          char *addr = NULL;
          if (!(addr = memsearch(buf, "addr=", i)))
            fatal("-iX corrupted Nmap XML output file!\n");
          /* Now point to the actual address string */
          addr += sizeof("addr=");

          /* Now find where the IP ends by finding the ending double quote */
          i = 0;
          while (addr[i] != '"')
            i++;
          i++;
          if (i > sizeof(ip))
            i = sizeof(ip);
          Strncpy(ip, addr, i);

        } else if (!strncmp(buf, "<runsta", 7)) {
          /* We reached the end, so that's all folks. Get out. */
          return -1;
        }

      } else {
        /* Search for open ports, since we already have an address */

        if (!fgets(buf, 9, inputfd))
          fatal("-iX <ports> section searching fgets failure!\n");


        if (!strncmp(buf, "<ports>", 7)) {
          /* Now, depending on Nmap invokation we can have an extra section of
           * "extraports" which we ignore */
          if (!fgets(buf, 12, inputfd))
            fatal("-iX <extraports> section searching fgets failure!\n");
          if (!strncmp(buf, "<extraports", 11)) {
            /* Found "extraports" section. Now find the end of this section
             * Nmap ends "</extraports>" in a new line, so use that */
            while ((ch = getc(inputfd)) != EOF) {
              if (ch == '\n') {
                if (!fgets(buf, 13, inputfd))
                  fatal("-iX extraports fgets failure!\n");
                if (!strncmp(buf, "</extraports", 12))
                  break;
              }
            }
          }
        } else if (!strncmp(buf, "<port ", 6)) {
          /* We are inside a <port section */

          /* Now get the rest of the line which is in the following format:
           * <port protocol="tcp" portid="22"><state state="open" 
           * reason="syn-ack" reason_ttl="0"/><service name="ssh"
           * method="table" conf="3" /></port>
           */
          memset(buf, 0, sizeof(buf));

          unsigned int port_section_length = 0;
          unsigned int subsection = 0;
          /* Since the <port section has a total of 3 subsections (port,
           * service, state) we can use that information for parsing */
          while ((ch = getc(inputfd)) != EOF) {
            if (ch == '>') {
              subsection++;
              if (subsection > 3)
                break;
            }
            if (port_section_length < sizeof(buf) / sizeof(char) - 1)
              buf[port_section_length++] = (char) ch;
            else 
              fatal("-iX possible buffer overflow inside port parsing\n");
          }
          if (port_section_length < 100) 
            fatal("-iX corrupted Nmap XML output file: too little length in "
                "<port> section\n");
          port_section_length--;
          
          char *p = NULL;
          if (!(p = memsearch(buf, "portid=", port_section_length)))
            fatal("-iX cannot find portid inside <port> section!\n");
          p += sizeof("portid=");

          /* Now find where the port number ends by finding the double quote */
          unsigned int i = 0;
          while (p[i] != '"')
            i++;
          i++;
          if (i > sizeof(portnum))
            i = sizeof(portnum);

          Strncpy(portnum, p, i);
          //printf("\nport: %s\n", portnum);

          /* Now make sure this port is in 'state=open' since we won't bother
           * grabbing ports that are not open. */
          p = NULL;
          if (!(p = memsearch(buf, "state=", port_section_length)))
            fatal("-iX cannot find state inside <port> section!\n");
          p += sizeof("state=");

          /* Port is open, so now grab the service name */
          if (!strncmp(p, "open", 4)) {

            p = NULL;
            if (!(p = memsearch(buf, "name", port_section_length)))
              fatal("-iX cannot find service 'name' inside <port> section!\n");
            p += sizeof("name=");

            i = 0;
            while (p[i] != '"')
              i++;
            i++;
            if (i > sizeof(service_name))
              i = sizeof(service_name);

            Strncpy(service_name, p, i);
            //printf("\nservice_name: %s\n", service_name);

            /* Now we get everything we need: IP, service name and port so
             * we can return them into host_spec 
             */
            Snprintf(host_spec, 1024, "%s://%s:%s", service_name, ip, portnum);
            return 0;
          }

        } else if (!strncmp(buf, "</ports>", 8)) {

          /* We reached the end of the <ports> section, so we now need a new
           * IP address - let the parser know that  */
          memset(ip, '\0', sizeof(ip));

        } else if (!strncmp(buf, "<runsta", 7)) {
          /* We reached the end, so that's all folks. Get out. */
          return -1;
        }


      }

    }
  }

  return -1;
}


int
normal_input(FILE *inputfd, char *host_spec)
{
  static bool begin = false;


  return -1;

}
