
/***************************************************************************
 * ncrack_resume.cc -- functions that implement the --resume option, which *
 * needs to save the current state of Ncrack into a file and then recall   *
 * it.                                                                     *
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

#include "ncrack_resume.h"
#include "NcrackOps.h"

extern NcrackOps o;


/* This function takes a command and the address of an uninitialized
   char ** .  It parses the command (by separating out whitespace)
   into an argv[] style char **, which it sets the argv parameter to.
   The function returns the number of items filled up in the array
   (argc), or -1 in the case of an error.  This function allocates
   memory for argv and thus it must be freed -- use argv_parse_free()
   for that.  If arg_parse returns <1, then argv does not need to be freed.
   The returned arrays are always terminated with a NULL pointer */
int
arg_parse(const char *command, char ***argv)
{
  char **myargv = NULL;
  int argc = 0;
  char mycommand[4096];
  char *start, *end;
  char oldend;

  *argv = NULL;
  if (Strncpy(mycommand, command, 4096) == -1) {      
    return -1;
  }
  myargv = (char **) safe_malloc((MAX_PARSE_ARGS + 2) * sizeof(char *));
  memset(myargv, 0, (MAX_PARSE_ARGS+2) * sizeof(char *));
  myargv[0] = (char *) 0x123456; /* Integrity checker */
  myargv++;
  start = mycommand;
  while (start && *start) {
    while (*start && isspace((int) (unsigned char) *start))
      start++;
    if (*start == '"') {
      start++;
      end = strchr(start, '"');
    } else if (*start == '\'') {
      start++;
      end = strchr(start, '\'');      
    } else if (!*start) {
      continue;
    } else {
      end = start+1;
      while (*end && !isspace((int) (unsigned char) *end)) {      
        end++;
      }
    }
    if (!end) {
      arg_parse_free(myargv);
      return -1;
    }
    if (argc >= MAX_PARSE_ARGS) {
      arg_parse_free(myargv);
      return -1;
    }
    oldend = *end;
    *end = '\0';
    myargv[argc++] = strdup(start);
    if (oldend)
      start = end + 1;
    else start = end;
  }
  myargv[argc+1] = 0;
  *argv = myargv;
  return argc;
}

/* Free an argv allocated inside arg_parse */
void
arg_parse_free(char **argv)
{
  char **current;
  /* Integrity check */
  argv--;
  assert(argv[0] == (char *) 0x123456);
  current = argv + 1;
  while (*current) {
    free(*current);
    current++;
  }
  free(argv);
}


int
ncrack_save(ServiceGroup *SG)
{
  FILE *outfile = NULL;
  int argiter;
  int magic = 0xdeadbeef;
  list <Service *>::iterator li;
  unsigned long index;

  abort();

  if (!(outfile = fopen("./ncrack.restore", "w")))
    fatal("%s: couldn't open file to save current state!\n", __func__);

  /* First write magic number */
  if (fwrite(&magic, sizeof(magic), 1, outfile) != 1)
    fatal("%s: couldn't write magic number to file!\n", __func__);

  /* Store the exact way Ncrack was invoked by writing the argv array */
  for (argiter = 0; argiter < o.saved_argc; argiter++) {
    if (fwrite(o.saved_argv[argiter], strlen(o.saved_argv[argiter]), 1,
          outfile) != 1)
      fatal("%s: couldn't write argv array to file!\n", __func__);
    if (fwrite(" ", 1, 1, outfile) != 1)
      fatal("%s: can't even write space!\n", __func__);
  }
  if (fwrite("\n", 1, 1, outfile) != 1)
    fatal("%s: can't write newline!\n", __func__);

  /* Now iterate through all services and write for each of them:
   * 1) the unique id
   * 2) the username/password lists's iterators
   * 3) any credentials found so far
   */
  for (li = SG->services_all.begin(); li != SG->services_all.end(); li++) {

    /* First write the unique id */
    if (fwrite(&(*li)->uid, sizeof((*li)->uid), 1, outfile) != 1)
      fatal("%s: couldn't write unique id to file!\n", __func__);

    printf("---------id: %lu-----------\n", (*li)->uid);
    /* Write the list iterators but first convert them to 'indexes' of the
     * vectors they are pointing to.
     */
    index = (*li)->getUserlistIndex();
    printf("user index: %lu\n", index);
    if (fwrite(&index, sizeof(index), 1, outfile) != 1)
      fatal("%s: couldn't write userlist index to file!\n", __func__);

    index = (*li)->getPasslistIndex();
    printf("pass index: %lu\n", index);
    if (fwrite(&index, sizeof(index), 1, outfile) != 1)
      fatal("%s: couldn't write passlist index to file!\n", __func__);



  }


  fclose(outfile);


  return 0;
}


/* Reads in the special restore file that has everything Ncrack needs to know
 * to resume the saved session. The important things it must gather are:
 * 1) The command arguments
 * 2) The unique id of each service
 * 3) The username/password lists's indexes
 * 4) Any credentials found so far
 */
int
ncrack_resume(char *fname, int *myargc, char ***myargv)
{
#if 0
  char *filestr;
  int filelen;
  char nmap_arg_buffer[1024];
  struct in_addr lastip;
  char *p, *q, *found; /* I love C! */
  /* We mmap it read/write since we will change the last char to a newline if it is not already */
  filestr = mmapfile(fname, &filelen, O_RDWR);
  if (!filestr) {
    fatal("Could not mmap() %s read/write", fname);
  }

  if (filelen < 20) {
    fatal("Output file %s is too short -- no use resuming", fname);
  }

  /* For now we terminate it with a NUL, but we will terminate the file with
     a '\n' later */
  filestr[filelen - 1] = '\0';

  /* First goal is to find the nmap args */
  if ((p = strstr(filestr, " as: ")))
    p += 5;
  else fatal("Unable to parse supposed log file %s.  Are you sure this is an Nmap output file?", fname);
  while(*p && !isspace((int) (unsigned char) *p))
    p++;
  if (!*p) fatal("Unable to parse supposed log file %s.  Sorry", fname);
  p++; /* Skip the space between program name and first arg */
  if (*p == '\n' || !*p) fatal("Unable to parse supposed log file %s.  Sorry", fname);

  q = strchr(p, '\n');
  if (!q || ((unsigned int) (q - p) >= sizeof(nmap_arg_buffer) - 32))
    fatal("Unable to parse supposed log file %s.  Perhaps the Nmap execution had not finished at least one host?  In that case there is no use \"resuming\"", fname);


  strcpy(nmap_arg_buffer, "nmap --append-output ");
  if ((q-p) + 21 + 1 >= (int) sizeof(nmap_arg_buffer)) fatal("0verfl0w");
  memcpy(nmap_arg_buffer + 21, p, q-p);
  nmap_arg_buffer[21 + q-p] = '\0';

  if (strstr(nmap_arg_buffer, "--randomize-hosts") != NULL) {
    error("WARNING:  You are attempting to resume a scan which used --randomize-hosts.  Some hosts in the last randomized batch may be missed and others may be repeated once");
  }

  *myargc = arg_parse(nmap_arg_buffer, myargv);
  if (*myargc == -1) {  
    fatal("Unable to parse supposed log file %s.  Sorry", fname);
  }

  /* Now it is time to figure out the last IP that was scanned */
  q = p;
  found = NULL;
  /* Lets see if its a machine log first */
  while((q = strstr(q, "\nHost: ")))
    found = q = q + 7;

  if (found) {
    q = strchr(found, ' ');
    if (!q) fatal("Unable to parse supposed log file %s.  Sorry", fname);
    *q = '\0';
    if (inet_pton(AF_INET, found, &lastip) == 0)
      fatal("Unable to parse supposed log file %s.  Sorry", fname);
    *q = ' ';
  } else {
    /* OK, I guess (hope) it is a normal log then */
    q = p;
    found = NULL;
    while((q = strstr(q, "\nInteresting ports on ")))
      found = q++;

    /* There may be some later IPs of the form 'All [num] scanned ports on  ([ip]) are: state */
    if (found) q = found;
    if (q) {    
      while((q = strstr(q, "\nAll "))) {
        q+= 5;
        while(isdigit((int) (unsigned char) *q)) q++;
        if (strncmp(q, " scanned ports on", 17) == 0)
          found = q;
      }
    }

    if (found) {    
      found = strchr(found, '(');
      if (!found) fatal("Unable to parse supposed log file %s.  Sorry", fname);
      found++;
      q = strchr(found, ')');
      if (!q) fatal("Unable to parse supposed log file %s.  Sorry", fname);
      *q = '\0';
      if (inet_pton(AF_INET, found, &lastip) == 0)
        fatal("Unable to parse ip (%s) supposed log file %s.  Sorry", found, fname);
      *q = ')';
    } else {
      error("Warning: You asked for --resume but it doesn't look like any hosts in the log file were successfully scanned.  Starting from the beginning.");
      lastip.s_addr = 0;
    }
  }
  o.resume_ip = lastip;

  /* Ensure the log file ends with a newline */
  filestr[filelen - 1] = '\n';
  munmap(filestr, filelen);
#endif 
  return 0;
}

