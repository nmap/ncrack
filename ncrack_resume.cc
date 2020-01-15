
/***************************************************************************
 * ncrack_resume.cc -- functions that implement the --resume option, which *
 * needs to save the current state of Ncrack into a file and then recall   *
 * it.                                                                     *
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

#include "ncrack_resume.h"
#include "NcrackOps.h"

#define BLANK_ENTRY "<BLANK>"

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
  uint32_t magic = MAGIC_NUM;  /* a bell that doesn't ring */
  list <Service *>::iterator li;
  vector <loginpair>::iterator vi;
  uint32_t index = 0;
  uint32_t credlist_size = 0;
  struct passwd *pw;
  int res, err;
  time_t now;
  struct tm local_time;
  char path[MAXPATHLEN];
  char filename[MAXPATHLEN];
  bool cmd_user_pass = false; /* boolean used for handling the blank username/password
                                 in the --user or --pass option */


  /* First find user home directory to save current session file
   * in there (if he hasn't already specified his own filename, in which case
   * we don't need to do all this work)
   */
  if (!o.save_file) {

#ifndef WIN32
    /* Unix systems -> use getpwuid of real or effective uid  */
    pw = getpwuid(getuid());
    if (!pw && getuid() != geteuid())
      pw = getpwuid(geteuid());
    if (!pw)
      fatal("%s: couldn't get current user's home directory to save restoration"
          " file", __func__);

    res = Snprintf(path, sizeof(path), "%s/.ncrack", pw->pw_dir);
    if (res < 0 || res > (int)sizeof(path))
      fatal("%s: possibly not enough buffer space for home path!\n", __func__);

#else
    /* Windows systems -> use the environmental variables */
    ExpandEnvironmentStrings("%userprofile%", path, sizeof(path));
    strncpy(&path[strlen(path)], "\\.ncrack", sizeof(path) - strlen(path));

#endif

    /* Check if <home>/.ncrack directory exists and has proper permissions.
     * If it doesn't exist, create it */
    if (access(path, F_OK)) {
      /* dir doesn't exist, so mkdir it */
#ifdef WIN32
      if (mkdir(path))
#else 
        if (mkdir(path, S_IRUSR | S_IWUSR | S_IXUSR))
#endif
          fatal("%s: can't create %s in user's home directory!\n", __func__, path);
    } else {
#ifdef WIN32
      if (access(path, R_OK | W_OK))
#else
        if (access(path, R_OK | W_OK | X_OK))
#endif
          fatal("%s: %s doesn't have proper permissions!\n", __func__, path);
    }

  }

  /* If user has specified a specific filename, then store saved state into
   * that, rather than in the normal restore. format */
  if (!o.save_file) {

    /* Now create restoration file name based on the current date and time */
    Strncpy(filename, "restore.", 9);

    now = time(NULL);
    err = n_localtime(&now, &local_time);
    if (err) {
      fatal("n_localtime failed: %s", strerror(err));
    }

    if (strftime(&filename[8], sizeof(filename), "%Y-%m-%d_%H-%M", &local_time) <= 0)
      fatal("%s: Unable to properly format time", __func__);

    if (chdir(path) < 0) {
      /* check for race condition */
      fatal("%s: unable to chdir to %s", __func__, path);
    }

  } else {

    Strncpy(filename, o.save_file, sizeof(filename) - 1);

  }

  if (!(outfile = fopen(filename, "w")))
    fatal("%s: couldn't open file to save current state!\n", __func__);


  /* First write magic number */
  if (fwrite(&magic, sizeof(magic), 1, outfile) != 1)
    fatal("%s: couldn't write magic number to file!\n", __func__);

  /* Store the exact way Ncrack was invoked by writing the argv array */
  for (argiter = 0; argiter < o.saved_argc; argiter++) {

    /* Special handling in case the user has passed a blank password to either
     * --user "" or --pass "" (or both). We are going to write a placeholder
     *  when saving this particular argument, so that the .restore file can be
     *  properly parsed in this case. 
     */
    if (cmd_user_pass 
        && (!strlen(o.saved_argv[argiter]) 
          || ((strlen(o.saved_argv[argiter]) == 1)
            && !strncmp(o.saved_argv[argiter], ",", 1)))) {
      /* If --user or --pass option argument is blank or a plain ",", then
       * write BLANK_ENTRY magic keyword to indicate this special case */
      if (fwrite(BLANK_ENTRY, strlen(BLANK_ENTRY), 1, outfile) != 1)
        fatal("%s: couldn't write %s to file!\n", __func__, BLANK_ENTRY);
      cmd_user_pass = false;
    } else {
      if (fwrite(o.saved_argv[argiter], strlen(o.saved_argv[argiter]), 1,
            outfile) != 1)
        fatal("%s: couldn't write argv array to file!\n", __func__);
    }
    if (fwrite(" ", 1, 1, outfile) != 1)
      fatal("%s: can't even write space!\n", __func__);

    if (cmd_user_pass)
      cmd_user_pass = false;

    if (!strncmp(o.saved_argv[argiter], "--user", strlen(o.saved_argv[argiter]))
        || !strncmp(o.saved_argv[argiter], "--pass", strlen(o.saved_argv[argiter])))
      cmd_user_pass = true; /* prepare for next iteration parsing */

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

    //printf("---------id: %u-----------\n", (*li)->uid);
    /* Write the list iterators but first convert them to 'indexes' of the
     * vectors they are pointing to. Indexes are uint32_t which helps
     * for portability, since it is a standard size of 32 bits everywhere.
     */

    index = (*li)->getUserlistIndex();
    if (fwrite(&index, sizeof(index), 1, outfile) != 1)
      fatal("%s: couldn't write userlist index to file!\n", __func__);

    index = (*li)->getPasslistIndex();
    if (fwrite(&index, sizeof(index), 1, outfile) != 1)
      fatal("%s: couldn't write passlist index to file!\n", __func__);


    /*
     * Now store any credentials found for this service. First store a 32bit
     * number that denotes the number of credentials (pairs of
     * username/password) that will follow.
     */
    credlist_size = (*li)->credentials_found.size();
    if (fwrite(&credlist_size, sizeof(credlist_size), 1, outfile) != 1)
      fatal("%s: couldn't write credential list size to file!\n", __func__);

    for (vi = (*li)->credentials_found.begin();
        vi != (*li)->credentials_found.end(); vi++) {
      if (fwrite(vi->user, strlen(vi->user), 1, outfile) != 1)
        fatal("%s: couldn't write credential username to file!\n", __func__);
      if (fwrite("\0", 1, 1, outfile) != 1)
        fatal("%s: couldn't even write \'\\0\' to file!\n", __func__);
      if (fwrite(vi->pass, strlen(vi->pass), 1, outfile) != 1)
        fatal("%s: couldn't write credential password to file!\n", __func__);
      if (fwrite("\0", 1, 1, outfile) != 1)
        fatal("%s: couldn't even write \'\\0\' to file!\n", __func__);
    }

  }

  log_write(LOG_STDOUT, "Saved current session state at: ");

  if (!o.save_file) {

    log_write(LOG_STDOUT, "%s", path);
#ifdef WIN32
    log_write(LOG_STDOUT, "\\");
#else
    log_write(LOG_STDOUT, "/");
#endif

  }
  log_write(LOG_STDOUT, "%s\n", filename);

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
  char *filestr;
  int filelen;
  uint32_t magic, uid, cred_num;
  struct saved_info tmp_info;
  vector <loginpair>::iterator vi;
  char ncrack_arg_buffer[1024];
  char buf[1024];
  loginpair tmp_pair;
  char *p, *q; /* I love C! Oh yes indeed. */

  //memset(&tmp_info, 0, sizeof(tmp_info));

  filestr = mmapfile(fname, &filelen, O_RDONLY);
  if (!filestr) {
    fatal("Could not mmap() %s read", fname);
  }

  if (filelen < 20) {
    fatal("Output file %s is too short -- no use resuming", fname);
  }

  /* First check magic number */
  p = filestr;
  memcpy(&magic, p, sizeof(magic));
  if (magic != MAGIC_NUM)
    fatal("Corrupted log file %s . Magic number isn't correct. Are you sure "
        "this is a Ncrack restore file?\n", fname);

  /* Now find the ncrack args */
  p += sizeof(magic);

  while (*p && !isspace((int) (unsigned char) *p))
    p++;
  if (!*p)
    fatal("Unable to parse supposed restore file %s . Sorry", fname);
  p++; /* Skip the space between program name and first arg */
  if (*p == '\n' || !*p)
    fatal("Unable to parse supposed restore file %s . Sorry", fname);

  q = strchr(p, '\n');
  if (!q || ((unsigned int) (q - p) >= sizeof(ncrack_arg_buffer) - 32))
    fatal("Unable to parse supposed restore file %s .", fname);

  strncpy(ncrack_arg_buffer, "ncrack ", 7);
  if ((q-p) + 7 + 1 >= (int) sizeof(ncrack_arg_buffer))
    fatal("0verfl0w");
  memcpy(ncrack_arg_buffer + 7, p, q - p);
  ncrack_arg_buffer[7 + q - p] = '\0';

  *myargc = arg_parse(ncrack_arg_buffer, myargv);
  if (*myargc == -1) {  
    fatal("Unable to parse supposed restore file %s . Sorry", fname);
  }

  /* Now if there is a BLANK_ENTRY placeholder in the .restore file, just place
   * '\0' over it, so that it seems as if the user had typed --user "" or
   * --pass "".
   */
  for (int i = 0; i < *myargc; i++) {
    if (!strncmp(*(*myargv+i), BLANK_ENTRY, strlen(BLANK_ENTRY))) {
      memset(*(*myargv+i), '\0', strlen(BLANK_ENTRY));
    }
  }

  q++;
  /* Now start reading in the services info. */
  while (q - filestr < filelen) {

    uid = (uint32_t)*q;
    q += sizeof(uint32_t);
    if (q - filestr >= filelen)
      fatal("Corrupted file! Error 1\n");

    memcpy(&tmp_info.user_index, q, sizeof(uint32_t));

    q += sizeof(uint32_t);
    if (q - filestr >= filelen)
      fatal("Corrupted file! Error 2\n");

    memcpy(&tmp_info.pass_index, q, sizeof(uint32_t));
    q += sizeof(uint32_t);
    if (q - filestr >= filelen)
      fatal("Corrupted file! Error 3\n");

    memcpy(&cred_num, q, sizeof(uint32_t));
    q += sizeof(uint32_t);
    if (cred_num > 0 && (q - filestr >= filelen))
      fatal("Corrupted file! Error 4\n");

    uint32_t i;
    size_t j;
    bool user = true;
    for (i = 0; i < cred_num * 2; i++) {

      j = 0;
      buf[j++] = *q;
      while (*q != '\0' && j < sizeof(buf)) {
        q++;
        if (q - filestr >= filelen)
          fatal("Corrupted file! Error 5\n");
        buf[j++] = *q;
      }

      q++;

      if (user) {
        user = false;
        tmp_pair.user = Strndup(buf, j - 1);
        if (q - filestr >= filelen)
          fatal("Corrupted file! Error 6\n");
      } else {
        user = true;
        tmp_pair.pass = Strndup(buf, j - 1);
        tmp_info.credentials_found.push_back(tmp_pair);
        if ((i != (cred_num * 2) - 1) && (q - filestr >= filelen))
          fatal("Corrupted file! Error 7\n");
      }

    }

    /* Now save the service info inside the map */
    o.resume_map[uid] = tmp_info;
  }

  munmap(filestr, filelen);
  return 0;
}

