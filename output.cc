#include "output.h"
#include "NcrackOps.h"
#include "ncrack_error.h"

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
void log_vwrite(int logt, const char *fmt, va_list ap) {
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
    case LOG_MACHINE:
    case LOG_XML:
#ifdef WIN32
      apcopy = ap;
#else
      va_copy(apcopy, ap); /* Needed in case we need to so a second vnsprintf */
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
            fatal("%s: vnsprintf failed.  Even after increasing bufferlen to %d, Vsnprintf returned %d (logt == %d).  Please email this message to fyodor@insecure.org.  Quitting.", __func__, writebuflen, len, logt);
          }
        }
        rc = fwrite(writebuf,len,1,o.logfd[fileidx]);
        if (rc != 1) {
          fatal("Failed to write %d bytes of data to (logt==%d) stream. fwrite returned %d.  Quitting.", len, logt, rc);
        }
        va_end(apcopy);
      }
      break;

    default:
      fatal("%s(): Passed unknown log type (%d).  Note that this function, unlike log_write, can only handle one log type at a time (no bitmasks)", __func__, logt);
  }

  return;
}


/* Close the given log stream(s) */
void log_close(int logt)
{
  int i;
  if (logt<0 || logt>LOG_FILE_MASK) return;
  for (i=0;logt;logt>>=1,i++) if (o.logfd[i] && (logt&1)) fclose(o.logfd[i]);
}

/* Flush the given log stream(s).  In other words, all buffered output
   is written to the log immediately */
void log_flush(int logt) {
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
void log_flush_all() {
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
int log_open(int logt, char *filename)
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
      fatal("Failed to open %s output file %s for writing", logtypes[i], filename);
  }
  return 1;
}


char *logfilename(const char *str, struct tm *tm)
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
