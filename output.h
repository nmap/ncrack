#ifndef OUTPUT_H
#define OUTPUT_H

#include <stdarg.h>
#include <time.h>

#define LOG_NUM_FILES 3 /* # of values that actual files (they must come first */
#define LOG_FILE_MASK 15 /* The mask for log typs in the file array */
#define LOG_NORMAL 1
#define LOG_MACHINE 2
#define LOG_XML 4
#define LOG_STDOUT 1024
#define LOG_STDERR 2048
#define LOG_MAX LOG_STDERR /* The maximum log type value */

#define LOG_PLAIN LOG_NORMAL|LOG_STDOUT

#define LOG_NAMES {"normal", "machine", "XML"}

void memprint(const char *addr, size_t bytes);

char *logfilename(const char *str, struct tm *tm);

/* Write some information (printf style args) to the given log stream(s).
   Remember to watch out for format string bugs. */
void log_write(int logt, const char *fmt, ...)
     __attribute__ ((format (printf, 2, 3)));

/* This is the workhorse of the logging functions.  Usually it is
   called through log_write(), but it can be called directly if you
   are dealing with a vfprintf-style va_list.  Unlike log_write, YOU
   CAN ONLY CALL THIS WITH ONE LOG TYPE (not a bitmask full of them).
   In addition, YOU MUST SANDWHICH EACH EXECUTION IF THIS CALL BETWEEN
   va_start() AND va_end() calls. */
void log_vwrite(int logt, const char *fmt, va_list ap);

/* Close the given log stream(s) */
void log_close(int logt);

/* Flush the given log stream(s).  In other words, all buffered output
   is written to the log immediately */
void log_flush(int logt);

/* Flush every single log stream -- all buffered output is written to the
   corresponding logs immediately */
void log_flush_all();

/* Open a log descriptor of the type given to the filename given.  If 
   o.append_output is nonzero, the file will be appended instead of clobbered if
   it already exists.  If the file does not exist, it will be created */
int log_open(int logt, char *filename);

#endif /* OUTPUT_H */
