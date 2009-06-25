#include "ncrack.h"
#include "nsock.h"
#include "NcrackOps.h"
#include "Service.h"
#include "modules.h"
#include <list>

#define TIMEOUT 20000


extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);


enum states { FTP_INIT, FTP_BANNER, FTP_USER_R, FTP_USER_W, FTP_PASS, FTP_FINI };

void
ncrack_ftp(nsock_pool nsp, Connection *con)
{
  char lbuf[BUFSIZE]; /* local buffer */
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  const char *hostinfo = serv->HostInfo();

  switch (con->state)
  {
    case FTP_INIT:
      con->state = FTP_BANNER;
      nsock_read(nsp, nsi, ncrack_read_handler, TIMEOUT, con);
      break;

    case FTP_BANNER:
      con->state = FTP_USER_R;
      if (!con->login_attempts) {
        if (!con->buf || con->buf[0] != '2') {
          if (o.debugging > 6)
            error("%s Not ftp or service was shutdown\n", hostinfo);
          ncrack_module_end(nsp, con);
        } else {
          if (o.debugging > 9)
            log_write(LOG_STDOUT, "%s reply: %s", hostinfo, con->buf);
        }
      }
      /* Workaround for Filezilla which sends 3 banners in 3 tcp segments */
      if (memsearch(con->buf, "FileZilla Server", con->bufsize) ||
          memsearch(con->buf, "Tim Kosse", con->bufsize)) {
        nsock_read(nsp, nsi, ncrack_read_handler, TIMEOUT, con);
        con->state = FTP_BANNER;
        break;
      }
      snprintf(lbuf, sizeof(lbuf), "USER %s\r\n", con->user);
      nsock_write(nsp, nsi, ncrack_write_handler, TIMEOUT, con, lbuf, -1);
      break;

    case FTP_USER_R:
      con->state = FTP_USER_W;
      nsock_read(nsp, nsi, ncrack_read_handler, TIMEOUT, con);
      break;

    case FTP_USER_W:
      con->state = FTP_PASS;
      if (!con->buf || con->buf[0] != '3') {
        if (con->buf[0] != '2') {
          if (o.debugging > 9)
            log_write(LOG_STDOUT, "%s Username failed\n", hostinfo);
        }
      } else {
        if (o.debugging > 9)
          log_write(LOG_STDOUT, "%s reply: %s", hostinfo, con->buf);
      }
      snprintf(lbuf, sizeof(lbuf), "PASS %s\r\n", con->pass);
      nsock_write(nsp, nsi, ncrack_write_handler, TIMEOUT, con, lbuf, -1);
      break;

    case FTP_PASS:
      con->state = FTP_FINI;
      nsock_read(nsp, nsi, ncrack_read_handler, TIMEOUT, con);
      break;

    case FTP_FINI:
      if (memsearch(con->buf, "230", con->bufsize))
        log_write(LOG_PLAIN, "%s Success: %s %s\n", hostinfo, con->user, con->pass);   
      else {
        if (o.debugging > 6)
          log_write(LOG_STDOUT, "%s Login failed: %s %s\n", hostinfo, con->user, con->pass);
      } 
      con->state = FTP_BANNER;

      return ncrack_module_end(nsp, con);
  }
  /* make sure that ncrack_module_end() is always called last or returned to have 
   * tail recursion or else stack space overflow might occur */
}
