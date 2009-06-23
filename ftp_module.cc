#include "ncrack.h"
#include "nsock.h"
#include "NcrackOps.h"
#include "Service.h"
#include "modules.h"
#include <list>


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
      nsock_read(nsp, nsi, ncrack_read_handler, 15000, con);
      break;

    case FTP_BANNER:
      con->state = FTP_USER_R;
      if (!con->login_attempts) {
        if (!con->buf || con->buf[0] != '2') {
          error("%s Not ftp or service was shutdown\n", hostinfo);
          ncrack_module_end(nsp, con);
        } else {
          if (o.debugging > 8)
            printf("%s reply: %s", hostinfo, con->buf);
        }
      }
      snprintf(lbuf, sizeof(lbuf), "USER %s\r\n", con->user);
      nsock_write(nsp, nsi, ncrack_write_handler, 15000, con, lbuf, -1);
      break;

    case FTP_USER_R:
      con->state = FTP_USER_W;
      nsock_read(nsp, nsi, ncrack_read_handler, 15000, con);
      break;

    case FTP_USER_W:
      con->state = FTP_PASS;
      if (!con->buf || con->buf[0] != '3') {
        if (o.debugging > 8)
          printf("%s Username failed\n", hostinfo);
      } else {
        if (o.debugging > 8)
          printf("%s reply: %s", hostinfo, con->buf);
      }
      snprintf(lbuf, sizeof(lbuf), "PASS %s\r\n", con->pass);
      nsock_write(nsp, nsi, ncrack_write_handler, 15000, con, lbuf, -1);
      break;

    case FTP_PASS:
      con->state = FTP_FINI;
      nsock_read(nsp, nsi, ncrack_read_handler, 15000, con);
      break;

    case FTP_FINI:
      if (memsearch(con->buf, "230", con->bufsize))
        printf("%s Success: %s %s\n", hostinfo, con->user, con->pass);   
      else {
        if (o.debugging > 3)
          printf("%s Login failed: %s %s\n", hostinfo, con->user, con->pass);
      } 
      con->state = FTP_BANNER;

      return ncrack_module_end(nsp, con);
  }
  /* make sure that ncrack_module_end() is always called last or returned to have 
   * tail recursion or else stack space overflow might occur */
}
