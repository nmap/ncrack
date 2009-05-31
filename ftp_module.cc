#include "ncrack.h"
#include "nsock.h"
#include "utils.h"
#include "global_structures.h"
#include "NcrackOps.h"
#include "Service.h"
#include "modules.h"
#include <string.h>
#include <list>


extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);


enum states { FTP_INIT, FTP_BANNER, FTP_USER_R, FTP_USER_W, FTP_PASS, FTP_FINI, END };

void
ncrack_ftp(nsock_pool nsp, Connection *con)
{
  char hostinfo[1024];
  char lbuf[BUFSIZE]; /* local buffer */
  nsock_iod nsi = con->niod;
  Service *serv = con->service;

  snprintf(hostinfo, sizeof(hostinfo), "%s://%s:%hu", serv->name,
      serv->target->NameIP(), serv->portno);
  con->retry = false; 

  switch (con->state)
  {
    case FTP_INIT:
      con->state = FTP_BANNER;
      nsock_read(nsp, nsi, ncrack_read_handler, 10000, con);
      break;

    case FTP_BANNER:
      con->state = FTP_USER_R;
      if (!con->login_attempts) {
        if (!con->buf || con->buf[0] != '2') {
          error("Not ftp or service was shutdown\n");
          ncrack_module_end(nsp, con);
        }
        else {
          if (o.debugging > 6)
            printf("%s reply: %s", hostinfo, con->buf);
        }
      }
      strncpy(lbuf, "USER ithilgore\r\n", sizeof(lbuf) - 1);
      nsock_write(nsp, nsi, ncrack_write_handler, 10000, con, lbuf, -1);
      break;

    case FTP_USER_R:
      con->state = FTP_USER_W;
      nsock_read(nsp, nsi, ncrack_read_handler, 10000, con);
      break;

    case FTP_USER_W:
      con->state = FTP_PASS;
      if (!con->buf || con->buf[0] != '3') {
        if (o.debugging > 6)
          printf("%s User failed\n", hostinfo);
      }
      else {
        if (o.debugging > 6)
          printf("%s reply: %s", hostinfo, con->buf);
      }
      strncpy(lbuf, "PASS ithilgore\r\n", sizeof(lbuf) - 1);
      nsock_write(nsp, nsi, ncrack_write_handler, 10000, con, lbuf, -1);
      break;

    case FTP_PASS:
      con->state = FTP_FINI;
      nsock_read(nsp, nsi, ncrack_read_handler, 10000, con);
      break;

    case FTP_FINI:
      con->state = FTP_BANNER;
      con->login_attempts++;
      serv->total_attempts++;
      if (!con->buf || con->buf[0] != '2')
        printf("%s Password failed\n", hostinfo);
      else
        printf("Success!\n");   
      break;

    default:
      break;
  }
  if (con->state == FTP_FINI) {
    con->retry = true;
    return ncrack_module_end(nsp, con);
  }
  /* make sure that ncrack_module_end() is always called last to have 
   * tail recursion or else stack space overflow might occur */
}
