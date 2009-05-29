#include "ncrack.h"
#include "nsock.h"
#include "utils.h"
#include "global_structures.h"
#include "Service.h"
#include "modules.h"
#include <string.h>
#include <list>




extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);


enum states { INIT, FTP_BANNER, FTP_USER_R, FTP_USER_W, FTP_PASS, FTP_FINI, END };

void
ncrack_ftp(nsock_pool nsp, Connection *con)
{
  char lbuf[BUFSIZE]; /* local buffer */
        nsock_iod nsi = con->niod;
        Service *serv = con->service;

  switch (con->state)
  {
    case INIT:
      printf("INIT\n");
      con->state = FTP_BANNER;
      nsock_read(nsp, nsi, ncrack_read_handler, 10000, con);
      break;

    case FTP_BANNER:
      printf("FTP_BANNER\n");
      con->state = FTP_USER_R;
      if (!con->login_attempts) {
        if (!con->buf || con->buf[0] != '2') {
          error("Not ftp or service was shutdown\n");
                                        ncrack_module_end(nsp, con);
                                }
        else 
          printf("reply: %d bytes %s\n", con->bufsize, con->buf);
      }
      strncpy(lbuf, "USER ithilgore\r\n", sizeof(lbuf) - 1);
      nsock_write(nsp, nsi, ncrack_write_handler, 10000, con, lbuf, -1);
      break;

    case FTP_USER_R:
      printf("FTP_USER_R\n");
      con->state = FTP_USER_W;
      nsock_read(nsp, nsi, ncrack_read_handler, 10000, con);
      break;

    case FTP_USER_W:
      printf("FTP_USER_W\n");
      con->state = FTP_PASS;
      if (!con->buf || con->buf[0] != '3')
        printf("User failed\n");
      else
        printf("reply: %d bytes %s\n", con->bufsize, con->buf);
      strncpy(lbuf, "PASS ithilgore\r\n", sizeof(lbuf) - 1);
      nsock_write(nsp, nsi, ncrack_read_handler, 10000, con, lbuf, -1);
      break;

    case FTP_PASS:
      printf("FTP_PASS\n");
      con->state = FTP_FINI;
      nsock_read(nsp, nsi, ncrack_read_handler, 10000, con);
      break;

    case FTP_FINI:
      printf("FTP_FINI\n");
      con->state = FTP_BANNER;
      con->login_attempts++;
      if (!con->buf || con->buf[0] != '2')
        printf("Password failed\n");
      else
        printf("Success!\n");   
      ncrack_module_end(nsp, con);
      break;

    default:
      break;
  }
}
