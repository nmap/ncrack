#include "ncrack.h"
#include "nsock.h"
#include "NcrackOps.h"
#include "Service.h"
#include "modules.h"
#include <list>


/* Telnet Commands */
#define IAC   255   /* interpret as command: */
#define DONT  254   /* you are not to use option */
#define DO    253   /* please, you use option */
#define WONT  252 	/* I won't use option */
#define WILL  251 	/* I will use option */
#define SB    250   /* interpret as subnegotiation */
#define	SE    240   /* end sub negotiation */

/* Telnet Options */
#define LINEMODE 34

#define WILL_LINEMODE "\xff\xfb\x22"
#define DO_LINEMODE "\xff\xfd\x22"


extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_timer_handler(nsock_pool nsp, nsock_event nse, void *mydata);

extern void ncrack_module_end(nsock_pool nsp, void *mydata);

typedef struct telnet_info {
  bool linemode; /* true if peer supports linemode */
  /* Some devices don't even bother to answer our question of whether they
   * support linemode or not, and thus we need a separate boolean to tell us
   * if we sent a request, so we can try only once.
   */
  bool asked_for_linemode;
  bool linemode_not_supported;  /* peer told us that he doesn't support linemode */
  bool can_start_auth;
  char *userptr;
  char *passptr;
} telnet_info;


enum states { TELNET_INIT, TELNET_OPTIONS_1, TELNET_OPTIONS_2, TELNET_AUTH, TELNET_ECHO_USER,
  TELNET_PASS_R, TELNET_PASS_W, TELNET_FINI };

void
ncrack_telnet(nsock_pool nsp, Connection *con)
{
  char lbuf[BUFSIZE]; /* local buffer */
  /* We can't let nsock handle the size by looking at '\0'
   * because telnet uses 0 as a valid value for options 
   * (e.g binary transmission option) */
  size_t lbufsize;  
  nsock_iod nsi = con->niod;
  Service *serv = con->service;
  const char *hostinfo = serv->HostInfo();
  telnet_info *info = NULL;
  size_t datasize;

  char *recvbufptr = con->buf;
  char *localbufptr = lbuf;
  if (con->misc_info)
    info = (telnet_info *) con->misc_info;

  switch (con->state)
  {
    case TELNET_INIT:
      con->peer_might_close = false;
      con->misc_info = (telnet_info *)safe_zalloc(sizeof(telnet_info));
      con->state = TELNET_OPTIONS_1;
      nsock_read(nsp, nsi, ncrack_read_handler, 50000, con);
      break;

    case TELNET_OPTIONS_1:
      /* Telnet Option Parsing */
      while (*recvbufptr == (char) IAC
          && ((recvbufptr - con->buf) < con->bufsize)
          && ((localbufptr - lbuf) < BUFSIZE - 3)) {

        /* For every option other than linemode we reject it */
        if (recvbufptr[1] == (char) WILL) {
          if (recvbufptr[2] == (char) LINEMODE) {
            /* reply is needed only when we haven't asked explicitly if the peer
             * supports linemode itself
             */
            if (info->asked_for_linemode == false) {
              strncpy(localbufptr, WILL_LINEMODE, sizeof(WILL_LINEMODE));
              localbufptr += 3;
            }
            info->linemode = true;
          } else {
            snprintf(localbufptr, 4, "%c%c%c", IAC, DONT, recvbufptr[2]);
            localbufptr += 3;
          }
          recvbufptr += 3;

        } else if (recvbufptr[1] == (char) WONT) {
          if (recvbufptr[2] == LINEMODE) {
            info->linemode = false;
            info->linemode_not_supported = true;
          } else {
            snprintf(localbufptr, 4, "%c%c%c", IAC, DONT, recvbufptr[2]);
            localbufptr += 3;
          }
          recvbufptr += 3;

        } else if (recvbufptr[1] == (char) DONT) {
          if (recvbufptr[2] == LINEMODE) {
            info->linemode = false;
            info->linemode_not_supported = true;
          }
          snprintf(localbufptr, 4, "%c%c%c", IAC, WONT, recvbufptr[2]);
          localbufptr += 3;
          recvbufptr += 3;

        } else if (recvbufptr[1] == (char) DO) {
          if (recvbufptr[2] == LINEMODE) {
            if (info->asked_for_linemode == false) {
              strncpy(localbufptr, WILL_LINEMODE, sizeof(WILL_LINEMODE));
              localbufptr += 3;
            }
            info->linemode = true;
          } else {
            snprintf(localbufptr, 4, "%c%c%c", IAC, WONT, recvbufptr[2]);
            localbufptr += 3;
          }
          recvbufptr += 3;

          /* We just ignore any suboption we receive */
        } else if (recvbufptr[1] == (char) SB) {
          while (*recvbufptr != (char) SE && (recvbufptr - con->buf) < con->bufsize)
            recvbufptr++;
          recvbufptr++;
        }
      }

      /* If peer didn't sent linemode as part of its options and didn't sent a 
       * command saying he doesn't support it and this is the first time we
       * request it from him, then try to ask him explicitly if
       * he supports it.
       */
      if (info->linemode == false
          && info->linemode_not_supported == false
          && info->asked_for_linemode == false) {
        if ((localbufptr - lbuf) < BUFSIZE - 3) {
          strncpy(localbufptr, WILL_LINEMODE, sizeof(WILL_LINEMODE));
          info->asked_for_linemode = true;
          localbufptr += 3;
        }
      }

      datasize = con->bufsize - (recvbufptr - con->buf);

      /* Now check for banner and login prompt */
      if (datasize > 0) {
        if (o.debugging > 8) {
          memprint(recvbufptr, datasize);
          printf("\n");
        }
        /* If we see a certain pattern that denotes that we can start
         * authentication then we note that down. */
        if (memsearch(recvbufptr, "login", datasize) 
            || memsearch(recvbufptr, "username", datasize)) 
          info->can_start_auth = true;
      }

      lbufsize = localbufptr - lbuf;

      con->state = TELNET_OPTIONS_2;
      /* If we have something to send then do so. Else just wait until you
       * receive a relevant authentication pattern to start cracking. 
       */
      if (localbufptr != lbuf) {
        nsock_write(nsp, nsi, ncrack_write_handler, 10000, con, lbuf, lbufsize);
      } else {
        if (info->can_start_auth == true)
          con->state = TELNET_AUTH;
        /* That's a bit of a hack, but we need the module to be called again
         * with a changed state without issuing a read or write this time. And
         * thus we create a timer event with a timeout of 0 milliseconds */
        nsock_timer_create(nsp, ncrack_timer_handler, 0, con);
      }
      break;

    case TELNET_OPTIONS_2:
      con->state = TELNET_OPTIONS_1;
      nsock_read(nsp, nsi, ncrack_read_handler, 10000, con);
      break;

    case TELNET_AUTH:
      if (info->linemode) {
        con->state = TELNET_PASS_R;
        snprintf(lbuf, sizeof(lbuf), "%s\r", con->user);
        nsock_write(nsp, nsi, ncrack_write_handler, 10000, con, lbuf, -1);
      } else {
        /* Since our peer doesn't support linemode, we need to send each
         * character of the username in individual packets. We send 1 byte
         * and wait for the server's echo and so on...
         */
        if (!info->userptr)
          info->userptr = con->user;

        /* we can move on to reading the password prompt */
        if (con->buf && memsearch(con->buf, "\r", con->bufsize)) {
          con->state = TELNET_PASS_R;
          nsock_timer_create(nsp, ncrack_timer_handler, 0, con);
          break;
        }

        if (info->userptr - con->user == strlen(con->user)) {
          lbuf[0] = '\r'; 
          lbuf[1] = '\0';
          nsock_write(nsp, nsi, ncrack_write_handler, 10000, con, lbuf, 2);
        } else {
          lbuf[0] = info->userptr[0];
          //printf("%c \n", lbuf[0]);
          info->userptr++;
          nsock_write(nsp, nsi, ncrack_write_handler, 10000, con, lbuf, 1);
        }
        con->state = TELNET_ECHO_USER;
      }
      break;

    case TELNET_ECHO_USER:
      con->state = TELNET_AUTH;
      nsock_read(nsp, nsi, ncrack_read_handler, 10000, con);
      break;

    case TELNET_PASS_R:
      con->state = TELNET_PASS_W;
      nsock_read(nsp, nsi, ncrack_read_handler, 10000, con);
      break;

    case TELNET_PASS_W:
      /* After some testing, it seems that we can send the password
       * as one packet, even if linemode is disabled. */
      con->state = TELNET_FINI;
      snprintf(lbuf, sizeof(lbuf), "%s\r", con->pass);
      con->peer_might_close = true;
      nsock_write(nsp, nsi, ncrack_write_handler, 10000, con, lbuf, -1);
      break;

    case TELNET_FINI:
      if (memsearch(con->buf, "incorrect", con->bufsize)
          || memsearch(con->buf, "fail", con->bufsize)) {
        if (o.debugging > 8)
          printf("%s Failed %s %s\n", hostinfo, con->user, con->pass);
        con->state = TELNET_AUTH;
        info->userptr = NULL;
        info->passptr = NULL;
        /* 
         * If telnetd sent the final answer along with the new login prompt
         * (something which happens with some daemons), then we don't need to 
         * check if the peer has closed the connection because obviously he hasn't!
         */
        if (memsearch(con->buf, "login", con->bufsize)
            || memsearch(con->buf, "username", con->bufsize))
            con->peer_alive = true;
        return ncrack_module_end(nsp, con);

      } else if (memsearch(con->buf, ">", con->bufsize)
          || memsearch(con->buf, "$", con->bufsize)
          || memsearch(con->buf, "#", con->bufsize)) {
        printf("%s SUCCESS %s %s\n", hostinfo, con->user, con->pass);
        con->auth_success = true;
        return ncrack_module_end(nsp, con);

      } else {  /* wait for more replies */
        con->state = TELNET_FINI;
        nsock_read(nsp, nsi, ncrack_read_handler, 10000, con);
      }
  }

}

