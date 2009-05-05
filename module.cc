#include "ncrack.h"
#include "nsock.h"
#include "utils.h"

#define BUFSIZE 256
void call_module(m_data *);


extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, nsock_iod nsi, void *mydata);


enum states { INIT, FTP_BANNER, FTP_USER_R, FTP_USER_W, FTP_PASS, FTP_FINI, END };

void
call_module(m_data *mdata)
{
	nsock_pool nsp = mdata->nsp;
	nsock_iod nsi = mdata->nsi;
	char buf[BUFSIZE];

	switch (mdata->state)
	{
		case INIT:
			printf("INIT\n");
			mdata->state = FTP_BANNER;
			nsock_read(nsp, nsi, ncrack_read_handler, 10000, mdata);
			break;

		case FTP_BANNER:
			printf("FTP_BANNER\n");
			mdata->state = FTP_USER_R;
			if (!mdata->attempts) {
				if (!mdata->buf || mdata->buf[0] != '2')
					fatal("not ftp or service was shutdown\n");
				else 
					printf("reply: %d bytes %s\n", mdata->bufsize, mdata->buf);
			}
			strncpy(buf, "USER ithilgore\r\n", sizeof(buf) - 1);
			nsock_write(nsp, nsi, ncrack_write_handler, 10000, mdata, buf, -1);
			break;

		case FTP_USER_R:
			printf("FTP_USER_R\n");
			mdata->state = FTP_USER_W;
			nsock_read(nsp, nsi, ncrack_read_handler, 10000, mdata);
			break;

		case FTP_USER_W:
			printf("FTP_USER_W\n");
			mdata->state = FTP_PASS;
			if (!mdata->buf || mdata->buf[0] != '3')
				printf("User failed\n");
			else
				printf("reply: %d bytes %s\n", mdata->bufsize, mdata->buf);
			strncpy(buf, "PASS ithilgore\r\n", sizeof(buf) - 1);
			nsock_write(nsp, nsi, ncrack_read_handler, 10000, mdata, buf, -1);
			break;

		case FTP_PASS:
			printf("FTP_PASS\n");
			mdata->state = FTP_FINI;
			nsock_read(nsp, nsi, ncrack_read_handler, 10000, mdata);
			break;

		case FTP_FINI:
			printf("FTP_FINI\n");
			mdata->state = FTP_BANNER;
			mdata->attempts++;
			if (!mdata->buf || mdata->buf[0] != '2')
				printf("Password failed\n");
			else
				printf("Success!\n");		
			ncrack_module_end(nsp, nsi, mdata);
			break;

		default:
			break;
	}
}
