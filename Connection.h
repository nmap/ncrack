
/***************************************************************************
 * Connection.h -- The "Connection" class holds information specifically   *
 * pertaining to connection probes. Objects of this class must always      *
 * belong to a certain "Service" object.                                   *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
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
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
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

 

class Service;

/* 
 * Active connection taking place for authenticating service.
 * Each connection may try to authenticatate more than once before closing,
 * depending on the service. For UDP 1 connection = 1 authentication session.
 */
class Connection
{
	public:
		Connection(Service *serv);
		~Connection();

		int time_started;
		int time_elapsed;

    char *user;
    char *pass;

    /* 
     * True when we peer might close connection at the near moment. 
     * Consider the case, when some services after reaching the maximum
     * authentication limit per connecton, just drop the connection without
     * specifically telling you that you failed at the last authentication
     * attempt. Thus, we use this, to be able to count the correct number of
     * maximum attempts the peer lets us do (stored in 'supported_attempts'
     * inside the Service class). A module should probably set it to true
     * after writing the password on the wire and before issuing the next
     * read call. Also if you use it, don't forget to set it to false, in the
     * first state of your module, because we might need it to differentiate
     * between normal server FINs and FINs/RSTs sent in the middle of an
     * authentication due to strange network conditions.
     */
    bool peer_might_close; 

    /* True if we have received a server reply, that indicated that it didn't
     * close the connection prematurely. This may used in cases, when the
     * server may close the connection after the maximum allowed auth attempts
     * are reached, but will also print a relative message saying we failed.
     */
    bool finished_normally; /* XXX not currently used anywhere */

    bool check_closed;  /* true -> check if peer closed connection on us */
    bool peer_alive;    /* true -> if peer is certain to be alive currently */
    bool auth_complete; /* true -> login pair tested */
    bool from_pool;     /* true -> login pair was extracted from pair_pool */
    bool closed;        /* true -> connection was closed */
    bool auth_success;  /* true -> we found a valid pair!!! */
    bool force_close;   /* true -> forcefully close the connection */

    void *misc_info;    /* additional state information that might be needed */

    /* function pointer to module-specific free operation that deallocates
     * all internal struct members of misc_info 
     */
    void (* ops_free)(Connection *);

    int close_reason;

		int state;          /* module state-machine's current state */

    Buf *inbuf;         /* buffer for inbound data */
    Buf *outbuf;        /* buffer for outbound data */

		unsigned long login_attempts; /* login attempts up until now */
		nsock_iod niod;     /* I/O descriptor for this connection */

    /* This stores our SSL session id, which will help speed up subsequent
     * SSL connections. It's overwritten each time. void* is used so we don't
     * need to #ifdef HAVE_OPENSSL all over. We'll cast later as needed.
     */
     void *ssl_session;    

		Service *service;   /* service it belongs to */
};

enum close_reasons { READ_EOF, READ_TIMEOUT, CON_ERR, CON_TIMEOUT, MODULE_ERR };

