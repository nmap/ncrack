
/***************************************************************************
 * nsock_ssl.c -- This contains functions that relate somewhat exclusively *
 * to SSL (over TCP) support in nsock.  Where SSL support is incidental,   *
 * it is often in other files where code can be more easily shared between *
 * the SSL and NonSSL paths.                                               *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *                                                                         *
 * The nsock parallel socket event library is (C) 1999-2009 Insecure.Com   *
 * LLC This library is free software; you may redistribute and/or          *
 * modify it under the terms of the GNU General Public License as          *
 * published by the Free Software Foundation; Version 2.  This guarantees  *
 * your right to use, modify, and redistribute this software under certain *
 * conditions.  If this license is unacceptable to you, Insecure.Com LLC   *
 * may be willing to sell alternative licenses (contact                    *
 * sales@insecure.com ).                                                   *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         * 
 * If you received these files with a written license agreement stating    *
 * terms other than the (GPL) terms above, then that alternative license   *
 * agreement takes precedence over this comment.                          *
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
 * General Public License v2.0 for more details                            *
 * (http://www.gnu.org/licenses/gpl-2.0.html).                             *
 *                                                                         *
 ***************************************************************************/

/* $Id: nsock_ssl.c 12956 2009-04-15 00:37:23Z fyodor $ */


#include "nsock.h"
#include "nsock_internal.h"
#include "nsock_ssl.h"
#include "netutils.h"

#if HAVE_OPENSSL

extern struct timeval nsock_tod;

static struct NsockSSLInfo *sslnfo = NULL;

/* Initializes Nsock for low security (fast) SSL connections.
 Eventually it will probably have arguments for various attributes
 (such as whether you want the connection to be fast or secure).  It is
 OK to call it multiple times - only the first one will count.  */
void Nsock_SSL_Init() {
  char rndbuf[128];

  if (sslnfo)
    return; /* Already done */

  sslnfo = (struct NsockSSLInfo *) safe_zalloc(sizeof(*sslnfo));

  SSL_load_error_strings();
  SSL_library_init();
  
  /* Note that we are assuming the SSL connections don't have to
     be high security */
  get_random_bytes(rndbuf, sizeof(rndbuf));
  RAND_seed(rndbuf, sizeof(rndbuf));

  sslnfo->ctx = SSL_CTX_new( SSLv23_client_method() );
  if ( ! sslnfo->ctx ) {
    fatal("OpenSSL failed to create a new SSL_CTX: %s", 
	  ERR_error_string(ERR_get_error(), NULL));
  }
  
  /* set us to ignore cert entirely */
  SSL_CTX_set_verify( sslnfo->ctx, SSL_VERIFY_NONE, NULL );   

  /* set bug-compatibility for pretty much everything. */
  SSL_CTX_set_options( sslnfo->ctx, SSL_OP_ALL );

  /* Accept any and all ciphers, including none.  Since speed, not security, is
     our goal, the list below is sorted by speed, based on Brian Hatch's (bri@ifokr.org)
     tests on an Pentium 686 against the ciphers listed.  Nmap's typical
     version scanning connections are short and sweet, so the actual speed
     difference isn't terribly great anyway. */
  if (!SSL_CTX_set_cipher_list( sslnfo->ctx, 
				"RC4-SHA:RC4-MD5:NULL-SHA:EXP-DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-RC4-MD5:NULL-MD5:EDH-RSA-DES-CBC-SHA:EXP-RC2-CBC-MD5:EDH-RSA-DES-CBC3-SHA:EXP-ADH-RC4-MD5:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:EXP-ADH-DES-CBC-SHA:ADH-AES256-SHA:ADH-DES-CBC-SHA:ADH-RC4-MD5:AES256-SHA:DES-CBC-SHA:DES-CBC3-SHA:ADH-DES-CBC3-SHA:AES128-SHA:ADH-AES128-SHA:eNULL:ALL")) {
    fatal("Unable to set OpenSSL cipher list: %s", 
	  ERR_error_string(ERR_get_error(), NULL));
  }


  /* Our SSL* will always have the SSL_SESSION* inside it, so we neither
     need to use nor waste memory for the session cache.
     (Use '1' because '0' means 'infinite'.)   */
  SSL_CTX_set_session_cache_mode(
     sslnfo->ctx,  SSL_SESS_CACHE_OFF | SSL_SESS_CACHE_NO_AUTO_CLEAR );
  SSL_CTX_sess_set_cache_size( sslnfo->ctx, 1 ); 
  SSL_CTX_set_timeout( sslnfo->ctx, 3600); /* pretty unnecessary */

}

/* This function returns the Nsock Global SSL information.  You should
   have called Nsock_SSL_Init once before, but this function will take
   care of it if you haven't. */
struct NsockSSLInfo *Nsock_SSLGetInfo() {

  if (!sslnfo)
    Nsock_SSL_Init();

  return sslnfo;
}
#endif /* HAVE_OPENSSL */
