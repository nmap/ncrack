/***************************************************************************
 * ncrack_firebird.cc -- ncrack module for firebird database               *                   *
 * Created by Barrend                                                      *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2018 Insecure.Com LLC ("The Nmap  *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed Nmap technology into proprietary      *
 * software, we sell alternative licenses (contact sales@nmap.com).        *
 * Dozens of software vendors already license Nmap technology such as      *
 * host discovery, port scanning, OS detection, version detection, and     *
 * the Nmap Scripting Engine.                                              *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, the Nmap Project grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * The Nmap Project has permission to redistribute Npcap, a packet         *
 * capturing driver and library for the Microsoft Windows platform.        *
 * Npcap is a separate work with it's own license rather than this Nmap    *
 * license.  Since the Npcap license does not permit redistribution        *
 * without special permission, our Nmap Windows binary packages which      *
 * contain Npcap may not be redistributed without special permission.      *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, we are happy to help.  As mentioned above, we also *
 * offer an alternative license to integrate Nmap into proprietary         *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing support and updates.  They also fund the continued         *
 * development of Nmap.  Please email sales@nmap.com for further           *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify            *
 * otherwise) that you are offering the Nmap Project the unlimited,        *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because     *
 * the inability to relicense code has caused devastating problems for     *
 * other Free Software projects (such as KDE and NASM).  We also           *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/
#include "ncrack.h"
#include "nsock.h"
#include "NcrackOps.h"
#include "Service.h"
#include "modules.h"
#define FB_TIMEOUT 20000 //here
#define DEFAULT_DB "/var/lib/firebird/3.0/data/employee.fdb"

#include <unistd.h>   // isatty()
#define API_ROUTINE

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

//typedef unsigned char* VoidPtr;
typedef void* VoidPtr;
//-----------------------------------------------------------------------

#define LINEFORMAT "d"
#define ALLOC_ARGS
//#define ISQL_ALLOC(x)	gds__alloc(x)
#define ISQL_ALLOC(x)	gds__alloc(long)
#define fb_assert(x) assert(x) //fb_assert definition
//VoidPtr API_ROUTINE gds__alloc(signed long);
unsigned char API_ROUTINE gds__alloc(signed long size_request)
{
    return getDefaultMemoryPool()->allocate(size_request ALLOC_ARGS);
}


#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
#define  ISC_EXPORT __stdcall
#define  ISC_EXPORT_VARARG  __cdecl
#else
#define  ISC_EXPORT
#define  ISC_EXPORT_VARARG
#endif

#define FB_SUCCESS	0
#define	FB_FAILURE	1

#define isc_dpb_version1			1
#define isc_dpb_user_name			28
#define isc_dpb_password			29
#define isc_dpb_lc_messages		47
#define isc_dpb_lc_ctype			48
#define	isc_dpb_reserved			53
#define isc_dpb_sql_role_name	60

#if defined(_LP64) || defined(__LP64__) || defined(__arch64__) || defined(_WIN64)
typedef unsigned int  FB_API_HANDLE;
#else
typedef void*   FB_API_HANDLE;
#endif

#if defined(_LP64) || defined(__LP64__) || defined(__arch64__)
typedef int       ISC_LONG;
typedef unsigned int  ISC_ULONG;
#else
typedef signed long   ISC_LONG;
typedef unsigned long ISC_ULONG;
#endif


typedef FB_API_HANDLE isc_db_handle;
typedef char ISC_SCHAR;
typedef intptr_t ISC_STATUS;

#define ISC_STATUS_LENGTH 20

/*unsigned char API_ROUTINE gds__alloc(signed long size_request)
{
  try
  {
    return getDefaultMemoryPool()->allocate(size_request ALLOC_ARGS);
  }
  catch (const Firebird::Exception&)
  {
    return NULL;
  }
}*/

#define MAX_UCHAR 0xFF		

int ISC_EXPORT isc_modify_dpb(ISC_SCHAR** dpb, short* dpb_size, unsigned short type,ISC_SCHAR* str, short str_len)
{
/**************************************
 *
 *	i s c _ m o d i f y _ d p b
 *
 **************************************
 * CVC: This is exactly the same logic as isc_expand_dpb, but for one param.
 * However, the difference is that when presented with a dpb type it that's
 * unknown, it returns FB_FAILURE immediately. In contrast, isc_expand_dpb
 * doesn't complain and instead treats those as integers and tries to skip
 * them, hoping to sync in the next iteration.
 *
 * Functional description
 *	Extend a database parameter block dynamically
 *	to include runtime info.  Generated
 *	by gpre to provide host variable support for
 *	READY statement	options.
 *	This expects one arg at a time.
 *      the length of the string is passed by the caller and hence
 * 	is not expected to be null terminated.
 * 	this call is a variation of isc_expand_dpb without a variable
 * 	arg parameters.
 * 	Instead, this function is called recursively
 *	Alternatively, this can have a parameter list with all possible
 *	parameters either nulled or with proper value and type.
 *
 *  	**** This can be modified to be so at a later date, making sure
 *	**** all callers follow the same convention
 *
 *	Note: dpb_size is signed short only for compatibility
 *	with other calls (isc_attach_database) that take a dpb length.
 *
 **************************************/

	// calculate length of database parameter block, setting initial length to include version
	short new_dpb_length;

	if (!*dpb || !(new_dpb_length = *dpb_size))
	{
		new_dpb_length = 1;
	}

	switch (type)
	{
	case isc_dpb_user_name:
	case isc_dpb_password:
	case isc_dpb_sql_role_name:
	case isc_dpb_lc_messages:
	case isc_dpb_lc_ctype:
	case isc_dpb_reserved:
		new_dpb_length += 2 + str_len;
		break;

	default:
		return FB_FAILURE;
	}

	// if items have been added, allocate space

	unsigned char* new_dpb;
	if (new_dpb_length > *dpb_size)
	{
		// Note: gds__free done by GPRE generated code

		new_dpb = (unsigned char*) gds__alloc((signed long)(sizeof(unsigned char) * new_dpb_length));

		// FREE: done by client process in GPRE generated code
		if (!new_dpb)
		{
			// NOMEM: don't trash existing dpb
			return FB_FAILURE;		// NOMEM: not really handled
		}

		memcpy(new_dpb, *dpb, *dpb_size);
	}
	else
		new_dpb = reinterpret_cast<unsigned char*>(*dpb);

	unsigned char* p = new_dpb + *dpb_size;

	if (!*dpb_size)
	{
		*p++ = isc_dpb_version1;
	}

	// copy in the new runtime items

	switch (type)
	{
	case isc_dpb_user_name:
	case isc_dpb_password:
	case isc_dpb_sql_role_name:
	case isc_dpb_lc_messages:
	case isc_dpb_lc_ctype:
	case isc_dpb_reserved:
		{
			const unsigned char* q = reinterpret_cast<const unsigned char*>(str);
			if (q)
			{
				short length = str_len;
				fb_assert(type <= MAX_UCHAR);
				*p++ = (unsigned char) type;
				fb_assert(length <= MAX_UCHAR);
				*p++ = (unsigned char) length;
				while (length--)
				{
					*p++ = *q++;
				}
			}
			break;
		}

	default:
		return FB_FAILURE;
	}
		*dpb_size = p - new_dpb;
	*dpb = (ISC_SCHAR*) new_dpb;

	return FB_SUCCESS;
}


typedef ISC_STATUS ISC_STATUS_ARRAY[ISC_STATUS_LENGTH];
int ISC_EXPORT isc_modify_dpb(ISC_SCHAR**, short*, unsigned short, const ISC_SCHAR*, short);

ISC_STATUS ISC_EXPORT isc_attach_database(ISC_STATUS*, short, const ISC_SCHAR*, isc_db_handle*, short, const ISC_SCHAR*);
ISC_STATUS ISC_EXPORT isc_detach_database(ISC_STATUS *, isc_db_handle *);
ISC_LONG ISC_EXPORT isc_free(ISC_SCHAR *);


//---------------------------------------------------

static int firebird_loop_read(nsock_pool nsp, Connection *con);
    
enum states { FB_INIT, FB_USER };


static int
firebird_loop_read(nsock_pool nsp, Connection *con)
{
  if ((con->inbuf == NULL) || !memsearch((const char *)con->inbuf->get_dataptr(), "Symmetric\n", con->inbuf->get_len())) {
    nsock_read(nsp, con->niod, ncrack_read_handler, FB_TIMEOUT, con);
    return -1;
  }

  return 0;
}

void
ncrack_firebird(nsock_pool nsp, Connection *con)
{
  //nsock_iod nsi = con->niod;
  char database[256];
  char connection_string[1024];
	int ret;
  isc_db_handle db;
  ISC_STATUS_ARRAY status;
  char *dpb = NULL;
  short dpb_length = 0;
  Service *serv=0; 
	
	switch(con->state)
  {
    
    case FB_INIT:
    
    	strncpy(database, DEFAULT_DB, sizeof(database));
    	database[sizeof(database)-1] = 0;
    
    	if (con->outbuf) 
      	delete con->outbuf;
    	con->outbuf = new Buf();
      
      dpb_length=(short) (1+ strlen(con->user) + 2 + strlen(con->pass) +2);  
      if ((dpb = (char *) malloc(dpb_length)) == NULL)  //no database data found
      {
        printf("Invalid database path");
      }
			*dpb = isc_dpb_version1;
			dpb_length=1;
      //isc_modify_dpb(&dpb, &dpb_length, isc_dpb_user_name, "%s" , strlen(con->user));
      isc_modify_dpb(&dpb, &dpb_length, isc_dpb_user_name, con->user , strlen(con->user));
      isc_modify_dpb(&dpb, &dpb_length, isc_dpb_password, con->pass, strlen(con->pass));
 			snprintf(connection_string, sizeof(connection_string), "%s:%s", serv->target->NameIP(), database);
      //con->outbuf->snprintf(sizeof(serv->target->NameIP()) + sizeof(database), "%s:%s", serv->target->NameIP(), database);
	 		//nsock_write(nsp, nsi, ncrack_write_handler, FB_TIMEOUT, con, (const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
      con->state = FB_USER;
     
      if(isc_attach_database(status, 0, connection_string, &db, dpb_length, dpb)) {
        isc_free(dpb);
				if ((ret = firebird_loop_read(nsp, con)) == 0)
					break;
			else {
        isc_detach_database(status, &db);
        isc_free(dpb);
				con->auth_success = true;
				}
			}
      return ncrack_module_end(nsp, con);
   } 
}

//#endif
