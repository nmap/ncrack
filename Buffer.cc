
/***************************************************************************
 * Buffer.cc -- The Buffer class is reponsible for I/O buffer manipulation *
 * and is based on the buffer code used in OpenSSH.                        *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
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
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
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

#include "Buffer.h"

Buffer::Buffer()
{
	const u_int len = 4096;

	alloc = 0;
	buf = (u_char *)safe_malloc(len);
	alloc = len;
	offset = 0;
	end = 0;
}


/* Frees any memory used for the buffer. */
Buffer::~Buffer()
{
	if (alloc > 0) {
		memset(buf, 0, alloc);
		alloc = 0;
    if (buf) {
  		free(buf);
      buf = NULL;
    }
	}
}


/*
 * Clears any data from the buffer, making it empty.  This does not actually
 * zero the memory.
 */
void
Buffer::clear(void)
{
	offset = 0;
	end = 0;
}


/* Appends data to the buffer, expanding it if necessary. */
void
Buffer::append(const void *data, u_int len)
{
	void *p;
	p = append_space(len);
	memcpy(p, data, len);
}


int
Buffer::compact(void)
{
	/*
	 * If the buffer is quite empty, but all data is at the end, move the
	 * data to the beginning.
	 */
	if (offset > MIN(alloc, BUFFER_MAX_CHUNK)) {
		memmove(buf, buf + offset, end - offset);
		end -= offset;
		offset = 0;
		return (1);
	}
	return (0);
}



/*
 * Appends space to the buffer, expanding the buffer if necessary. This does
 * not actually copy the data into the buffer, but instead returns a pointer
 * to the allocated region.
 */
void *
Buffer::append_space(u_int len)
{
	u_int newlen;
	void *p;

	if (len > BUFFER_MAX_CHUNK)
		fatal("buffer_append_space: len %u not supported", len);

	/* If the buffer is empty, start using it from the beginning. */
	if (offset == end) {
		offset = 0;
		end = 0;
	}
restart:
	/* If there is enough space to store all data, store it now. */
	if (end + len < alloc) {
		p = buf + end;
		end += len;
		return p;
	}

	/* Compact data back to the start of the buffer if necessary */
	if (compact())
		goto restart;

	/* Increase the size of the buffer and retry. */
	newlen = roundup(alloc + len, BUFFER_ALLOCSZ);
	if (newlen > BUFFER_MAX_LEN)
		fatal("buffer_append_space: alloc %u not supported",
		    newlen);
	buf = (u_char *)safe_realloc(buf, newlen);
	alloc = newlen;
	goto restart;
	/* NOTREACHED */
}


/*
 * Check whether an allocation of 'len' will fit in the buffer
 * This must follow the same math as buffer_append_space
 */
int
Buffer::check_alloc(u_int len)
{
	if (offset == end) {
		offset = 0;
		end = 0;
	}
 restart:
	if (end + len < alloc)
		return (1);
	if (compact())
		goto restart;
	if (roundup(alloc + len, BUFFER_ALLOCSZ) <= BUFFER_MAX_LEN)
		return (1);
	return (0);
}


/* Returns the number of bytes of data in the buffer. */
u_int
Buffer::get_len(void)
{
	return end - offset;
}


/* Gets data from the beginning of the buffer. */
int
Buffer::buffer_get(void *bufdst, u_int len)
{
	if (len > end - offset) {
		error("buffer_get_ret: trying to get more bytes %d than in buffer %d",
		    len, end - offset);
		return (-1);
	}
	memcpy(bufdst, buf + offset, len);
	offset += len;
	return (0);
}


/* Consumes the given number of bytes from the beginning of the buffer. */

#if 0
int
buffer_consume_ret(Buffer *buffer, u_int bytes)
{
	if (bytes > buffer->end - buffer->offset) {
		error("buffer_consume_ret: trying to get more bytes than in buffer");
		return (-1);
	}
	buffer->offset += bytes;
	return (0);
}

void
buffer_consume(Buffer *buffer, u_int bytes)
{
	if (buffer_consume_ret(buffer, bytes) == -1)
		fatal("buffer_consume: buffer error");
}

/* Consumes the given number of bytes from the end of the buffer. */

int
buffer_consume_end_ret(Buffer *buffer, u_int bytes)
{
	if (bytes > buffer->end - buffer->offset)
		return (-1);
	buffer->end -= bytes;
	return (0);
}

void
buffer_consume_end(Buffer *buffer, u_int bytes)
{
	if (buffer_consume_end_ret(buffer, bytes) == -1)
		fatal("buffer_consume_end: trying to get more bytes than in buffer");
}

/* Returns a pointer to the first used byte in the buffer. */

void *
buffer_ptr(Buffer *buffer)
{
	return buffer->buf + buffer->offset;
}

/* Dumps the contents of the buffer to stderr. */

void
buffer_dump(Buffer *buffer)
{
	FILE *fp = fopen("/home/sin/output", "a");
	if (!fp)
		return;
	u_int i;
	u_char *ucp = buffer->buf;

	for (i = buffer->offset; i < buffer->end; i++) {
		fprintf(fp, "%02x", ucp[i]);
		if ((i-buffer->offset)%16==15)
			fprintf(fp, "\r\n");
		else if ((i-buffer->offset)%2==1)
			fprintf(fp, " ");
	}
	fprintf(fp, "\r\n");
	fclose(fp);
}
#endif
