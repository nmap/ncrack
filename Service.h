#ifndef SERVICE_H
#define SERVICE_H

#include "ncrack.h"



class Service
{
	public:
		Service();
		~Service();

		char *name;
		char *proto;
		u16 portno;

		int done;

		/* timing options that override global ones */
		unsigned int attempts_min;
		unsigned int timeout;

		// TODO: complete with more here

};





#endif 
