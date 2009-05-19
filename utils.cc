#include "utils.h"
#include "Service.h"
#include "NcrackOps.h"
#include "global_structures.h"
#include <vector>

extern NcrackOps o;
/* global supported services' lookup table from ncrak-services file */
extern vector <service_lookup> ServicesSupported; 
using namespace std;

static int check_duplicate_services(vector <service_lookup *> services, service_lookup *serv);
static unsigned long check_port(char *exp);



static unsigned long
check_port(char *exp)
{
  unsigned long pvalue;
	char *endp = NULL;

	errno = 0;
	pvalue = strtoul(exp, &endp, 0);
	if (errno != 0 || *endp != '\0') 
		fatal("Invalid port number: %s\n", exp);
	if (pvalue > 65535) 
		fatal("Port number too large: %s\n", exp);

	return pvalue;
}


/*
 * Checks for duplicates. Assumes that every service has already
 * been resolved with a name-port.
 */
static int
check_duplicate_services(vector <service_lookup *> services, service_lookup *serv)
{
	vector <service_lookup *>::iterator vi;

	for (vi = services.begin(); vi != services.end(); vi++) {
		if (  //(*vi)->name && !strcmp((*vi)->name, serv->name) &&
				(*vi)->portno == serv->portno) {
			if (o.debugging > 5)
				error("Ignoring duplicate service: '%s:%hu' . Collides with "
						"'%s:%hu'\n", serv->name, serv->portno,
						(*vi)->name, (*vi)->portno);
			return -1;
		}
	}
	return 0;
}



/* 
 * Appends src's elements into dst's as long as no duplicates
 * are created.
 */
void
append_services(vector <service_lookup *> &dst, vector <service_lookup *> src)
{
	unsigned int i, j;
	int dup = 0;

	for (i = 0; i < src.size(); i++) {
		for (j = 0; j < dst.size(); j++) {
			if (src[i]->portno == dst[j]->portno &&
					!strcmp(src[i]->name, dst[j]->name)) {
				if (o.debugging > 5)
					error("Ignoring duplicate service: '%s:%hu'\n",
							src[i]->name, src[i]->portno);
				dup = 1;
				break;
			}
		}
		if (!dup) 
			dst.push_back(src[i]);
	}	
}



/*
 * Checks if current service is supported by looking at
 * the global lookup table ServicesSupported.
 * If a service name has no port, then a default is assigned.
 * If a port has no service name, then the corresponding service
 * name is assigned. Returns -1 if service is not supported.
 */
int 
check_supported_services(service_lookup *serv)
{
	vector <service_lookup>::iterator vi;
	/*
	 * If only port is specified make search based on port.
	 * If only service OR if service:port is specified then
	 * lookup based on service name.
	 */
	if (!serv->name && serv->portno) {
		for (vi = ServicesSupported.begin(); vi != ServicesSupported.end(); vi++) {
			if (vi->portno == serv->portno) {
				serv->name = strdup(vi->name); /* assign service name */
				break;
			}
		}
		if (vi == ServicesSupported.end()) {
			error("Service with default port '%hu' not supported! Ignoring...\n"
					"For non-default ports specify <service-name>:<non-default-port>\n",
					serv->portno);
			return -1;
		}
	} else if (serv->name) {
		for (vi = ServicesSupported.begin(); vi != ServicesSupported.end(); vi++) {
			if (!strcmp(vi->name, serv->name)) {
				if (!serv->portno) /* assign default port number */
					serv->portno = vi->portno;
				break;
			}
		}
		if (vi == ServicesSupported.end()) {
			error("Service with name '%s' not supported! Ignoring...\n",
					serv->name);
			return -1;
		}
	} else 
		fatal("%s failed due to invalid parsing\n", __func__);

	serv->proto = vi->proto;  // TODO: check for UDP (duplicate etc)
	return 0;
}


/* 
 * Parse service/port information from target specification
 * Prepares expression by removing delimiters that separate target-service
 */
int 
parse_services_target(char *const exp, vector <service_lookup *> &services)
{
	char *s1, *s2, *servexp;
	size_t service_len;

	if ((s1 = strchr(exp, '[')) && (s2 = strchr(exp, ']'))) {
		service_len = s2 - s1;
	} else if ((s1 = strstr(exp, "::"))) {
		s1++;
		service_len = strlen(s1);
	} else if ((s1 = strstr(exp, "://"))) {
		s1 += 2;
		service_len = strlen(s1);
 	}	else {
		if (o.debugging > 3) 
			printf("No service specified for TargetGroup %s -- "
						"Valid delimiters are: '::' '://' '[ ]'\n", exp);
		return -1;
	}

	servexp = (char *)safe_zalloc(service_len);
	memcpy(servexp, s1 + 1, service_len - 1);
	return parse_services_handler(servexp, services);
}


/*
 * Service parser - do *not* call directly from target specification
 * since additional parsing needs to be done for the host-service
 * separation delimiters
 */
int 
parse_services_handler(char *const exp, vector <service_lookup *> &services)
{
	unsigned int nports;
	char *temp, *s;
	service_lookup *serv;

	nports = 0;
	while (1) {
		if (nports == 0)
			temp = strtok(exp, ",");
		else
			temp = strtok(NULL, ",");

		if (temp == NULL)
			break;

		serv = (service_lookup *)safe_zalloc(sizeof(service_lookup));

		if (isdigit(temp[0])) { /* just port number */
			serv->portno = (uint16_t)check_port(temp);
		} else {	/* service name and/or port number */
			if ((s = strchr(temp, ':'))) {	/* service name and port number */
				*s = '\0';
				serv->name = strdup(temp);
				serv->portno = (uint16_t)check_port(++s);
			} else	/* service name only */
				serv->name = strdup(temp);
		}	
		nports++;

		/* check if service is supported */
		if (check_supported_services(serv))
			continue;

		/* check for duplicate services */
		if (check_duplicate_services(services, serv))
			continue;

		services.push_back(serv);
	}
	return 0;
}




void
fatal(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}


void error(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
	return;
}

/* Compare a canonical option name (e.g. "max-scan-delay") with a
	 user-generated option such as "max_scan_delay" and returns 0 if the
	 two values are considered equivalant (for example, - and _ are
	 considered to be the same), nonzero otherwise. */
int
optcmp(const char *a, const char *b) {
	while(*a && *b) {
		if (*a == '_' || *a == '-') {
			if (*b != '_' && *b != '-')
				return 1;
		}
		else if (*a != *b)
			return 1;
		a++; b++;
	}
	if (*a || *b)
		return 1;
	return 0;
}


/* convert string to protocol number */
u8
str2proto(char *str)
{
	if (!strcmp(str, "tcp"))
		return IPPROTO_TCP;
	else if (!strcmp(str, "udp"))
		return IPPROTO_UDP;
	else 
		return 0;
}



