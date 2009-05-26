#ifndef SERVICES_H
#define SERVICES_H 1

#include "global_structures.h"
#include "Service.h"
#include <vector>
using namespace std;

/* target-service specification */
typedef struct ts_spec {
	char *service_name;
	char *host_expr;
	char *service_options;
	char *portno;
} ts_spec;


/* parse service/port information for Ncrack */
ts_spec parse_services_target(char *const exp);
void parse_module_options(char *const exp);
void apply_service_options(Service *service);
void apply_host_options(Service *service, char *const options);
void parse_services(char *const exp, vector <service_lookup *> &services);
void clean_spec(ts_spec *spec);

#endif
