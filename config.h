#ifndef _CONFIG_H
#define _CONFIG_H

#include <arpa/nameser.h> 

typedef struct {
	ns_type type;
	char *mask;
	char *data;
} Record;

typedef struct {
	char *name;
	int length;
	Record *records;
} Zone;

#endif
