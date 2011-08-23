#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdint.h>
#include <arpa/nameser.h> 

typedef struct {
	ns_type type;
	char *mask;
	char *data;
} Record;

typedef struct {
	char *name;
	uint16_t length;
	Record *records;
} Zone;

#endif
