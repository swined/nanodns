#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdint.h>

typedef struct {
	uint16_t type;
	char *mask;
	char *data;
} Record;

typedef struct {
	char *name;
	uint16_t length;
	Record *records;
} Zone;

#endif
