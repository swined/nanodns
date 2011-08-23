#ifndef _CONFIG_H
#define _CONFIG_H

typedef struct {
	short type;
	char *mask;
	char *data;
} Record;

typedef struct {
	char *name;
	unsigned int length;
	Record *records;
} Zone;

#endif
