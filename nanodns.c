#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include "config.h"

// #define DEBUG 

#define DATA_SIZE	1024
#define MSG_SIZE	DATA_SIZE + sizeof(HEADER)

#pragma pack(1)

typedef struct {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t length;
	union {
		uint32_t i;
		char d[0];	
	} data;
} Answer;

typedef struct {
	struct sockaddr_in from;
	HEADER header;
	char data[DATA_SIZE];
} DnsMessage;

#define TTL 3600

extern Zone zones[];
extern int zoneCount;

int findChar(char *s, char c) {
	int o = 0;
	while (s[o] && (s[o] != c))
		o++;
	return o;
}


void dots(char *str) {
	int i;
        for (i = 0; i < strlen(str); i++)
                if (str[i] == '.')
                        str[i] = findChar(str + i + 1, '.');
}

int qnameEqualsStr(char *name, char *str) {
	int so = findChar(str, '.');
	if (so != name[0])
		return 0;
	if (so == 0)
		return 1;
	if (strncmp(name + 1, str, so) != 0)
		return 0;
	return qnameEqualsStr(name + so + 1, str + so + 1);
}

int listenUdp(int port) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in sockaddr;
	bzero(&sockaddr, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);
	if (bind(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == 0)
		return sock;
	else {
		close(sock);
		return -1;
	}
}

int match(Zone *zone, char *query, char *sub) {
	int len = query[0];
	sub[0] = 0;
	if (!len)
		return 0;
	if (qnameEqualsStr(query, zone->name))
		return 1;
	strncpy(sub, query + 1, len);
	sub[len] = '.';
	return match(zone, query + len + 1, sub + len + 1);
}

Zone *findZone(char *query, char *sub) {
	int i;
	for (i = 0; i < zoneCount; i++)
		if (match(&zones[i], query, sub))
			return &zones[i];
	return 0;
}

short getType(char *query) {
        return ntohs(*(short*)(query + strlen(query) + 1));
}

#define getClass(q) ntohs(*(short*)(q + strlen(q) + 3))

int receive(int sock, DnsMessage *msg) {
	socklen_t f = sizeof(struct sockaddr_in);
	int r = recvfrom(sock, &msg->header, MSG_SIZE, 0, (struct sockaddr*)&msg->from, &f);
	return (r >= sizeof(HEADER)) && (r < MSG_SIZE);
}

#define qrLength(q) strlen(q) + 5

int rrLength(char *rr) {
	return strlen(rr) + 11 + ntohs(*(short*)(rr + strlen(rr) + 9));
}

#define rrCount(h) (ntohs((h).ancount) + ntohs((h).nscount) + ntohs((h).arcount))

int messageLength(DnsMessage *msg) {
	int i, offset = 0;
	for (i = 0; i < ntohs(msg->header.qdcount); i++)
		offset += qrLength(msg->data + offset);
	for (i = 0; i < rrCount(msg->header); i++)
		offset += rrLength(msg->data + offset);
	return offset;
}

void reply(int sock, DnsMessage *msg, ns_rcode errCode, int aa) {
	msg->header.qr = 1;
	msg->header.aa = aa;
	msg->header.tc = 0;
	msg->header.rd = 0;
	msg->header.ra = 1;
	msg->header.ad = 0;
	msg->header.cd = 0;
	msg->header.rcode = errCode;
	sendto(sock, &msg->header, sizeof(HEADER) + messageLength(msg), 0, (struct sockaddr*)&msg->from, sizeof(struct sockaddr_in)); 
}

void append(DnsMessage *msg, char *query, Record *rec) {
	int offset = messageLength(msg);
	Answer *answer; 
	strcpy(msg->data + offset, query);
	dots(msg->data + offset);
	offset += strlen(query) + 1;
	answer = (Answer*)(msg->data + offset);
	answer->type = htons(rec->type);
	answer->class = htons(ns_c_in);
	answer->ttl = htonl(TTL);
	switch (rec->type) {
	case ns_t_a:
		answer->length = htons(4);
		answer->data.i = inet_addr(rec->data);
		break;
	case ns_t_ns:
	case ns_t_cname:
		answer->length = htons(strlen(rec->data) + 1);
		strcpy(answer->data.d, rec->data);
		dots(answer->data.d);
		break;
	default:
		answer->length = 0;
	}
	msg->header.ancount = htons(ntohs(msg->header.ancount) + 1);
}

int rrA(Record *rec, char *host) {	
	struct addrinfo *r;
	rec->type = ns_t_a;
	rec->mask = "<recursive>";
	rec->data = "127.0.0.1";
	if (getaddrinfo(host, NULL, NULL, &r))
		return 0;
	rec->data = inet_ntoa(((struct sockaddr_in*)(r->ai_addr))->sin_addr);
	freeaddrinfo(r);
	return 1;
}

int maskMatches(Record *rec, char *sub, int direct) {
	if (direct) {
		return !strcmp(rec->mask, sub);
	} else {
		return strlen(sub) && !strcmp(rec->mask, "*");
	}
}

int appendRecursiveA(DnsMessage *msg, char *host) {
	Record recursive;
	if (rrA(&recursive, host + 1)) {
		append(msg, host, &recursive);
		return 1;
	} else return 0;
}

int search(DnsMessage *msg, Zone *zone, char *sub, int type, int direct, int fake) {
	int i, r = 0;
	for (i = 0; i < zone->length; i++) {
		if (zone->records[i].type != (fake ? ns_t_cname : type))
			continue;
		if (maskMatches(&zone->records[i], sub, direct)) {
			append(msg, msg->data, &zone->records[i]);
			if (fake) {
				if (appendRecursiveA(msg, zone->records[i].data)) {
					r++;
					break;
				}
			} else r++;
		}
	}
	if (!r) {
		if (direct)
			return search(msg, zone, sub, type, 0, fake);
		if (!fake && (type == ns_t_a))
			return search(msg, zone, sub, type, 1, 1);
	}
	return r;
}

int isBadHead(HEADER *h) {
	return h->qr || h->opcode || h->tc || rrCount(*h) || (ntohs(h->qdcount) != 1);
}

void run(int sock) {
        Zone *zone;
        char sub[DATA_SIZE];
        DnsMessage msg;
        while (1) {
                if (!receive(sock, &msg))
                        continue;
                if (isBadHead(&msg.header) || (getClass(msg.data) != ns_c_in)) {
                        reply(sock, &msg, ns_r_notimpl, 0);
                        continue;
                }
		#ifdef DEBUG
		printf("query: %s (%d)\n", msg.data, getType(msg.data));
		#endif
                zone = findZone(msg.data, sub);
                if (zone) {
			#ifdef DEBUG
			printf("zone: %s\n", zone->name);
			#endif
                        search(&msg, zone, sub, getType(msg.data), 1, 0);
                        reply(sock, &msg, ns_r_noerror, 1);
                } else {
			#ifdef DEBUG
			printf("no zone\n");
			#endif
                        reply(sock, &msg, ns_r_refused, 0);
		}
        } 
}

int main(int a, char **b) {
	int sock;
#ifndef DEBUG
	if (fork())
		return 0;
#endif
	sock = listenUdp(53);
	if (sock) 
		run(sock);
	close(sock);
	return 0;
}

