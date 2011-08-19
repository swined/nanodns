#include <arpa/inet.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>

#define DATA_SIZE	1024
#define MSG_SIZE	DATA_SIZE + sizeof(DnsHeader)

#define CLASS_IN	1

#define TYPE_A               1
#define TYPE_NS              2
#define TYPE_CNAME           5
#define TYPE_SOA             6
#define TYPE_PTR             12
#define TYPE_MX              15
#define TYPE_TXT             16

#define ZONE(name, recs) { name, sizeof(recs) / sizeof(Record), recs }

#pragma pack(1)

typedef struct {
	unsigned short id;
	unsigned char a, b;
	unsigned short qd, an, ns, ar;
} DnsHeader;

typedef struct {
	struct sockaddr_in from;
	DnsHeader header;
	char data[DATA_SIZE];
} DnsMessage;

typedef struct {
	unsigned int type;
	char *mask;
	char *data;
} Record;

typedef struct {
	char *name;
	unsigned int length;
	Record *records;
} Zone;

#define DEFAULT_NS { TYPE_NS, "", "ns0.swined.net.ru" }, { TYPE_NS, "", "ns1.swined.net.ru" }
#define HOME_A { TYPE_A, "", "85.118.231.99" }
#define FIRSTVDS_A { TYPE_A, "", "188.120.227.223" }, { TYPE_A, "", "62.109.23.110" }

Record zone_sw_vg[] = { 
	DEFAULT_NS,
	HOME_A,
};

Record zone_swined_org[] = {
	DEFAULT_NS,
	FIRSTVDS_A,
};

Zone zones[] = {
	ZONE("sw.vg.", zone_sw_vg),
	ZONE("swined.org.", zone_swined_org),
};

int findChar(char *s, char c) {
	int o = 0;
	while (s[o] && (s[o] != c))
		o++;
	return o;
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
	int i, l = sizeof(zones) / sizeof(Zone);
	for (i = 0; i < l; i++)
		if (match(&zones[i], query, sub))
			return &zones[i];
	return 0;
}

int receive(int sock, DnsMessage *msg) {
	socklen_t f = sizeof(struct sockaddr_in);
	int r = recvfrom(sock, &msg->header, MSG_SIZE, 0, (struct sockaddr*)&msg->from, &f);
	return (r >= sizeof(DnsHeader)) && (r < MSG_SIZE);
}

int main(int a, char **b) {
	int sock = listenUdp(53);
	Zone *zone;
	char sub[DATA_SIZE];
	DnsMessage msg;
	if (sock < 0) {
		printf("bind() failed\n");
		return 1;
	}
	while (1) {
		if (!receive(sock, &msg)) 
			continue;
		printf("id=%d\n", ntohs(msg.header.id));
		zone = findZone(msg.data, sub);
		if (zone)
			printf("zone: '%s' sub: '%s'\n", zone->name, sub);
	}	
	close(sock);
	return 0;
}
