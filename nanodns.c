#include <arpa/inet.h>

#define ZONE(name, recs) { (name), sizeof(recs) / sizeof(Record), recs }

#pragma pack(1)

typedef struct {
	unsigned short id;
	unsigned char a, b;
	unsigned short qd, an, ns, ar;
	char data[512];
} DnsHeader;

typedef struct {
	unsigned int type;
	unsigned int cls;
	unsigned int len; 
	unsigned char mask[16];
	unsigned char data[16];
} Record;

typedef struct {
	char *name;
	unsigned int length;
	Record *records;
} Zone;

extern int printf (__const char *__restrict __format, ...);
extern int close (int __fd);
extern void bzero(void *t, size_t l);
extern int strcmp(const char *s1, const char *s2);
extern size_t strlen ( const char * str );

Record zone_swined_net_ru[] = {
	{ 1, 2, 3, "4", "5" },
};

Zone zones[] = {
	ZONE(".swined.net.ru", zone_swined_net_ru),
	ZONE(".xwined.net.ru", zone_swined_net_ru),
};

int findChar(char *s, char c) {
	int o = 0;
	while (s[o] && (s[o] != c))
		o++;
	return o;
}

void strToDns(char *str, char *dns) {
	int i, l = strlen(str);
	for (i = 0; i <= l; i++)
		dns[i] = (str[i] == '.') ? (char)findChar(str + i + 1, '.') : str[i];
}

int dnsNameEndsWith(char *name, char *end) {
	if (0 == strcmp(name, end))
		return 1;
	if (0 == name[0])
		return 0;
	return dnsNameEndsWith(&(name[name[0]+1]), end);
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

char getOpcode(DnsHeader *header) {
	return (header->a >> 4) & 7;
}

int zoneMatches(Zone *zone, char *query) {
	char name[64];
	strToDns(zone->name, name);
	return dnsNameEndsWith(query, name);
}

Zone *findZone(char *query) {
	int i, l = sizeof(zones) / sizeof(Zone);
	for (i = 0; i < l; i++)
		if (zoneMatches(&zones[i], query))
			return &zones[i];
	return 0;
}

int main(int a, char **b) {
	int sock = listenUdp(53);
	uint32_t i;
	struct sockaddr_in d;
	Zone *zone;
	DnsHeader header;
	socklen_t f = 511;
	if (sock < 0) {
		printf("bind() failed\n");
		return 1;
	}
	for (;;) {
		i = recvfrom(sock, &header, 255, 0, (struct sockaddr*)&d, &f);
		printf("id=%d opcode=%d qd=%d an=%d ns=%d ar=%d\n",
			ntohs(header.id),
			getOpcode(&header),
			ntohs(header.qd),
			ntohs(header.an),
			ntohs(header.ns),
			ntohs(header.ar)
		);
		zone = findZone(header.data);
		if (zone)
			printf("zone: %s\n", zone->name);
		printf("%s\n", header.data);
	}
	close(sock);
	return 0;
}
