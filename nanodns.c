#include <arpa/inet.h>

#pragma pack(1)

typedef struct {
	unsigned short id;
	unsigned char a, b;
	unsigned short qd, an, ns, ar;
	unsigned char data[512];
} DnsHeader;

typedef struct {
	char *name;
} Zone;

typedef struct {
	unsigned int count;
	Zone *zones;
} Zones;

extern int printf (__const char *__restrict __format, ...);
extern int close (int __fd);
extern void bzero(void *t, size_t l);

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

int main(int a, char **b) {
	int sock = listenUdp(53);
	uint32_t i;
	struct sockaddr_in d;
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
		printf("%s\n", header.data);
	}
	close(sock);
	return 0;
}
