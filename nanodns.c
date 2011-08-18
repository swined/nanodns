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

int dnsNameLen(char *name) {
	int i = 0;
	while (name[i])
		i += name[i] + 1;
	return i + 1;
}

int dnsNameEquals(char *a, char *b) {
	int i;
	if (a[0] != b[0])
		return 0;
	if (a[0] == 0)
		return 1;
	for (i = 0; i < a[0]; i++)
		if (a[i + 1] != b[i + 1])
			return 0;
	return dnsNameEquals(&a[a[0]], &b[b[0]]);
}

int dnsNameEndsWith(char *name, char *end) {
	return 0;
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
