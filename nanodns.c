#include <arpa/inet.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>

#define DATA_SIZE	1024
#define MSG_SIZE	DATA_SIZE + sizeof(DnsHeader)

#define ERR_OK 0
#define ERR_FORMAT 1
#define ERR_SERVFAIL 2
#define ERR_NXDOMAIN 3
#define ERR_NOTIMPL 4
#define ERR_REFUSED 5

#define CLASS_IN	1

#define TYPE_A               1
#define TYPE_NS              2
#define TYPE_CNAME           5
/*#define TYPE_SOA             6
#define TYPE_PTR             12
#define TYPE_MX              15
#define TYPE_TXT             16*/

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
	short type;
	char *mask;
	char *data;
} Record;

typedef struct {
	char *name;
	unsigned int length;
	Record *records;
} Zone;

#define TTL 3600
#define DEFAULT_NS { TYPE_NS, "", ".ns0.swined.net.ru" }, { TYPE_NS, "", ".ns1.swined.net.ru" }
#define GHS_CNAME { TYPE_CNAME, "*", ".ghs.google.com" }
#define HOME_A { TYPE_A, "", "85.118.231.99" }
#define NSSRV_A_0 "188.120.227.223"
#define NSSRV_A_1 "62.109.23.110"
#define NSSRV_A { TYPE_A, "", NSSRV_A_0 }, { TYPE_A, "", NSSRV_A_1 }

Record zone_ghs[] = {
	DEFAULT_NS,
	NSSRV_A,
	GHS_CNAME,
};

Record zone_swined_net_ru[] = {
	DEFAULT_NS,
	NSSRV_A,
	{ TYPE_A, "ns0.", NSSRV_A_0 },
	{ TYPE_A, "ns1.", NSSRV_A_1 },
};

Record zone_sw_vg[] = { 
	DEFAULT_NS,
	HOME_A,
	GHS_CNAME,
	{ TYPE_A, "lms.", "216.208.29.154" },
};

Record zone_swined_org[] = {
	DEFAULT_NS,
	NSSRV_A,
	{ TYPE_CNAME, "blog.", ".ghs.google.com" },
	{ TYPE_CNAME, "lr.", ".ghs.google.com" },
};

Zone zones[] = {
	ZONE("swined.net.ru.", zone_swined_net_ru),
	ZONE("sw.vg.", zone_sw_vg),
	ZONE("swined.org.", zone_swined_org),
	ZONE("proofpic.org.", zone_ghs),
	ZONE("p-ic.org.", zone_ghs),
	ZONE("prooflink.org.", zone_ghs),
};

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
	int i, l = sizeof(zones) / sizeof(Zone);
	for (i = 0; i < l; i++)
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
	return (r >= sizeof(DnsHeader)) && (r < MSG_SIZE);
}

#define qrLength(q) strlen(q) + 5

int rrLength(char *rr) {
	return strlen(rr) + 11 + ntohs(*(short*)(rr + strlen(rr) + 9));
}

int rrCount(DnsMessage *msg) {
	DnsHeader *h = &msg->header;
	return ntohs(h->an) + ntohs(h->ns) + ntohs(h->ar);
}

int messageLength(DnsMessage *msg) {
	int i, offset = 0;
	for (i = 0; i < ntohs(msg->header.qd); i++)
		offset += qrLength(msg->data + offset);
	for (i = 0; i < rrCount(msg); i++)
		offset += rrLength(msg->data + offset);
	return offset;
}

void reply(int sock, DnsMessage *msg, int errCode, int aa) {
	int op = (msg->header.a >> 3) & 7;
	msg->header.a = 0x80 | (op << 3) | (aa ? 4 : 0);
	msg->header.b = errCode & 0x0F;
	sendto(sock, &msg->header, sizeof(DnsHeader) + messageLength(msg), 0, (struct sockaddr*)&msg->from, sizeof(struct sockaddr_in)); 
}

void append(DnsMessage *msg, char *query, Record *rec) {
	int offset = messageLength(msg);
	short *rdlen;
	char *rddata;
	strcpy(msg->data + offset, query);
	dots(msg->data + offset);
	offset += strlen(query) + 1;
	*(short*)(msg->data + offset) = htons(rec->type);
	*(short*)(msg->data + offset + 2) = htons(CLASS_IN);
	*(int*)(msg->data + offset + 4) = htons(TTL);
        rdlen = (short*)(msg->data + offset + 8);
        rddata = msg->data + offset + 10;
	switch (rec->type) {
	case TYPE_A:
		*rdlen = htons(4);
		*(int*)rddata = inet_addr(rec->data);
		break;
	case TYPE_NS:
	case TYPE_CNAME:
		*rdlen = htons(strlen(rec->data) + 1);
		strcpy(rddata, rec->data);
		dots(rddata);
		break;
	default:
		*rdlen = 0;
	}
	msg->header.an = htons(ntohs(msg->header.an) + 1);
}

int initFakeRec(Record *rec, char *data) {
	struct hostent *he;
	switch (rec->type) {
		case TYPE_A: 
			he = gethostbyname(data);
			if (he)
				strcpy(rec->data, inet_ntoa(*(struct in_addr*)(he->h_addr_list)));
			return he != 0;
		default: return 0;
	}
}

int search(DnsMessage *msg, Zone *zone, char *sub, int type, int direct, int fake) {
	char fakeData[DATA_SIZE];
	Record fakeRec = { 0, "", 0 };
	int i, r = 0;
	fakeRec.type = type;
	fakeRec.data = fakeData;
	for (i = 0; i < zone->length; i++) {
		if (zone->records[i].type != (fake ? TYPE_CNAME : type))
			continue;
		if (strcmp(zone->records[i].mask, direct ? sub : "*") == 0) {
			append(msg, msg->data, &zone->records[i]);
			r++;
			if (fake) {
				if (!initFakeRec(&fakeRec, zone->records[i].data + 1)) {
					r--;
					continue;
				}
				append(msg, zone->records[i].data, &fakeRec);
				break;
			}
		}
	}
	if (!r) {
		if (direct)
			return search(msg, zone, sub, type, 0, fake);
		if (!fake && (type != TYPE_CNAME))
			return search(msg, zone, sub, type, 1, 1);
	}
	return r;
}

void run(int sock) {
        Zone *zone;
        char sub[DATA_SIZE];
        DnsMessage msg;
        int type;
        while (1) {
                if (!receive(sock, &msg))
                        continue;
                if ((ntohs(msg.header.qd) != 1) || (rrCount(&msg) != 0) || (msg.header.a & 0xFE) || msg.header.b || (getClass(msg.data) != 1)) {
                        reply(sock, &msg, ERR_NOTIMPL, 0);
                        continue;
                }
                zone = findZone(msg.data, sub);
                if (zone) {
                        type = getType(msg.data);
                        search(&msg, zone, sub, type, 1, 0);
                        reply(sock, &msg, ERR_OK, 1);
                } else
                        reply(sock, &msg, ERR_REFUSED, 0);
        } 
}

int main(int a, char **b) {
	int sock;
	if (fork())
		return 0;
	sock = listenUdp(53);
	if (sock) 
		run(sock);
	close(sock);
	return 0;
}

