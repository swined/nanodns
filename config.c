#include "config.h"
#include "const.h"

#define ZONE(name, recs) { name, sizeof(recs) / sizeof(Record), recs }

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

int zoneCount = sizeof(zones);
