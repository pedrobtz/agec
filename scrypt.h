#include <stdio.h>
#include "common.h"
#include "header.h"

typedef struct Scryptarg Scryptarg;
struct Scryptarg {
	uchar salt[16];
	uchar body[32];
	int cost;
};

void scryptstanza(Header *h, Data filekey, char *pass);
int scryptgetkey(uchar k[16], Scryptarg *arg, char *pass);
