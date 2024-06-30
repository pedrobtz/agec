#ifndef HEADER_H
#define HEADER_H

#include "common.h"
#include "util.h"

typedef struct Header Header;
struct Header {
	uchar *data;
	size_t len;
	size_t allocated;
};

void hdrinit(Header *h);
void hdrappend(Header *h, char *fmt, ...);
void hdrmac(uchar *data, size_t len, uchar filekey[16], char *out, size_t *outlen);
void mac(uchar *data, size_t len, uchar filekey[16], uchar out[32]);

#endif /* HEADER_H */
