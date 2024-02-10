#define CHUNKLEN 64*1024
#define TAGLEN   16      /* poly1305 authentication tag */

struct Ectx;
struct Ibuf;

typedef struct Ebuf Ebuf;
struct Ebuf {
	uchar ibuf[CHUNKLEN + TAGLEN];
	uchar obuf[CHUNKLEN + TAGLEN];
	struct Ectx *ctx;
	struct Ibuf *in;
	uchar nonce[12];
	size_t cur, size;
};

void payloadkey(uchar filekey[16], uchar nonce[16], uchar plkey[32]);
const char *plencrypt(Ibuf *in, Obuf *out, uchar plkey[32]);
const char *pldecrypt(Ibuf *in, Obuf *out, uchar plkey[32]);
const char *plinit(Ebuf *b, Ibuf *ib, uchar plkey[32]);
void plfree(Ebuf *b);
ssize_t plread(Ebuf *b, void *buf, size_t nbytes);
ssize_t plpeek(Ebuf *b, char *c);
