typedef struct Header Header;
struct Header {
	uchar *data;
	size_t len;
	size_t allocated;
};

const char *hdrinit(Header *h);
const char *hdrappend(Header *h, char *fmt, ...);
void hdrmac(uchar *data, size_t len, uchar filekey[16], char *out, size_t *outlen);
void mac(uchar *data, size_t len, uchar filekey[16], uchar out[32]);
