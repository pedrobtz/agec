#define SHA256_DIGEST_LENGTH 32

typedef struct Sha256ctx Sha256ctx;
struct Sha256ctx {
        uint64_t len;    /* processed message length */
        uint32_t h[8];   /* hash state */
        uchar buf[64];  /* message block buffer */
};

typedef struct Hmacsha256ctx Hmacsha256ctx;
struct Hmacsha256ctx {
	Sha256ctx inner, outer;
};

typedef struct Chacha20poly1305ctx Chacha20poly1305ctx;
struct Chacha20poly1305ctx {
	uint64_t counter;
	uchar key[32];
	uchar nonce[8];
};

extern const uchar curve25519basepoint[32];

int randombuf(uchar *buf, int len);
int x25519(uchar out[32], const uchar priv[32], const uchar pub[32]);
int x25519pub(uchar out[32], uchar priv[32]);
void sha256init(Sha256ctx *ctx);
void sha256update(Sha256ctx *ctx, const void *m, unsigned long len);
/* state is ruined after sum, keep a copy if multiple sum is needed */
/* part of the message might be left in ctx, zero it if secrecy is needed */
void sha256final(Sha256ctx *ctx, uchar md[SHA256_DIGEST_LENGTH]);
void hmacsha256(const uchar *k, size_t klen, const uchar *in, size_t inlen, uchar out[32]);
void hmacsha256init(Hmacsha256ctx *ctx, const uchar *k, size_t klen);
void hmacsha256update(Hmacsha256ctx *ctx, const uchar *in, size_t inlen);
void hmacsha256final(Hmacsha256ctx *ctx, uchar out[32]);
void hkdfsha256(const uchar *ikm, size_t ikmlen, const uchar *salt, size_t saltlen, const uchar *info, size_t infolen, uchar out[32]);
void chacha20poly1305init(Chacha20poly1305ctx *ctx, const uchar key[32], const uchar nonce[12]);
void chacha20poly1305write(Chacha20poly1305ctx *ctx, uchar *out, const uchar *ad, size_t adlen, const uchar *in, size_t inlen);
int chacha20poly1305read(Chacha20poly1305ctx *ctx, uchar *out, const uchar *ad, size_t adlen, const uchar *in, size_t inlen);
const char *scrypt(const uchar *pass, size_t passlen, const uchar *salt, size_t saltlen, uint32_t n, uint32_t r, uint32_t p, uchar *out, size_t bytes);
