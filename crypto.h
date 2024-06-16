#define SHA256_DIGEST_LENGTH 32

typedef struct Sha256ctx Sha256ctx;
struct Sha256ctx {
        uint64_t len;    /* processed message length */
        uint32_t h[8];   /* hash state */
        uchar buf[64];  /* message block buffer */
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
void hkdfsha256(const uchar *ikm, size_t ikmlen, const uchar *salt, size_t saltlen, const uchar *info, size_t infolen, uchar out[32]);
