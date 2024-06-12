extern const uchar curve25519basepoint[32];

int randombuf(uchar *buf, int len);

int x25519(uchar out[32], const uchar priv[32], const uchar pub[32]);
int x25519pub(uchar out[32], uchar priv[32]);
