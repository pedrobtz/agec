/* Length of buffer for encoded string */
#define B64EBUFLEN(l) (((l) * 4 / 3 + 4) + ((l) * 4 / 3 + 4) / 64 + 1)

/*
 * Length of buffer for decoded string.
 * l is the number of base64 characters.
 */
#define B64DBUFLEN(l) ((l) / 4 * 3)

void base64encode(uchar *in, uchar *out, size_t len, size_t *outlen, int pad);
int  base64decode(uchar *in, uchar *out, size_t len, size_t *outlen, int pad);
