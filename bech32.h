/* out size must be at least strlen(s) - 8 */
int bech32decode(char *s, uchar *out, size_t *outlen, size_t *hrplen);

/* out size must be at least strlen(label) + datalen + 8 */
int bech32encode(char *label, uchar *data, size_t datalen, uchar *out);
