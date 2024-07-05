const char *ewrap(const char *outer, const char *inner);
const char *esys(const char *outer);
const char *efmt(const char *fmt, ...);
void die(const char *msg);
void *reallocarr(void *p, size_t nmemb, size_t size);
const char *getpassword(const char *prompt, char *buf, size_t len);
