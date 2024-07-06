#define IOBUFSIZE 8*1024
#define IOABUFRAWSIZE 48*256
#define IOABUFSIZE B64EBUFLEN(IOABUFRAWSIZE) + B64EBUFLEN(IOABUFRAWSIZE) / 64
#define IOABUFREADSIZE 65*126
enum {
	EBADARMOR   = -1,
	EDECRYPT    = -2,
	EEMPTYCHUNK = -3
};

typedef struct Obuf Obuf;
struct Obuf {
	int fd;
	size_t cur;
	int isarmor;
	union {
		uchar buf[IOBUFSIZE];
		uchar abuf[IOABUFRAWSIZE];
	};
};

/* To keep record of read bytes for MAC */
typedef struct Record Record;
struct Record {
	uchar *buf;
	size_t len, capacity;
};

typedef struct Ibuf Ibuf;
struct Ibuf {
	int fd;
	int eof;
	int isarmor;
	int recording, recfail;
	size_t cur, size;
	size_t acur, asize;
	int aendpos;
	uchar buf[IOBUFSIZE];
	uchar abuf[IOABUFREADSIZE];
	Record rec;
};

extern const char armorfirst[36];
extern const char armorlast[34];

void ibinit(Ibuf *b, int fd);
void ibfree(Ibuf *b);
ssize_t bwrite(Obuf *b, void *buf, size_t n);
ssize_t bflush(Obuf *b);
ssize_t bread(Ibuf *b, void *buf, size_t n);
ssize_t bpeek(Ibuf *b, char *c);
uchar *recstop(Ibuf *b, size_t *len);
const char *ioerror(int errn);
