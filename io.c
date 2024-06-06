#include <assert.h>
#include <err.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "base64.h"
#include "util.h"
#include "io.h"

#define RECINITLEN 512

static ssize_t awrite(Obuf *b, void *buf, size_t nbytes);
static ssize_t aflush(Obuf *b);
static void recappend(Record *rec, void *buf, size_t len);
static ssize_t readall(int fd, void *buf, size_t nbytes);
static int isarmor(Ibuf *b);
static int endcheck(uchar *buf, size_t len, int *endpos);
static int endskip(int fd, int endpos);
static ssize_t aread(Ibuf *b, void *buf, size_t nbytes);

ssize_t
bwrite(Obuf *b, void *buf, size_t nbytes)
{
	size_t rest, c;
	ssize_t ret;

	if(b->isarmor)
		return awrite(b, buf, nbytes);
	if(nbytes > IOBUFSIZE) {
		ret = bflush(b);
		if(ret == -1)
			return -1;
		return write(b->fd, buf, nbytes);
	}
	rest = IOBUFSIZE - b->cur;
	c = (rest > nbytes) ? nbytes : rest;
	memcpy(b->buf + b->cur, buf, c);
	if(rest > nbytes) {
		b->cur += nbytes;
		return 0;
	} else {
		ret = write(b->fd, b->buf, b->cur);
		if(ret == -1)
			return -1;
		memcpy(b->buf, (uchar *)buf + rest, nbytes - rest);
		b->cur = nbytes - rest;
		return ret;
	}
}

static ssize_t
awrite(Obuf *b, void *buf, size_t nbytes)
{
	size_t rest, c;
	ssize_t r;

	while(nbytes > 0) {
		rest = sizeof(b->abuf) - b->cur;
		c = (rest > nbytes) ? nbytes : rest; 
		memcpy(b->abuf + b->cur, buf, c);
		buf = (char *)buf + c;
		b->cur += c;
		nbytes -= c;
		if(b->cur == sizeof(b->abuf)) {
			r = aflush(b);
			if(r == -1)
				return -1;
		}
	}
	return 1;
}

static ssize_t
aflush(Obuf *b)
{
	uchar buf[IOABUFSIZE];
	size_t outlen;
	ssize_t r;

	if(b->cur == 0)
		return 0;
	base64_encode(b->abuf, buf, b->cur, &outlen, 1);
	r = write(b->fd, buf, outlen);
	b->cur = 0;
	return r;
}

ssize_t
bflush(Obuf *b)
{
	ssize_t r;

	if(b->isarmor)
		return aflush(b);
	if(b->cur == 0)
		return 0;
	r = write(b->fd, b->buf, b->cur);
	b->cur = 0;
	return r;
}

static ssize_t
readall(int fd, void *buf, size_t nbytes)
{
	ssize_t nr, total = 0;

	while(nbytes > 0) {
		nr = read(fd, buf, nbytes);
		if(nr < 0)
			return nr;
		if(nr == 0)
			return total;
		nbytes -= nr;
		total += nr;
		buf = (char *)buf + nr;
	}
	return total;
}

static int
isarmor(Ibuf *b)
{
	static const char armorfirst[] = "-----BEGIN AGE ENCRYPTED FILE-----\n";
	ssize_t nr;

	assert(sizeof(armorfirst) - 1 < IOBUFSIZE);
	nr = readall(b->fd, b->buf, sizeof(armorfirst) - 1);
	if(nr == -1)
		err(1, "failed to read input");
	b->size = nr;
	if((size_t)nr < sizeof(armorfirst) - 1)
		return 0;
	if(memcmp(armorfirst, b->buf, sizeof(armorfirst) - 1) == 0) {
		b->size = 0;
		return 1;
	} else {
		return 0;
	}
}

void
ibinit(Ibuf *b, int fd)
{
	b->size = b->cur = 0;
	b->asize = b->acur = b->aendpos = 0;
	b->eof = 0;
	b->fd = fd;
	b->recording = 1;
	b->rec.len = b->rec.capacity = 0;
	b->isarmor = 0;
	b->isarmor = isarmor(b);
}

void
ibfree(Ibuf *b)
{
	if(b->recording && b->rec.capacity > 0)
		free(b->rec.buf);
}

ssize_t
bread(Ibuf *b, void *buf, size_t nbytes)
{
	size_t c, rest;
	size_t orig = nbytes;
	ssize_t nr;

	if(b->eof)
		return 0;
	while(nbytes > 0) {
		if(b->cur == b->size) {
			if(b->recording && b->size > 0)
				recappend(&b->rec, b->buf, b->size);
			b->cur = b->size = 0;
		}
		if(b->size == 0) {
			if(b->isarmor)
				nr = aread(b, b->buf, IOBUFSIZE);
			else
				nr = read(b->fd, b->buf, IOBUFSIZE);
			if(nr == -1)
				return -1;
			if(nr == -2)
				errx(1, "failed to read input: "
					"armor format error");
			if(nr == 0) {
				b->eof = 1;
				return orig - nbytes;
			}
			b->size = nr;
		}
		rest = b->size - b->cur;
		c = (rest > nbytes) ? nbytes : rest;
		memcpy(buf, b->buf + b->cur, c);
		buf = (uchar *)buf + c;
		b->cur += c;
		nbytes -= c;
	}
	return orig - nbytes;
}

/*
 * Checks for the PEM ending line.
 * Return value is:
 *   1 if the ending line fully resides in the buf
 *   0 if there is no ending line in the buf, or it's partial
 *  -1 for the format error
 * endpos must point to the size of the ending line part that
 * has already been read (zero if has not). The value is
 * updated if the ending line is partial.
 */
static int
endcheck(uchar *buf, size_t len, int *endpos)
{
	static const char line[]  = "-----END AGE ENCRYPTED FILE-----\n";
	size_t start;
	const char *p, *q;

	if(len - *endpos < sizeof(line) - 1)
		return -1;
	start = len - *endpos - (sizeof(line) - 1);
	p = (char *)buf + start;
	q = line + *endpos;

	if(*p != *q && *endpos == 0) {
		while(p < (char *)buf + len) {
			if(*p == '-')
				break;
			p++;
		}
		return 0;
	}
	while(p <= (char *)buf + len) {
		if(q == line + (sizeof(line) - 1)) /* end */
			return (p == (char *)buf + len) ? 1 : -1;
		if(*p != *q)
			return -1;
		p++, q++;
		(*endpos)++;
	}
	return 0;
}

static int
endskip(int fd, int endpos)
{
	static const char line[]  = "-----END AGE ENCRYPTED FILE-----\n";
	uchar buf[sizeof(line)];
	ssize_t nr, nr2;

	nr = readall(fd, buf, sizeof(line) - endpos);
	if(nr == -1)
		return -1;
	if(nr < (ssize_t)(sizeof(line) - 1) - endpos)
		return -2;
	if(memcmp(buf, line + endpos, (sizeof(line) - 1) - endpos) != 0)
		return -2;
	nr2 = read(fd, buf, 1);
	if(nr2 == -1)
		return -1;
	if(nr2 > 0)
		return -2;
	return nr;
}

static ssize_t
aread(Ibuf *b, void *buf, size_t nbytes)
{
	uchar raw[IOABUFREADSIZE];
	size_t rest, c, outlen, orig = nbytes;
	ssize_t nr;
	int ok, end;

	while(nbytes > 0) {
		if(b->acur == b->asize)
			b->acur = b->asize = 0;
		if(b->asize == 0) {
			nr = readall(b->fd, raw, sizeof(raw));
			if(nr == -1)
				return -1;
			if(nr == 0)
				return orig - nbytes;
			end = endcheck(raw, nr, &b->aendpos);
			if(end == -1)
				return -2;
			ok = base64_decode(raw, b->abuf, nr - b->aendpos,
					&outlen, 1);
			if(!ok)
				return -2;
			b->asize = outlen;
			if(end == 0 && b->aendpos > 0) {   /* partial */
				endskip(b->fd, b->aendpos);
			} else if(end == 1) {   /* full */
				/* it must be the last block */
				nr = read(b->fd, raw, 1);
				if(nr == -1)
					return -1;
				if(nr != 0)
					return -2;
			}
		}
		rest = b->asize - b->acur;
		c = (rest > nbytes) ? nbytes : rest;
		memcpy(buf, b->abuf + b->acur, c);
		b->acur += c;
		buf = (uchar *)buf + c;
		nbytes -= c;
	}
	return orig - nbytes;
}

ssize_t
bpeek(Ibuf *b, char *c)
{
	ssize_t nr;

	if(b->eof)
		return 0;
	if(b->cur < b->size) {
		*c = b->buf[b->cur];
		return 1;
	}
	if(b->recording && b->size > 0)
		recappend(&b->rec, b->buf, b->size);
	b->cur = b->size = 0;
	if(b->isarmor)
		nr = aread(b, b->buf, IOBUFSIZE);
	else
		nr = read(b->fd, b->buf, IOBUFSIZE);
	if(nr == -1)
		return -1;
	if(nr == 0) {
		b->eof = 1;
		return 0;
	}
	b->size = nr;
	*c = b->buf[0];
	return 1;
}

static void
recappend(Record *rec, void *buf, size_t len)
{
	size_t cap, ncap;

	if(len > 0 && rec->capacity == 0) {
		rec->buf = emalloc(RECINITLEN);
		rec->capacity = RECINITLEN;
	}
	if(rec->len + len > rec->capacity) {
		cap = ncap = rec->capacity;
		while(rec->len + len > ncap) {
			ncap *= 2;
			if(ncap < cap)	/* overflow */
				errx(1, "failed to reallocate record buffer: "
					"overflow");
			cap = ncap;
		}
		rec->buf = erealloc(rec->buf, ncap);
		rec->capacity = ncap;
	}
	memcpy(rec->buf + rec->len, buf, len);
	rec->len += len;
}

uchar *
recstop(Ibuf *b, size_t *len)
{
	b->recording = 0;
	if(b->rec.capacity == 0) {
		*len = b->cur;
		return b->buf;
	} else {
		recappend(&b->rec, b->buf, b->cur);
		*len = b->rec.len;
		return b->rec.buf;
	}
}
