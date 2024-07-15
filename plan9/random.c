#include <u.h>
#include <libc.h>
#include <libsec.h>

int
randombuf(uchar *buf, int len)
{
	genrandom(buf, len);
	return 1;
}
