#include <unistd.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "../common.h"

int
randombuf(uchar *buf, int len)
{
	return RAND_bytes(buf, len);
}
