#include <err.h>
#include <stdlib.h>

#include "util.h"

void *
emalloc(size_t size)
{
	void *ret;

	if((ret = malloc(size)) == NULL)
		err(1, "failed to allocate memory");
	return ret;
}

void *
erealloc(void *p, size_t size)
{
	void *ret;

	if((ret = realloc(p, size)) == NULL)
		err(1, "failed to allocate memory");
	return ret;
}

void *
ereallocarr(void *p, size_t nmemb, size_t size)
{
	void *ret;
	size_t n;

	n = nmemb * size;
	if(nmemb > 0 && n / nmemb != size)
		errx(1, "failed to allocate memory: overflow");
	ret = realloc(p, n);
	if(ret == 0)
		err(1, "failed to allocate memory");
	return ret;
}
