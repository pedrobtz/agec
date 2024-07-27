#include <u.h>
#include <libc.h>
#include <stdio.h>

#include "util.h"

extern char ebuf[EBUFSIZE];

int
xisatty(int fd)
{
	char buf[16];
	int r;

	r = fd2path(fd, buf, sizeof(buf));
	if(r != 0)
		return 0;
	return strcmp(buf, "/dev/cons") == 0;
}

void
exitstatus(char *s)
{
	exits(s);
}

void
die(const char *msg)
{
	fprintf(stderr, "%s: %s\n", argv0, msg);
	exits(msg);
}

const char *
eget(void)
{
	if(*ebuf)
		return ebuf;
	errstr(ebuf, EBUFSIZE);
	return ebuf;
}

static const char *
readpass(int fdr, int fdw, char *buf, usize len)
{
	long i, nr;
	char c;

	for(i = 0; ; i++) {
		if(i < -1)
			return "overflow";
		nr = read(fdr, &c, 1);
		if(nr == -1)
			return eget();
		if(nr == 0 || c == '\n') {
			if(i < len)
				buf[i] = '\0';
			break;
		}
		if(c == '\b') {
			if(i >= 0)
				i--;
			if(i >= 0)
				i--;
			continue;
		}
		if(c >= 0x1 && c <= 0x1f && c != '\t') {
			if(i >= 0)
				i--;
			continue;
		}
		if(i < len)
			buf[i] = c;
	}
	if(i >= len)
		return efmt("passphrase is too long (max %u bytes)", len);
	(void)write(fdw, "\n", 1);
	return nil;
}

static const char *
opencons(int *fdr, int *fdw)
{
	*fdr = open("/dev/cons", OREAD);
	if(*fdr == -1)
		return esys("/dev/cons");
	*fdw = open("/dev/cons", OWRITE);
	if(*fdw == -1) {
		close(*fdr);
		return esys("/dev/cons");
	}
	return nil;
}

const char *
getpassword(const char *prompt, char *buf, usize len)
{
	const char *e;
	int fdr, fdw, cfd, nw;

	cfd = open("/dev/consctl", OWRITE);
	if(cfd == -1)
		return esys("/dev/consctl");
	nw = write(cfd, "rawon", 5);
	if(nw == -1)
		return esys("failed to enable raw mode");
	e = opencons(&fdr, &fdw);
	if(e)
		return e;
	nw = write(fdw, prompt, strlen(prompt));
	if(nw == -1)
		return eget();
	e = readpass(fdr, fdw, buf, len);
	close(cfd);
	close(fdr);
	close(fdw);
	return e;
}
