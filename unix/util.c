#include <errno.h>
#include <termios.h>

#include "common.h"
#include "util.h"

extern char ebuf[EBUFSIZE];
extern const char *argv0;

const char *
eget(void)
{
	if(*ebuf)
		return ebuf;
	return strerror(errno);
}

void
die(const char *msg)
{
	fprintf(stderr, "%s: %s\n", argv0, msg);
	exit(1);
}

void
exitusage(void)
{
	exit(1);
}

int
xisatty(int fd)
{
	return isatty(fd);
}

static const char *
readpass(int fd, char *buf, usize len)
{
	usize i;
	int nr, over;
	char c;

	over = (len == 0) ? 1 : 0;
	for(i = 0; ; i++) {
		if(!over && i >= len - 1)
			over = 1;
		nr = read(fd, &c, 1);
		if(nr == -1)
			return strerror(errno);
		if(nr == 0 || c == '\n' || c == '\r') {
			if(!over)
				buf[i] = '\0';
			break;
		}
		if(!over)
			buf[i] = c;
	}
	if(over)
		return efmt("passphrase is too long (max %u bytes)", len);
	(void)write(fd, "\n", 1);
	return NULL;
}

/* TODO: consider the need to mess with signals */
const char *
getpassword(const char *prompt, char *buf, usize len)
{
	struct termios term;
	const char *e = NULL;
	int fd, r;

	fd = open("/dev/tty", O_RDWR);
	if(fd == -1)
		return esys("failed to open /dev/tty");
	r = tcgetattr(fd, &term);
	if(r == -1) {
		e = strerror(errno);
		goto out;
	}
	term.c_lflag &= ~ECHO;
	r = tcsetattr(fd, TCSANOW, &term);
	if(r == -1) {
		e = esys("unable to turn off echo");
		goto out;
	}
	(void)write(fd, prompt, strlen(prompt));
	e = readpass(fd, buf, len);
	if(e)
		goto out;
	term.c_lflag |= ECHO;
	r = tcsetattr(fd, TCSANOW, &term);
	if(r == -1)
		e = esys("unable to turn on echo");
out:
	close(fd);
	return e;
}
