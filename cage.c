#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "crypto.h"
#include "base64.h"
#include "header.h"
#include "scrypt.h"
#include "x25519.h"
#include "io.h"
#include "parse.h"
#include "payload.h"

#define SCRYPTMAXCOST 22

struct Key {
	uchar r[32];
};
typedef struct Key Key;

struct Keys {
	Key *buf;
	size_t len;
	size_t capacity;
};
typedef struct Keys Keys;

static const char *mkfilekey(uchar filekey[16]);
static void usage(void);
static const char *payload(uchar filekey[16], Ibuf *in, Obuf *out);
static const char *passenc(Header *h, uchar filekey[16]);
static const char *pubenc(Header *h, uchar filekey[16], Keys *recs);
static const char *keyinit(Keys *keys);
static void keyfree(Keys *keys);
static const char *keynew(Keys *keys);
static const char *recadd(Keys *recs, char *bech);
static int privadd(Keys *recs, char bech[74+1], const char **err);
static ssize_t skipline(void *b, int encrypted);
static ssize_t getkey(void *b, Keys *privs, int encrypted, const char **err);
static int checkencrypted(Ibuf *ib, Ebuf *eb, const char **err);
static const char *matchscrypt(Ibuf *ib, Stanza *s);
static const char *readprivkeys(Keys *privs, const char *path);
static const char *encipher(Ibuf *in, Obuf *out, int ispass, Keys *recs);
static const char *validmac(Ibuf *in, uchar filekey[16], int *isvalid);
static const char *validatemac(Ibuf *in, uchar filekey[16]);
static const char *scryptkey(uchar filekey[16], Stanza *s);
static const char *match(Ibuf *in, uchar filekey[16], Stanza *s, Keys *ids, int *found);
static const char *decipher(Ibuf *in, Obuf *out, Keys *ids);

char *argv0;
static const char armorfirst[] = "-----BEGIN AGE ENCRYPTED FILE-----\n";
static const char armorlast[]  = "-----END AGE ENCRYPTED FILE-----\n";

static void
usage(void)
{
	fprintf(stderr, "usage:"
			"\t%s [-a] (-r recipient)...) [file]\n"
			"\t%s [-a] -p [file]\n"
			"\t%s [-i path] -d [file]\n",
			argv0, argv0, argv0);
	exit(1);
}

static const char *
keyinit(Keys *keys)
{
	keys->len = 0;
	keys->capacity = 32;
	keys->buf = malloc(keys->capacity * sizeof(Key));
	if(keys->buf == NULL) {
		return ewrap("failed to initialize key buffer",
				strerror(ENOMEM));
	}
	return NULL;
}

static void
keyfree(Keys *keys)
{
	size_t n;

	n = keys->capacity * sizeof(Key);
	if(keys->capacity > 0 && n / keys->capacity != sizeof(Key))
		fputs("failed to wipe key buffer: overflow", stderr);
	explicit_bzero(keys->buf, n);
	free(keys->buf);
}

/* Allocate keys->buf for another recepient */
static const char *
keynew(Keys *keys)
{
	size_t ncap;

	if(keys->len + 1 > keys->capacity) {
		ncap = keys->capacity * 2;
		if(ncap < keys->capacity) {
			return ewrap("failed to reallocate key buffer",
					"overflow");
		}
		keys->buf = reallocarr(keys->buf, ncap, sizeof(Key));
		if(keys->buf == NULL)
			return esys("failed to reallocate key buffer");
		keys->capacity = ncap;
	}
	return NULL;
}

static const char *
recadd(Keys *recs, char *bech)
{
	const char *e;
	int ok;

	e = keynew(recs);
	if(e)
		return e;
	ok = x25519pubkey(bech, (uchar *)(recs->buf + recs->len));
	recs->len++;
	if(!ok) {
		return efmt("failed to parse recipient key (line %d)",
				recs->len);
	}
	return NULL;
}

static int
privadd(Keys *privs, char bech[74+1], const char **err)
{
	int ok;

	*err = keynew(privs);
	if(*err)
		return 0;
	ok = x25519privkey(bech, (uchar *)(privs->buf + privs->len));
	privs->len++;
	return ok;
}

static const char *
mkfilekey(uchar filekey[16])
{
	int r;

	r = randombuf(filekey, 16);
	if(r == 0)
		return "failed to generate file key";
	return NULL;
}

static const char *
payload(uchar filekey[16], Ibuf *in, Obuf *out)
{
	uchar plkey[32], plnonce[16];
	const char *e;
	int ok;

	ok = randombuf(plnonce, 16);
	if(!ok)
		return "failed to generate payload nonce";
	payloadkey(filekey, plnonce, plkey);
	bwrite(out, plnonce, sizeof(plnonce));
	e = plencrypt(in, out, plkey);
	explicit_bzero(plkey, sizeof(plkey));
	return e;
}

static const char *
passenc(Header *h, uchar filekey[16])
{
	const char *e;
	char *pass;

	pass = getpass("Enter passphrase: ");
	if(pass == NULL)
		return "failed to read passphrase";
	e = scryptstanza(h, filekey, pass);
	explicit_bzero(pass, strlen(pass)); /* TODO: leaks pass length */
	return e;
}

static const char *
pubenc(Header *h, uchar filekey[16], Keys *recs)
{
	const char *e;
	size_t i;

	for(i = 0; i < recs->len; i++) {
		e = x25519stanza(h, filekey, (uchar *)(recs->buf + i));
		if(e)
			return e;
	}
	return NULL;
}

static ssize_t
skipline(void *b, int encrypted)
{
	ssize_t nr;
	char c;

	for(;;) {
		if(encrypted)
			nr = plread((Ebuf *)b, &c, 1);
		else
			nr = bread((Ibuf *)b, &c, 1);
		if(nr <= 0)
			return nr;
		if(c == '\n')
			return 1;
	}
}

static ssize_t
getkey(void *b, Keys *privs, int encrypted, const char **err)
{
	char key[74+1], c;
	ssize_t nr;
	int ok;

	nr = encrypted ? plread((Ebuf *)b, key, 74) : bread((Ibuf *)b, key, 74);
	if(nr <= 0)
		return nr;
	if(nr != 74)
		return -2;
	nr = encrypted ? plread((Ebuf *)b, &c, 1) : bread((Ibuf *)b, &c, 1);
	if(nr == -1)
		return -1;
	if(nr == 1 && c != '\n')
		return -2;
	*err = NULL;
	ok = privadd(privs, key, err);
	if(!ok)
		return -2;
	if(nr == 0)
		return 0;
	return 1;
}

static const char *
readprivkeys(Keys *privs, const char *path)
{
	int fd;
	Ibuf ib;
	Ebuf eb;
	void *in = &ib;
	const char *e;
	ssize_t nr;
	int lineno;
	char c;
	int encrypted = 0;

	fd = open(path, O_RDONLY);
	if(fd == -1)
		return esys("failed to open key file");
	e = ibinit(&ib, fd);
	if(e) {
		e = ewrap("failed to read key file", e);
		goto out;
	}
	encrypted = checkencrypted(&ib, &eb, &e);
	if(e)
		goto out;
	if(encrypted)
		in = &eb;
	for(lineno = 1; ; lineno++) {
		nr = encrypted ? plpeek(&eb, &c) : bpeek(&ib, &c);
		if(nr == -1) {
			e = ewrap("failed to read key file", ioerror(errno));
			goto out;
		}
		if(nr == 0)
			break;
		if(c == '#') {
			nr = skipline(in, encrypted);
			if(nr == -1) {
				e = ewrap("failed to read key file",
						ioerror(errno));
				goto out;
			}
			if(nr == 0)
				break;
			continue;
		}
		nr = getkey(in, privs, encrypted, &e);
		if(e)
			goto out;
		if(nr == -1) {
			e = ewrap("failed to read key file", ioerror(errno));
			goto out;
		}
		if(nr == -2) {
			e = efmt("invalid private key at line %d", lineno);
			goto out;
		}
		if(nr == 0)
			break;
	}
out:
	if(encrypted)
		plfree(&eb);
	ibfree(&ib);
	close(fd);
	if(e)
		return e;
	return NULL;
}

static int
checkencrypted(Ibuf *ib, Ebuf *eb, const char **err)
{
	uchar filekey[16], plnonce[16], plkey[32];
	Stanza s;
	ssize_t nr;
	char c;
	const char *e;

	*err = NULL;
	nr = bpeek(ib, &c);
	if(nr == -1) {
		*err = ewrap("failed to read key file", ioerror(errno));
		return 0;
	}
	if(nr == 0 || c != 'a')
		return 0;
	e = getversion(ib);
	if(e) {
		*err = efmt("invalid private key at line %d", 1);
		return 0;
	}
	e = matchscrypt(ib, &s);
	if(e) {
		*err = e;
		return 0;
	}
	e = scryptkey(filekey, &s);
	if(e) {
		*err = ewrap("failed to decrypt key file", e);
		return 0;
	}
	e = validatemac(ib, filekey);
	if(e) {
		*err = ewrap("failed to decrypt key file", e);
		return 0;
	}
	e = getplnonce(ib, plnonce);
	if(e) {
		*err = ewrap("failed to decrypt key file", e);
		return 0;
	}
	payloadkey(filekey, plnonce, plkey);
	plinit(eb, ib, plkey);
	return 1;
}

static const char *
matchscrypt(Ibuf *ib, Stanza *s)
{
	uchar filekey[16];
	const char *e = NULL;
	Keys nilkeys;
	int found;

	nilkeys.len = 0;
	e = match(ib, filekey, s, &nilkeys, &found);
	if(e)
		return ewrap("failed to read key file", e);
	if(!found || s->type != SCRYPT)
		return ewrap("failed to read key file", "identity not found");
	return NULL;
}

static const char *
encipher(Ibuf *in, Obuf *out, int ispass, Keys *recs)
{
	Header h;
	uchar filekey[16];
	char mac[B64EBUFLEN(32)];
	const char *e;
	size_t maclen;

	e = mkfilekey(filekey);
	if(e)
		return e;
	e = hdrinit(&h);
	if(e) {
		e = ewrap("failed to generate header", e);
		goto out;
	}
	hdrappend(&h, "age-encryption.org/v1\n");
	e = ispass ? passenc(&h, filekey) : pubenc(&h, filekey, recs);
	if(e) {
		e = ewrap("failed to generate header", e);
		goto out;
	}
	hdrappend(&h, "---");
	hdrmac(h.data, h.len, filekey, mac, &maclen);
	if(out->isarmor)
		write(out->fd, armorfirst, sizeof(armorfirst) - 1);
	hdrappend(&h, " %s\n", mac);
	bwrite(out, h.data, h.len);
	e = payload(filekey, in, out);
	if(e) {
		e = ewrap("failed to encrypt", e);
		goto out;
	}
	bflush(out);
	if(out->isarmor)
		write(out->fd, armorlast, sizeof(armorlast) - 1);
out:
	explicit_bzero(filekey, sizeof(filekey));
	free(h.data);
	return e;
}

static const char *
validmac(Ibuf *in, uchar filekey[16], int *isvalid)
{
	uchar mac1[32], mac2[32];
	static const char *e;
	uchar *data;
	size_t len;

	data = recstop(in, &len);
	if(data == NULL)
		return strerror(errno);
	e = getmac(in, mac1);
	if(e)
		return e;
	mac(data, len, filekey, mac2);
	*isvalid = memcmp(mac1, mac2, 32) == 0;
	return NULL;
}

static const char *
decipher(Ibuf *in, Obuf *out, Keys *ids)
{
	const char *e;
	uchar filekey[16], plnonce[16], plkey[32];
	Stanza s;
	int found;

	e = getversion(in);
	if(e)
		return ewrap("error parsing header", e);
	e = match(in, filekey, &s, ids, &found);
	if(e)
		return e;
	if(!found)
		return "no identity matched any of the recipients";
	if(s.type == SCRYPT) {
		e = scryptkey(filekey, &s);
		if(e)
			return e;
	}
	e = validatemac(in, filekey);
	if(e)
		return ewrap("failed to decrypt", e);
	e = getplnonce(in, plnonce);
	if(e)
		return ewrap("error parsing header", e);
	payloadkey(filekey, plnonce, plkey);
	e = pldecrypt(in, out, plkey);
	if(e)
		return ewrap("failed to decrypt", e);
	bflush(out);
	return NULL;
}

/* filekey is filled only if X25519 id is found */
static const char *
match(Ibuf *in, uchar filekey[16], Stanza *s, Keys *ids, int *found)
{
	const char *e;
	int end, seenscrypt, n;
	unsigned i;

	for(n = seenscrypt = *found = 0;; n++) {
		e = getstanza(in, s, &end);
		if(e)
			return ewrap("error parsing header", e);
		if(end)
			break;
		if(s->type == SCRYPT) {
			seenscrypt = *found = 1;
		} else if(s->type == X25519 && !*found) {
			for(i = 0; i < ids->len && !*found; i++) {
				*found = x25519getkey(filekey, &s->x25519,
						ids->buf[i].r, &e);
				if(e) {
					return ewrap("failed to match identity",
							e);
				}
			}
		}
	}
	if(n > 1 && seenscrypt)
		return "invalid input: scrypt recipient is not the only one";
	return NULL;
}

static const char *
scryptkey(uchar filekey[16], Stanza *s)
{
	const char *e = NULL;
	char *pass;
	int ok;

	if(s->scrypt.cost > SCRYPTMAXCOST)
		return "rejecting: scrypt work factor is too big";
	pass = getpass("Enter passphrase: ");
	if(pass == NULL)
		return "failed to read passphrase";
	ok = scryptgetkey(filekey, &s->scrypt, pass, &e);
	explicit_bzero(pass, strlen(pass)); /* TODO: leaks pass length */
	if(e)
		return e;
	if(!ok)
		return "invalid passphrase";
	return NULL;
}

static const char *
validatemac(Ibuf *in, uchar filekey[16])
{
	const char *e;
	int valid;

	e = validmac(in, filekey, &valid);
	if(e)
		return ewrap("error parsing header", e);
	if(!valid)
		return "bad header MAC";
	return NULL;
}

int
main(int argc, char *argv[])
{
	Ibuf ib;
	Obuf ob;
	Keys recs, ids;
	int pflag = 0, dflag = 0;
	const char *idpath = NULL, *e = NULL;
	int ch, fd;

	argv0 = argv[0] ? argv[0] : "cage";
	e = keyinit(&recs);
	if(e)
		die(e);
	ob.isarmor = 0;
	while((ch = getopt(argc, argv, "adi:pr:")) != -1) {
		switch(ch) {
		case 'a':
			ob.isarmor = 1;
			break;
		case 'd':
			dflag = 1;
			break;
		case 'i':
			if(idpath) {
				keyfree(&recs);
				usage();
			}
			idpath = optarg;
			break;
		case 'p':
			pflag = 1;
			break;
		case 'r':
			e = recadd(&recs, optarg);
			if(e)
				goto out;
			break;
		default:
			keyfree(&recs);
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if(!dflag && pflag && recs.len > 0)
		goto earlybadusage;
	if(!dflag && !pflag && recs.len == 0)
		goto earlybadusage;
	if(argc == 1) {
		fd = open(argv[0], O_RDONLY);
		if(fd == -1) {
			e = esys("failed to open input file");
			goto out;
		}
		e = ibinit(&ib, fd);
	} else if(argc == 0) {
		e = ibinit(&ib, 0);
	} else {
		goto badusage;
	}
	if(e)
		goto out;
	ob.cur = 0;
	ob.fd = 1;
	if(dflag) {
		if(pflag || recs.len || ob.isarmor)
			goto badusage;
		if(idpath) {
			e = keyinit(&ids);
			if(e)
				goto out;
			e = readprivkeys(&ids, idpath);
			if(e)
				goto out;
		}
		e = decipher(&ib, &ob, &ids);
		if(idpath)
			keyfree(&ids);
	} else {
		if(idpath)
			goto badusage;
		e = encipher(&ib, &ob, pflag, &recs);
	}
out:
	explicit_bzero(&ob, sizeof(ob));
	keyfree(&recs);
	ibfree(&ib);
	if(e)
		die(e);
	return 0;
badusage:
	ibfree(&ib);
earlybadusage:
	explicit_bzero(&ob, sizeof(ob));
	keyfree(&recs);
	usage();
}
