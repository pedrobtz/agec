#include "common.h"
#include "arg.h"
#include "crypto.h"
#include "base64.h"
#include "header.h"
#include "scrypt.h"
#include "x25519.h"
#include "io.h"
#include "parse.h"
#include "payload.h"
#include "util.h"

#define SCRYPTMAXCOST 22

typedef struct Key Key;
struct Key {
	uchar r[32];
};

typedef struct Keys Keys;
struct Keys {
	Key *buf;
	usize len;
	usize capacity;
};

typedef struct Opts Opts;
struct Opts {
	int isarmor, dflag, pflag;
	const char *idpath;
};

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
static ssize skipline(void *b, int encrypted);
static ssize getkey(void *b, Keys *privs, int encrypted, const char **err);
static int checkencrypted(Ibuf *ib, Ebuf *eb, const char **err);
static const char *matchscrypt(Ibuf *ib, Stanza *s);
static const char *readprivkeys(void *b, Keys *privs, int encrypted);
static const char *getprivkeys(Keys *privs, const char *path);
static const char *genhdr(Header *h, uchar filekey[16], int ispass, Keys *recs);
static const char *writehdr(Obuf *out, Header *h);
static const char *encipher(Ibuf *in, Obuf *out, int ispass, Keys *recs);
static const char *validmac(Ibuf *in, uchar filekey[16], int *isvalid);
static const char *validatemac(Ibuf *in, uchar filekey[16]);
static const char *scryptkey(const char *prompt, uchar filekey[16], Stanza *s);
static const char *findx25519(uchar filekey[16], Stanza *s, Keys *ids, int *found);
static const char *match(Ibuf *in, uchar filekey[16], Stanza *s, Keys *ids, int *found);
static const char *decipher(Ibuf *in, Obuf *out, Keys *ids);
static int getopts(char **argv, Keys *recs, Opts *opts);
static int validopts(Opts *opts, Keys *recs);

const char *argv0;

static void
usage(void)
{
	fprintf(stderr, "usage:\n"
			"\t%s (-r recipient)... [-a] [file]\n"
			"\t%s -p [-a] [file]\n"
			"\t%s -d [-i keyfile] [file]\n",
			argv0, argv0, argv0);
	exitstatus("usage");
}

static const char *
keyinit(Keys *keys)
{
	keys->len = 0;
	keys->capacity = 32;
	keys->buf = malloc(keys->capacity * sizeof(Key));
	if(keys->buf == NULL)
		return ewrap("failed to initialize key buffer", eget());
	return NULL;
}

static void
keyfree(Keys *keys)
{
	usize n;

	n = keys->capacity * sizeof(Key);
	if(keys->capacity > 0 && n / keys->capacity != sizeof(Key))
		fputs("failed to wipe key buffer: overflow", stderr);
	wipe(keys->buf, n);
	free(keys->buf);
}

/* Allocate keys->buf for another recepient */
static const char *
keynew(Keys *keys)
{
	usize ncap;

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
		return efmt("failed to parse recipient key %d",
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
	ssize nw;
	int ok;

	ok = randombuf(plnonce, 16);
	if(!ok)
		return "failed to generate payload nonce";
	payloadkey(filekey, plnonce, plkey);
	nw = bwrite(out, plnonce, sizeof(plnonce));
	if(nw == -1)
		return eget();
	e = plencrypt(in, out, plkey);
	wipe(plkey, sizeof(plkey));
	return e;
}

static const char *
passenc(Header *h, uchar filekey[16])
{
	const char *e;
	char pass[512];

	e = getpassword("Enter passphrase: ", pass, sizeof(pass));
	if(e)
		return ewrap("failed to read passphrase", e);
	e = scryptstanza(h, filekey, pass);
	wipe(pass, sizeof(pass));
	return e;
}

static const char *
pubenc(Header *h, uchar filekey[16], Keys *recs)
{
	const char *e;
	usize i;

	for(i = 0; i < recs->len; i++) {
		e = x25519stanza(h, filekey, (uchar *)(recs->buf + i));
		if(e)
			return e;
	}
	return NULL;
}

static ssize
skipline(void *b, int encrypted)
{
	ssize nr;
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

static ssize
getkey(void *b, Keys *privs, int encrypted, const char **err)
{
	char key[74+1], c;
	ssize nr;
	int ok;

	nr = encrypted ? plread((Ebuf *)b, key, 74) : bread((Ibuf *)b, key, 74);
	if(nr <= 0)
		return nr;
	if(nr != 74)
		return -2;
	nr = encrypted ? plread((Ebuf *)b, &c, 1) : bread((Ibuf *)b, &c, 1);
	if(nr == -1) {
		*err = eget();
		return -1;
	}
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
readprivkeys(void *b, Keys *privs, int encrypted)
{
	const char *e = NULL;
	ssize nr;
	int lineno;
	char c;

	for(lineno = 1; ; lineno++) {
		nr = encrypted ? plpeek((Ebuf *)b, &c) : bpeek((Ibuf *)b, &c);
		if(nr == -1)
			return eget();
		if(nr == 0)
			break;
		if(c == '#') {
			nr = skipline(b, encrypted);
			if(nr == -1)
				return eget();
			if(nr == 0)
				break;
			continue;
		} else if(c == '\n') {
			if(encrypted)
				(void)plread((Ebuf *)b, &c, 1);
			else
				(void)bread((Ibuf *)b, &c, 1);
			continue;
		}
		nr = getkey(b, privs, encrypted, &e);
		if(e)
			return e;
		if(nr == -2)
			return efmt("invalid private key at line %d", lineno);
		if(nr == 0)
			break;
	}
	return NULL;
}

static const char *
getprivkeys(Keys *privs, const char *path)
{
	Ibuf ib;
	Ebuf eb;
	void *in = &ib;
	const char *e;
	int fd, encrypted;

	fd = open(path, O_RDONLY);
	if(fd == -1)
		return esys("failed to open key file");
	ibinit(&ib, fd);
	encrypted = checkencrypted(&ib, &eb, &e);
	if(e)
		goto out;
	if(encrypted)
		in = &eb;
	e = readprivkeys(in, privs, encrypted);
	if(e)
		e = ewrap("failed to read key file", e);
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
	ssize nr;
	char c;
	const char *e;

	*err = NULL;
	nr = bpeek(ib, &c);
	if(nr == -1) {
		*err = ewrap("failed to read key file", eget());
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
	e = scryptkey("Enter passphrase for key file: ", filekey, &s);
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
	const char *e;
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
genhdr(Header *h, uchar filekey[16], int ispass, Keys *recs)
{
	char mac[B64EBUFLEN(32) + 1];
	const char *e;
	usize maclen;

	e = hdrappend(h, "age-encryption.org/v1\n");
	if(e)
		return e;
	e = ispass ? passenc(h, filekey) : pubenc(h, filekey, recs);
	if(e)
		return e;
	e = hdrappend(h, "---");
	if(e)
		return e;
	hdrmac(h->data, h->len, filekey, mac, &maclen);
	mac[sizeof(mac) - 1] = '\0';
	e = hdrappend(h, " %s\n", mac);
	if(e)
		return e;
	return NULL;
}

static const char *
writehdr(Obuf *out, Header *h)
{
	ssize nw;

	if(out->isarmor) {
		nw = writeall(out->fd, armorfirst, sizeof(armorfirst) - 1);
		if(nw == -1)
			return eget();
	}
	nw = bwrite(out, h->data, h->len);
	if(nw == -1)
		return eget();
	return NULL;
}

static const char *
writebody(Obuf *out, Ibuf *in, uchar filekey[16])
{
	const char *e;
	ssize nw;

	e = payload(filekey, in, out);
	if(e)
		return e;
	bflush(out);
	if(out->isarmor) {
		nw = writeall(out->fd, armorlast, sizeof(armorlast) - 1);
		if(nw == -1)
			return eget();
	}
	return NULL;
}

static const char *
encipher(Ibuf *in, Obuf *out, int ispass, Keys *recs)
{
	Header h;
	uchar filekey[16];
	const char *e;

	e = mkfilekey(filekey);
	if(e)
		return e;
	e = hdrinit(&h);
	if(e)
		return ewrap("failed to generate header", e);
	e = genhdr(&h, filekey, ispass, recs);
	if(e) {
		e = ewrap("failed to generate header", e);
		goto out;
	}
	e = writehdr(out, &h);
	if(e) {
		e = ewrap("failed to encrypt", e);
		goto out;
	}
	e = writebody(out, in, filekey);
	if(e)
		e = ewrap("failed to encrypt", e);
out:
	wipe(filekey, sizeof(filekey));
	free(h.data);
	return e;
}

static const char *
validmac(Ibuf *in, uchar filekey[16], int *isvalid)
{
	uchar mac1[32], mac2[32];
	static const char *e;
	uchar *data;
	usize len;

	data = recstop(in, &len);
	if(data == NULL)
		return eget();
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
		e = scryptkey("Enter passphrase: ", filekey, &s);
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

static const char *
findx25519(uchar filekey[16], Stanza *s, Keys *ids, int *found)
{
	const char *e = NULL;
	usize i;

	for(i = 0; i < ids->len && !*found; i++) {
		*found = x25519getkey(filekey, &s->arg.x25519,
				ids->buf[i].r, &e);
		if(e)
			return e;
	}
	return NULL;
}

/* filekey is filled only if and only if X25519 id is found */
static const char *
match(Ibuf *in, uchar filekey[16], Stanza *s, Keys *ids, int *found)
{
	const char *e;
	int end, seenscrypt, n;

	for(n = seenscrypt = *found = 0;; n++) {
		e = getstanza(in, s, &end);
		if(e)
			return ewrap("error parsing header", e);
		if(end)
			break;
		if(s->type == SCRYPT) {
			seenscrypt = *found = 1;
		} else if(s->type == X25519 && !*found) {
			e = findx25519(filekey, s, ids, found);
			if(e)
				return ewrap("failed to match identity", e);
		}
	}
	if(n > 1 && seenscrypt)
		return "invalid input: scrypt recipient is not the only one";
	return NULL;
}

static const char *
scryptkey(const char *prompt, uchar filekey[16], Stanza *s)
{
	const char *e = NULL;
	char pass[512];
	int ok;

	if(s->arg.scrypt.cost > SCRYPTMAXCOST)
		return "rejecting: scrypt work factor is too big";
	e = getpassword(prompt, pass, sizeof(pass));
	if(e)
		return ewrap("failed to read passphrase", e);
	ok = scryptgetkey(filekey, &s->arg.scrypt, pass, &e);
	wipe(pass, sizeof(pass));
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

static int
getopts(char **argv, Keys *recs, Opts *opts)
{
	const char *e;
	char **start, *arg;

	memset(opts, 0, sizeof(*opts));
	start = argv;
	XARGBEGIN {
		case 'a':
			opts->isarmor = 1;
			break;
		case 'd':
			opts->dflag = 1;
			break;
		case 'i':
			if(opts->idpath) {
				keyfree(recs);
				usage();
			}
			opts->idpath = XARGF();
			if(opts->idpath == NULL)
				usage();
			break;
		case 'p':
			opts->pflag = 1;
			break;
		case 'r':
			arg = XARGF();
			if(arg == NULL)
				usage();
			e = recadd(recs, arg);
			if(e) {
				keyfree(recs);
				die(e);
			}
			break;
		default:
			keyfree(recs);
			usage();
	} XARGEND
	return argv - start;
}

static int
validopts(Opts *opts, Keys *recs)
{
	if(opts->dflag) {
		if(opts->pflag || recs->len > 0 || opts->isarmor)
			return 0;
	} else {
		if(opts->pflag && recs->len > 0)
			return 0;
		if(!opts->pflag && recs->len == 0)
			return 0;
		if(opts->idpath)
			return 0;
	}
	return 1;
}

int
main(int argc, char *argv[])
{
	Ibuf ib;
	Obuf ob;
	Opts opts;
	Keys recs, ids;
	const char *e;
	int optshift, fd;

	argv0 = xprogname(argv[0], "agec");
	e = keyinit(&recs);
	if(e)
		die(e);
	optshift = getopts(argv, &recs, &opts);
	if(!validopts(&opts, &recs))
		goto badusage;
	argc -= optshift;
	argv += optshift;
	if(argc == 1) {
		fd = open(argv[0], O_RDONLY);
		if(fd == -1) {
			e = esys("failed to open input file");
			goto out;
		}
		ibinit(&ib, fd);
	} else if(argc == 0) {
		ibinit(&ib, 0);
	} else {
		goto badusage;
	}
	ob.cur = 0;
	ob.fd = 1;
	ob.isarmor = opts.isarmor;
	if(opts.dflag) {
		if(opts.idpath) {
			e = keyinit(&ids);
			if(e)
				goto out;
			e = getprivkeys(&ids, opts.idpath);
			if(e)
				goto out;
		}
		e = decipher(&ib, &ob, &ids);
		if(opts.idpath)
			keyfree(&ids);
	} else {
		e = encipher(&ib, &ob, opts.pflag, &recs);
	}
out:
	wipe(&ob, sizeof(ob));
	keyfree(&recs);
	ibfree(&ib);
	if(e)
		die(e);
	exitstatus(NULL);
badusage:
	wipe(&ob, sizeof(ob));
	keyfree(&recs);
	usage();
	return 1;
}
