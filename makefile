OS = unix
INC = -I. -I$(OS)
LIBS = -lssl -lcrypto
OBJ_AGEC = agec.o base64.o bech32.o header.o io.o keyenc.o parse.o \
	payload.o scrypt.o util.o x25519.o crypto/chacha20poly1305.o \
	crypto/curve25519.o crypto/hkdf.o crypto/hmac.o crypto/scrypt.o \
	crypto/sha256.o $(OS)/util.o $(OS)/random.o
OBJ_AGECGEN = agecgen.o bech32.o util.o crypto/curve25519.o \
	$(OS)/random.o $(OS)/util.o
OBJS = $(OBJ_AGEC) $(OBJ_AGECGEN)
TESTS = test/unit/base64.o test/unit/bech32.o test/unit/util.o
OBJ_TEST = base64.o bech32.o util.o
TESTTMP = test/unit/main test/unit/main.o test/unit/*.c \
	test/vectors/body test/vectors/out test/vectors/priv
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man
MAN1DIR = $(MANDIR)/man1
MAN5DIR = $(MANDIR)/man5
.SUFFIXES: .c .o .ts _test.c

all: agec agecgen

agec: $(OBJ_AGEC)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_AGEC) $(LIBS)

agecgen: $(OBJ_AGECGEN)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_AGECGEN) $(LIBS)

.c.o:
	$(CC) $(INC) $(CFLAGS) -c -o $@ $<

install: agec agecgen
	mkdir -p $(DESTDIR)$(BINDIR)
	cp agec agecgen $(DESTDIR)$(BINDIR)
	chmod 755 $(DESTDIR)$(BINDIR)/agec $(DESTDIR)$(BINDIR)/agecgen
	mkdir -p $(DESTDIR)$(MAN1DIR) $(DESTDIR)$(MAN5DIR)
	cp -a doc/agec.1 doc/agecgen.1 $(DESTDIR)$(MAN1DIR)
	chmod 644 $(DESTDIR)$(MAN1DIR)/agec.1 $(DESTDIR)$(MAN1DIR)/agecgen.1
	cp -a doc/age.5 $(DESTDIR)$(MAN5DIR)
	chmod 644 $(DESTDIR)$(MAN5DIR)/age.5

check-usage: agec
	cd test && ./usage.sh

check-vectors: agec
	cd test/vectors && ./testall.sh

check-afl:
	cd test/afl && afl-fuzz -i cases/ -o found/ -- ../../agec -d -i priv

check-unit: test/unit/main
	cd test/unit && ./main

test/unit/main: test/unit/main.o $(TESTS) $(OBJ_TEST)
	$(CC) $(LDFLAGS) -o $@ test/unit/main.o \
		$(TESTS) $(OBJ_TEST) -lcheck $(LIBS)

test/unit/main.c: $(TESTS)
	./test/unit/mkmain.sh test/unit/main.c test/unit/*.ts

.ts_test.c:
	awk -f test/unit/checkmk.awk $< >$@

_test.c.o:
	$(CC) $(CFLAGS) -I. -c -o $@ $<

clean:
	rm -f agec agecgen $(OBJS) $(TESTS) $(TESTTMP)

base64.o:	base64.h util.h
bech32.o:	bech32.h $(OS)/common.h
agec.o:		$(OS)/common.h arg.h base64.h crypto.h header.h io.h parse.h \
		payload.h scrypt.h util.h x25519.h
header.o:	header.h $(OS)/common.h base64.h crypto.h util.h
io.o:		io.h $(OS)/common.h base64.h util.h
keyenc.o:	keyenc.h $(OS)/common.h crypto.h util.h
agecgen.o:	bech32.h $(OS)/common.h crypto.h util.h
parse.o:	parse.h $(OS)/common.h base64.h header.h io.h scrypt.h \
		x25519.h util.h
payload.o:	payload.h $(OS)/common.h base64.h util.h io.h crypto.h
scrypt.o:	scrypt.h $(OS)/common.h base64.h crypto.h header.h keyenc.h \
		util.h
util.o:		util.h $(OS)/common.h
x25519.o:	x25519.h $(OS)/common.h crypto.h base64.h bech32.h header.h \
		keyenc.h util.h
