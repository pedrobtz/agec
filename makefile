LIBS = -lssl -lcrypto
OBJ_AGEC = agec.o base64.o bech32.o header.o io.o keyenc.o parse.o \
	payload.o scrypt.o util.o x25519.o crypto/chacha20poly1305.o \
	crypto/curve25519.o crypto/hkdf.o crypto/hmac.o crypto/random.o \
	crypto/scrypt.o crypto/sha256.o
OBJ_KEYGEN = bech32.o keygen.o util.o crypto/curve25519.o crypto/random.o
OBJS = $(OBJ_AGEC) $(OBJ_KEYGEN)
TESTS = test/unit/base64.o test/unit/bech32.o
OBJ_TEST = base64.o bech32.o
TESTTMP = test/unit/main test/unit/main.o test/unit/*.c \
	test/vectors/body test/vectors/out test/vectors/priv
PREFIX = /usr/local
BINDIR = $(PREFIX)bin
.SUFFIXES: .c .o .ts _test.c

all: agec agec-keygen

agec: $(OBJ_AGEC)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_AGEC) $(LIBS)

agec-keygen: $(OBJ_KEYGEN)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_KEYGEN) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

install: agec agec-keygen
	mkdir -p $(DESTDIR)$(BINDIR)
	cp -f agec agec-keygen $(DESTDIR)$(BINDIR)
	chmod 755 $(DESTDIR)$(BINDIR)/agec $(DESTDIR)$(BINDIR)agec-keygen

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
	rm -f agec agec-keygen $(OBJS) $(TESTS) $(TESTTMP)

base64.o:	base64.h util.h
bech32.o:	bech32.h common.h
agec.o:		common.h base64.h crypto.h header.h io.h parse.h payload.h \
		scrypt.h util.h x25519.h
header.o:	header.h common.h base64.h crypto.h util.h
io.o:		io.h common.h base64.h util.h
keyenc.o:	keyenc.h common.h crypto.h util.h
keygen.o:	bech32.h common.h crypto.h util.h
parse.o:	parse.h common.h base64.h header.h io.h scrypt.h x25519.h
payload.o:	payload.h common.h base64.h util.h io.h crypto.h
scrypt.o:	scrypt.h common.h base64.h crypto.h header.h keyenc.h util.h
util.o:		util.h
x25519.o:	x25519.h common.h crypto.h base64.h bech32.h header.h keyenc.h \
		util.h
