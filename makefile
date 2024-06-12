CC ?= cc
CFLAGS += -Werror -Wall -Wextra -pedantic
LIBS = -lssl -lcrypto
OBJ_CAGE = cage.o base64.o scrypt.o util.o libscrypt/crypto_scrypt.o \
	libscrypt/sha256.o header.o payload.o x25519.o bech32.o io.o \
	keyenc.o parse.o crypto/curve25519.o crypto/random.o
OBJ_KEYGEN = keygen.o bech32.o util.o crypto/curve25519.o crypto/random.o
OBJS = $(OBJ_CAGE) $(OBJ_KEYGEN)
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)bin
.SUFFIXES: .c .o

all: cage cage-keygen

cage: $(OBJ_CAGE)
	$(CC) $(LDFLAGS) $(OBJ_CAGE) $(LIBS) -o $@

cage-keygen: $(OBJ_KEYGEN)
	$(CC) $(LDFLAGS) $(OBJ_KEYGEN) $(LIBS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

base64.o:	base64.h util.h
bech32.o:	bech32.h common.h
cage.o:		base64.h common.h header.h scrypt.h x25519.h io.h payload.h \
		parse.h crypto.h
header.o:	header.h base64.h common.h
io.o:		io.h common.h base64.h
keyenc.o:	keyenc.h common.h util.h
keygen.o:	bech32.h common.h util.h crypto.h
parse.o:	parse.h common.h io.h base64.h scrypt.h x25519.h
payload.o:	payload.h common.h base64.h util.h io.h
scrypt.o:	scrypt.h base64.h common.h header.h keyenc.h util.h crypto.h
util.o:		util.h
x25519.o:	x25519.h common.h base64.h bech32.h header.h keyenc.h util.h \
		crypto.h

install: cage cage-keygen
	mkdir -p $(DESTDIR)$(BINDIR)
	cp -f cage cage-keygen $(DESTDIR)$(BINDIR)
	chmod 755 $(DESTDIR)$(BINDIR)/cage $(DESTDIR)$(BINDIR)cage-keygen

clean:
	rm -f cage cage-keygen $(OBJS)
