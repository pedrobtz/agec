CC ?= cc
CFLAGS += -Werror -Wall -Wextra -pedantic
LIBS = -lssl -lcrypto
OBJ_AGEC = agec.o base64.o scrypt.o util.o header.o payload.o x25519.o \
	bech32.o io.o keyenc.o parse.o crypto/curve25519.o crypto/random.o \
	crypto/sha256.o crypto/hmac.o crypto/hkdf.o crypto/chacha20poly1305.o \
	crypto/scrypt.o
OBJ_KEYGEN = keygen.o bech32.o util.o crypto/curve25519.o crypto/random.o
OBJS = $(OBJ_AGEC) $(OBJ_KEYGEN)
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)bin
.SUFFIXES: .c .o

all: agec agec-keygen

agec: $(OBJ_AGEC)
	$(CC) $(LDFLAGS) $(OBJ_AGEC) $(LIBS) -o $@

agec-keygen: $(OBJ_KEYGEN)
	$(CC) $(LDFLAGS) $(OBJ_KEYGEN) $(LIBS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

base64.o:	base64.h util.h
bech32.o:	bech32.h common.h
agec.o:		base64.h common.h header.h scrypt.h x25519.h io.h payload.h \
		parse.h crypto.h
header.o:	header.h base64.h common.h crypto.h
io.o:		io.h common.h base64.h
keyenc.o:	keyenc.h common.h util.h
keygen.o:	bech32.h common.h util.h crypto.h
parse.o:	parse.h common.h io.h base64.h scrypt.h x25519.h
payload.o:	payload.h common.h base64.h util.h io.h crypto.h
scrypt.o:	scrypt.h base64.h common.h header.h keyenc.h util.h crypto.h
util.o:		util.h
x25519.o:	x25519.h common.h base64.h bech32.h header.h keyenc.h util.h \
		crypto.h

install: agec agec-keygen
	mkdir -p $(DESTDIR)$(BINDIR)
	cp -f agec agec-keygen $(DESTDIR)$(BINDIR)
	chmod 755 $(DESTDIR)$(BINDIR)/agec $(DESTDIR)$(BINDIR)agec-keygen

clean:
	rm -f agec agec-keygen $(OBJS)
