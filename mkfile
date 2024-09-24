</$objtype/mkfile

os = plan9
TARG=\
	agec\
	agecgen

BIN = /$objtype/bin/auth

CFLAGS=$CFLAGS -I. -I$os
OFILES=\
	base64.$O\
	bech32.$O\
	header.$O\
	io.$O\
	keyenc.$O\
	parse.$O\
	payload.$O\
	scrypt.$O\
	util.$O\
	x25519.$O\
	crypto/chacha20poly1305.$O\
	crypto/curve25519.$O\
	crypto/hkdf.$O\
	crypto/hmac.$O\
	crypto/scrypt.$O\
	crypto/sha256.$O\
	$os/random.$O\
	$os/util.$O

HFILES=\
	plan9/common.h\
	crypto.h \
	header.h \
	io.h \
	keyenc.h \
	parse.h \
	payload.h \
	scrypt.h \
	util.h \
	x25519.h

CLEANFILES=$OFILES

</sys/src/cmd/mkmany

%.$O: %.c
	$CC $CFLAGS -o $target $stem.c
