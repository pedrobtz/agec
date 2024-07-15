</$objtype/mkfile

os = plan9
TARG = agec keygen
BIN = /$objtype/bin
HFILES = base64.h bech32.h plan9/common.h crypto.h header.h io.h \
	keyenc.h parse.h payload.h scrypt.h util.h x25519.h

</sys/src/cmd/mkmany

CFLAGS = $CFLAGS -I. -I$os
OBJ_AGEC = agec.$O base64.$O bech32.$O header.$O io.$O keyenc.$O \
	parse.$O payload.$O scrypt.$O util.$O x25519.$O \
	crypto/chacha20poly1305.$O crypto/curve25519.$O crypto/hkdf.$O \
	crypto/hmac.$O crypto/scrypt.$O crypto/sha256.$O \
	$os/random.$O $os/util.$O
OBJ_KEYGEN = bech32.$O keygen.$O util.$O \
	crypto/curve25519.$O \
	$os/random.$O $os/util.$O

$O.agec: $OBJ_AGEC
$O.keygen: $OBJ_KEYGEN

%.$O: %.c
	$CC $CFLAGS -o $target $stem.c

clean:V:
	rm -f *.[$OS] crypto/*.[$OS] $os/*.[$OS] [$OS].??*
