#include <string.h>

#include "common.h"
#include "bech32.h"

#suite bech32

typedef struct Vecs Vecs;
struct Vecs {
	size_t inlen;
	const char *hrp;
	const char *in;
	char *out;
};

#test bech32_decode
	uchar buf[256];
	size_t outlen, hrplen, i;
	int r;
	Vecs vecs[] = {
		{0, "a", "", strdup("A12UEL5L")}, /* bech32decode modify input */
		{0, "a", "", "a12uel5l"},
		{0, "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio", "", "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs"},
		{20, "abcdef", "\x00\x44\x32\x14\xc7\x42\x54\xb6\x35\xcf\x84\x65\x3a\x56\xd7\xc6\x75\xbe\x77\xdf", "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw"},
		{51, "1", "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j"},
		{30, "split", "\xc5\xf3\x8b\x70\x30\x5f\x51\x9b\xf6\x6d\x85\xfb\x6c\xf0\x30\x58\xf3\xdd\xe4\x63\xec\xd7\x91\x8f\x2d\xc7\x43\x91\x8f\x2d", "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"},
		{0, "?", "", "?1ezyfcl"},
	};
	Vecs vec;

	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		vec = vecs[i];
		memset(buf, 0xbe, sizeof(buf));
		r = bech32decode((char *)vec.out, buf, &outlen, &hrplen);
		ck_assert_msg(r == 1, "input %d: %s", i, vec.out);
		ck_assert_uint_eq(outlen, vec.inlen);
		ck_assert_uint_eq(hrplen, strlen(vec.hrp));
		ck_assert_mem_eq(buf, vec.in, vec.inlen);
		ck_assert_uint_eq(buf[outlen], 0xbe);
	}

#test bech32_decode_bad_hrp_char
	uchar buf[256];
	size_t outlen, hrplen, i;
	int r;
	const char *vecs[] = {
		"\x20" "1nwldj5",
		"\x7f" "1axkwrx",
		"\x80" "1eym55h",
	};

	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		r = bech32decode((char *)vecs[i], buf, &outlen, &hrplen);
		ck_assert_msg(r == 0, "input %d", i);
	}

#test bech32_decode_too_long
	uchar buf[256];
	size_t outlen, hrplen;
	int r;
	const char *in = "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx";

	r = bech32decode((char *)in, buf, &outlen, &hrplen);
	ck_assert_int_eq(r, 0);

#test bech32_decode_no_separator
	uchar buf[256];
	size_t outlen, hrplen;
	int r;
	const char *in = "pzry9x0s0muk";

	r = bech32decode((char *)in, buf, &outlen, &hrplen);
	ck_assert_int_eq(r, 0);

#test bech32_decode_empty_hrp
	uchar buf[256];
	size_t outlen, hrplen, i;
	int r;
	const char *vecs[] = {
		"1pzry9x0s0muk",
		"10a06t8",
		"1qzzfhee",
	};

	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		r = bech32decode((char *)vecs[i], buf, &outlen, &hrplen);
		ck_assert_msg(r == 0, "input %d", i);
	}

#test bech32_decode_checksum_too_short
	uchar buf[256];
	size_t outlen, hrplen;
	int r;
	const char *in = "li1dgmt3";

	r = bech32decode((char *)in, buf, &outlen, &hrplen);
	ck_assert_int_eq(r, 0);

#test bech32_decode_checksum_on_uppercase_hrp
	uchar buf[256];
	size_t outlen, hrplen;
	int r;
	const char *in = strdup("A1G7SGD8");

	r = bech32decode((char *)in, buf, &outlen, &hrplen);
	ck_assert_int_eq(r, 0);

#test bech32_decode_bad_data_char
	uchar buf[256];
	size_t outlen, hrplen;
	int r;
	const char *in = "x1b4n0q5v";

	r = bech32decode((char *)in, buf, &outlen, &hrplen);
	ck_assert_int_eq(r, 0);

#test bech32_decode_bad_checksum_char
	uchar buf[256];
	size_t outlen, hrplen;
	int r;
	const char *in = "de1lg7wt" "\xff";

	r = bech32decode((char *)in, buf, &outlen, &hrplen);
	ck_assert_int_eq(r, 0);

#test bech32_decode_case_mix
	uchar buf[256];
	size_t outlen, hrplen;
	int r;
	char *in = strdup("tag1l7lq3vYslk");

	r = bech32decode((char *)in, buf, &outlen, &hrplen);
	ck_assert_int_eq(r, 0);

#test bech32_encode
	uchar buf[256];
	size_t i;
	int r;
	Vecs vecs[] = {
		{0, "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio", "", "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs"},
		{20, "abcdef", "\x00\x44\x32\x14\xc7\x42\x54\xb6\x35\xcf\x84\x65\x3a\x56\xd7\xc6\x75\xbe\x77\xdf", "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw"},
		{51, "1", "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j"},
		{30, "split", "\xc5\xf3\x8b\x70\x30\x5f\x51\x9b\xf6\x6d\x85\xfb\x6c\xf0\x30\x58\xf3\xdd\xe4\x63\xec\xd7\x91\x8f\x2d\xc7\x43\x91\x8f\x2d", "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"},
		{0, "?", "", "?1ezyfcl"},
	};
	Vecs vec;

	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		vec = vecs[i];
		memset(buf, 0xbe, sizeof(buf));
		r = bech32encode((char *)vec.hrp, (uchar *)vec.in,
				vec.inlen, buf);
		ck_assert_msg(r == 1, "input %d: %s", i, vec.out);
		ck_assert_uint_eq(strlen((char *)buf), strlen(vec.out));
		ck_assert_str_eq((char *)buf, vec.out);
		ck_assert_uint_eq(buf[strlen((char *)buf) + 1], 0xbe);
	}

#test bech32_encode_bad_hrp
	uchar buf[256];
	size_t i;
	int r;
	char *vecs[] = {
		"prefix" "\x01",
		"prefix" "\x7f",
		"prefix" "\xff",
		"prefix" "\xaf",
	};
	char *in = "foobar";
	Vecs vec;

	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		r = bech32encode(vecs[i], (uchar *)in, strlen(vecs[i]), buf);
		ck_assert_msg(r == 0, "input %d: %s", i, vec.out);
	}

#test bech32_encode_too_long
	uchar buf[256];
	int r;
	uchar in[51];

	memset(in, 0xff, sizeof(in));
	r = bech32encode("ab", in, sizeof(in), buf);
	ck_assert_uint_eq(r, 0);
