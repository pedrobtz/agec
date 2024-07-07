#include <string.h>

#include "common.h"
#include "base64.h"

#suite base64

typedef struct Vecs Vecs;
struct Vecs {
	const char *in, *out;
};

#test base64_encode
	size_t olen, i;
	uchar buf[256];
	Vecs vecs[] = {
		{"",       ""},
		{"f",      "Zg"},
		{"fo",     "Zm8"},
		{"foo",    "Zm9v"},
		{"foob",   "Zm9vYg"},
		{"fooba",  "Zm9vYmE"},
		{"foobar", "Zm9vYmFy"},
		{"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg"},
	};

	memset(buf, 0xbe, sizeof(buf));
	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		base64encode((uchar *)vecs[i].in, buf,
				strlen(vecs[i].in), &olen, 0);
		ck_assert_uint_eq(olen, strlen(vecs[i].out));
		ck_assert(buf[olen] == 0xbe);
		ck_assert_mem_eq(buf, vecs[i].out, olen);
	}

#test base64_encode_stream
	size_t olen, i;
	uchar buf[256];
	Vecs vecs[] = {
		{"",       "\n"},
		{"f",      "Zg==\n"},
		{"fo",     "Zm8=\n"},
		{"foo",    "Zm9v\n"},
		{"foob",   "Zm9vYg==\n"},
		{"fooba",  "Zm9vYmE=\n"},
		{"foobar", "Zm9vYmFy\n"},
		{"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4\neHh4eHh4eHh4eHh4eHh4eHg=\n"},
	};

	memset(buf, 0xbe, sizeof(buf));
	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		base64encode((uchar *)vecs[i].in, buf,
				strlen(vecs[i].in), &olen, 1);
		ck_assert_uint_eq(olen, strlen(vecs[i].out));
		ck_assert(buf[olen] == 0xbe);
		ck_assert_mem_eq(buf, vecs[i].out, olen);
	}

#test base64_decode
	size_t olen, i;
	int r;
	uchar buf[256];
	Vecs vecs[] = {
		{"",       ""},
		{"f",      "Zg"},
		{"fo",     "Zm8"},
		{"foo",    "Zm9v"},
		{"foob",   "Zm9vYg"},
		{"fooba",  "Zm9vYmE"},
		{"foobar", "Zm9vYmFy"},
		{"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg"},
	};

	memset(buf, 0xbe, sizeof(buf));
	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		r = base64decode((uchar *)vecs[i].out, buf,
				strlen(vecs[i].out), &olen, 0);
		ck_assert_int_eq(r, 1);
		ck_assert_uint_eq(olen, strlen(vecs[i].in));
		ck_assert(buf[olen] == 0xbe);
		ck_assert_mem_eq(buf, vecs[i].in, olen);
	}

#test base64_decode_stream
	size_t olen, i;
	int r;
	uchar buf[256];
	Vecs vecs[] = {
		{"",       "\n"},
		{"f",      "Zg==\n"},
		{"fo",     "Zm8=\n"},
		{"foo",    "Zm9v\n"},
		{"foob",   "Zm9vYg==\n"},
		{"fooba",  "Zm9vYmE=\n"},
		{"foobar", "Zm9vYmFy\n"},
		{"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4\neHh4eHh4eHh4eHh4eHh4eHg=\n"},
	};

	memset(buf, 0xbe, sizeof(buf));
	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		r = base64decode((uchar *)vecs[i].out, buf,
				strlen(vecs[i].out), &olen, 1);
		ck_assert_int_eq(r, 1);
		ck_assert_uint_eq(olen, strlen(vecs[i].in));
		ck_assert(buf[olen] == 0xbe);
		ck_assert_mem_eq(buf, vecs[i].in, olen);
	}

#test base64_decode_stream_bad_lf
	size_t olen, i;
	int r;
	uchar buf[256];
	const char *vecs[] = {
		"Zg==",
		"Zm8=",
		"Zm9v",
		"Zm9vYg==",
		"Zm9vYmE=",
		"Zm9vYmFy",
		"Z\ng==\n",
		"Zm8\n=\n",
		"\nZm9v\n",
		"Zm9vYg=\n=\n",
		"Zm9vYmE\n=\n",
		"eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e\nHh4eHh4eHh4eHh4eHh4eHg=\n",
		"eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh\n4eHh4eHh4eHh4eHh4eHh4eHg=\n",
		"\neHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4\neHh4eHh4eHh4eHh4eHh4eHg=\n",
	};

	memset(buf, 0xbe, sizeof(buf));
	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		r = base64decode((uchar *)vecs[i], buf,
				strlen(vecs[i]), &olen, 1);
		ck_assert_msg(r == 0, "input %d: %s", i, vecs[i]);
	}

#test base64_decode_bad_char
	size_t olen, i;
	int r;
	uchar buf[256];
	const char *vecs[] = {
		"Zm9vYmE.",
		"Zm9vYmE:",
		"Zm9vYmE\x01",
		"Zm9vYmE\x7f",
		"Zm9vYmE\xff",
		"Zm.vYmE",
		"Zm:vYmE",
		"Zm\0vYmE",
		"Zm\x7fvYmE",
		"Zm\xffvYmE",
	};

	memset(buf, 0xbe, sizeof(buf));
	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		r = base64decode((uchar *)vecs[i], buf,
				strlen(vecs[i]), &olen, 0);
		ck_assert_msg(r == 0, "input %d: %s", i, vecs[i]);
	}

#test base64_decode_nopad
	size_t olen, i;
	int r;
	uchar buf[256];
	const char *vecs[] = {
		"Zg==",
		"Zm8=",
		"Zm9vYg==",
		"Zm9vYmE=",
		"eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=",
	};

	memset(buf, 0xbe, sizeof(buf));
	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		r = base64decode((uchar *)vecs[i], buf,
				strlen(vecs[i]), &olen, 0);
		ck_assert_msg(r == 0, "input %d: %s", i, vecs[i]);
	}

#test base64_decode_invalid_padding
	size_t olen, i;
	int r;
	uchar buf[256];
	const char *vecs[] = {
		"Zm9vYg====\n",
		"Zm9vYg===\n",
		"Zm9vYg=\n",
		"Zm9vY=\n",
		"Zm9vY==\n",
		"Zm9vY===\n",
		"Zm9v====\n",
		"Zm9=====\n",
		"Zm======\n",
		"Z=======\n",
		"========\n",
		"====\n",

		"Zm9vYg=g\n",
		"===g\n",
		"==g=\n",
		"=g==\n",
		"g===\n",
	};

	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		r = base64decode((uchar *)vecs[i], buf,
				strlen(vecs[i]), &olen, 1);
		ck_assert_msg(r == 0, "input %d: %s", i, vecs[i]);
	}

#test base64_decode_non_canonical
	size_t olen, i;
	int r;
	uchar buf[256];
	const char *vecs[] = {
		"Zh",
		"Zi",
		"Zj",
		"Zk",
		"Zl",
		"Zm",
		"Zn",
		"Zo",
		"Zp",
		"Zq",
		"Zr",
		"Zs",
		"Zt",
		"Zu",
		"Zv",
	};

	memset(buf, 0xbe, sizeof(buf));
	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		r = base64decode((uchar *)vecs[i], buf,
				strlen(vecs[i]), &olen, 0);
		ck_assert_msg(r == 0, "input %d: %s", i, vecs[i]);
	}
