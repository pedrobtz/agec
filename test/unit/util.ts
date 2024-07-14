#include <string.h>

#include "common.h"
#include "util.h"

#suite util

char *argv0;

typedef struct Vecs Vecs;
struct Vecs {
	const char *in;
	const char *out;
};

#test util_xprogname
	const char *out;
	Vecs vecs[] = {
		{NULL,          "default"},
		{"",            "default"},
		{"/",           "default"},
		{"/foo/",       "default"},
		{"foo/",        "default"},
		{"foo//",       "default"},
		{"foo///bar/",  "default"},
		{"foo///bar//", "default"},

		{"bar",          "bar"},
		{"foo/bar",      "bar"},
		{"/foo/bar",     "bar"},
		{"/foo/bar",     "bar"},
		{"///foo/bar",   "bar"},
		{"///foo///bar", "bar"},
		{"foo///bar",    "bar"},
		{"foo/baz/bar",  "bar"},
		{"./bar",        "bar"},
		{"../bar",       "bar"},
	};
	Vecs vec;
	size_t i;

	for(i = 0; i < sizeof(vecs) / sizeof(*vecs); i++) {
		vec = vecs[i];
		out = xprogname(vec.in, "default");
		ck_assert(out);
		ck_assert_str_eq(out, vec.out);
	}
