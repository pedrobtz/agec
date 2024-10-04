#!/bin/sh -e

if test "$#" -le 1; then
	echo "usage: $0 output [file ...]" >&2
	exit 1
fi

out="$1"
shift

echo '#include <check.h>' >$out
if [ $(uname) = Plan9 ]; then
	echo '#include <u.h>' >> $out
	echo '#include <libc.h>' >> $out
else
	echo '#define exits(x)' >> $out
fi
echo '' >>$out
sed -n '/^#suite /s/^#suite *//p' $* \
	| tr A-Z a-z \
	| sed 's/^/Suite * get_suite_/;s/$/(void);/' \
	>>$out
echo '' >>"$out"

cat <<. >>"$out"
int
main()
{
	SRunner *sr;
	int nf;

.

sed -n '/^#suite /s/^#suite *//p' $* \
	| tr A-Z a-z \
	| sed 's/^/	srunner_add_suite(sr, get_suite_/;s/$/());/' \
	| sed '1s/srunner_add_suite(sr, /sr = srunner_create(/' \
	>>$out

cat <<. >>"$out"
	srunner_run_all(sr, CK_ENV);
	nf = srunner_ntests_failed(sr);

	srunner_free(sr);
	exits(nil);
	return nf == 0 ? 0 : 1;
}
.
