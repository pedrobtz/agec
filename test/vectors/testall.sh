#!/bin/sh

export ASAN_OPTIONS=log_path=log/asan

checksegfault() {
	test $1 -gt 127 && echo >&2 $0: $2: abnormal termination
}

failed=0

for case in dec/* dec-extra/*; do
	./testdec.sh $case 2>/dev/null
	code=$?
	test $code != 0 && echo >&2 $0: failed test case \"$case\" && failed=1
	checksegfault $code $case
done

for case in enc/*; do
	./testenc.sh $case 2>/dev/null
	code=$?
	test $code != 0 && echo >&2 $0: failed test case \"$case\" && failed=1
	checksegfault $code $case
done

./test-deckey.sh dec/armor
test $? != 0 && echo >&2 $0: failed test case with encrypted key && failed=1

test -n "`ls -1 log`" && echo >&2 $0: entries in log/

test $failed = 1 && exit 1

exit 0
