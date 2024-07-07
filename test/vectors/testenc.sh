#!/bin/sh

checksegfault() {
	test $1 -gt 127 && echo >&2 $0: abnormal termination && exit $1
}

tool=../../agec
reftool=age

rm -f body priv
body=false
nbytes=0
while IFS='' read -r LINE || test -n "${LINE}"; do
	if test -z "${LINE}"; then
		nbytes=`expr $nbytes + 1`
		break
	fi
	len=`echo $LINE | wc -c`
	nbytes=`expr $nbytes + $len`
	key=`echo "${LINE}" | sed 's/: .*//g'`
	val=`echo "${LINE}" | sed 's/.*: //g'`
	case "$key" in
	expect)
		expect="$val"
		;;
	recipient)
		recipient="$val"
		;;
	identity)
		identity="$val"
		;;
	passphrase)
		pass="$val"
		;;
	armored)
		armored="$val"
		;;
	comment)
		;;
	*)
		echo >&2 $0: unknown key: $key
		exit 1
	esac
done < "$1"

dd bs=1 skip=$nbytes <"$1" >body 2>/dev/null
test $? != 0 && echo >&2 $0: dd failed

if test -n "$identity"; then
	test -z "$recipient" && echo >&2 $0: $1: recipient is not provided
	echo "$identity" >priv
	test -n $armored && aflag=-a
	"$tool" $aflag -r "$recipient" <body >out
	code=$?
	checksegfault $code
	if test "$expect" = success; then
		if test $code != 0; then
			echo >&2 $0: test failed: expected success, got $code
			exit 1
		fi
	else
		if test $code = 0; then
			echo >&2 $0: test failed: expected failure "($expect)"
			exit 1
		fi
		exit 0
	fi
	"$reftool" -i priv -d <out >/dev/null
	if test $? != 0; then
		echo >&2 $0: reference implementation failed to decrypt
		exit 1
	fi
else
	test -z "$pass" && echo >&2 $0: neither identity nor password \
			is provided
	test -n $armored && aflag=-a
	echo password: $pass
	"$tool" $aflag -p <body >out
	code=$?
	checksegfault $code
	if test "$expect" = success; then
		if test $code != 0; then
			echo >&2 $0: test failed: expected success, got $code
			exit 1
		fi
	else
		if test $code = 0; then
			echo >&2 $0: test failed: expected failure "($expect)"
			exit 1
		fi
		exit 0
	fi
	"$reftool" -d <out >/dev/null
	if test $? != 0; then
		echo >&2 $0: reference implementation failed to decrypt
		exit 1
	fi
fi

exit 0
