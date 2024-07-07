#!/bin/sh

tool=../../agec
reftool=age
sha256="openssl sha256"

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
	payload)
		payload="$val"
		;;
	"file key")
		filekey="$val"
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
	echo password: password
	echo "$identity" | "$reftool" -p >priv
	test $? != 0 && echo >&2 $0: reftool failed to encrypt keys
	"$tool" -d -ipriv <body >out
	code=$?
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
	hash=`$sha256 <out`
	test $? != 0 && echo >&2 $0: failed to compute output hashsum
	hash=`echo "$hash" | sed 's/.* //g'`
	test $? != 0 && echo >&2 $0: failed to compute output hashsum
	if test "$hash" != "$payload"; then
		echo >&2 $0: test failed: invalid payload sum: expected $payload
	fi
else
	echo >&2 $0: specified test has no identity metadata
	exit 1
fi

exit 0
