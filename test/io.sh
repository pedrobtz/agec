#!/bin/sh

age=../agec
gen=../agecgen

die() {
	echo >&2 $*
	exit 1
}

sizes="
	`seq 1 300`
	`seq 8000 8300`
	`seq 1 4096 131072`
	`seq 65336 65736`
"

$gen >vectors/priv 2>/dev/null || exit 1
rec=`$gen -y <vectors/priv` || exit 1

for i in $sizes; do
	dd bs=$i count=1 </dev/zero >vectors/body 2>/dev/null || die dd failed
	$age -r$rec vectors/body >vectors/out || die fail at size $i
	$age -d -ivectors/priv vectors/out >vectors/decbody \
		|| die fail at size $i
	cmp -s vectors/body vectors/decbody || die differ at size $i
done
