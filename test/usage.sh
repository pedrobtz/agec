#!/bin/sh -x

if [ $(uname) = Plan9 ]; then
	tool=../6.agec
else
	tool=../agec
fi
rec=age19a79get8k27m20w6j3z7jw5xarn22u2lhf6rpwg2hqpg83vkmsus3k4m7f

fail() {
	echo >&2 $0: expected fail
	exit 1
}

"$tool" -d -a 2>/dev/null && fail
"$tool" -d -r $rec 2>/dev/null && fail
"$tool" -d -p 2>/dev/null && fail
"$tool" -d -a -r $rec 2>/dev/null && fail
"$tool" -d -a -p 2>/dev/null && fail
"$tool" -d -r $rec -p 2>/dev/null && fail

"$tool" -r $rec -p 2>/dev/null && fail
"$tool" 2>/dev/null && fail
"$tool" -i /dev/null 2>/dev/null && fail
"$tool" -a 2>/dev/null && fail

exit 0
