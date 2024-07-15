#include <u.h>
#include <libc.h>
#include <stdio.h>

#define O_RDONLY OREAD

typedef long     ssize;
typedef u8int    uint8;
typedef u16int   uint16;
typedef u32int   uint32;
typedef u64int   uint64;
typedef s8int    int8;
typedef s16int   int16;
typedef s32int   int32;
typedef s64int   int64;

typedef struct Data Data;
struct Data {
	uchar *data;
	usize len;
};
