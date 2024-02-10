#ifndef COMMON_H
#define COMMON_H

typedef unsigned char uchar;

typedef struct Data Data;
struct Data {
	uchar *data;
	size_t len;
};

#endif /* COMMON_H */
