/*
 * Copy me if you can.
 * by 20h
 */

#define XARGBEGIN \
				for (argv++;\
					argv[0] && argv[0][0] == '-'\
					&& argv[0][1];\
					argv++) {\
				char argc_;\
				char **argv_;\
				int brk_;\
				if (argv[0][1] == '-' && argv[0][2] == '\0') {\
					argv++;\
					break;\
				}\
				for (brk_ = 0, argv[0]++, argv_ = argv;\
						argv[0][0] && !brk_;\
						argv[0]++) {\
					if (argv_ != argv)\
						break;\
					argc_ = argv[0][0];\
					switch (argc_)

#define XARGEND \
				}\
			}

#define XARGF()	\
			((argv[0][1] == '\0' && argv[1] == NULL)?\
				(char *)0 :\
				(brk_ = 1, (argv[0][1] != '\0')?\
					(&argv[0][1]) :\
					(argv++, argv[0])))
