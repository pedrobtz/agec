#define CK_ENV 0

typedef unsigned long long size_t;

#define ck_assert_uint_eq(a, b)	assert(a == b)
#define	ck_assert_int_eq(a, b)	assert(a == b)
#define ck_assert_msg(a, ...)	assert(a)
#define ck_assert 		assert
#define ck_assert_mem_eq(a, b, n)\
				assert(memcmp(a, b, n) == 0)
#define ck_assert_str_eq(a, b)	assert(strcmp(a, b) == 0)

#define START_TEST(x)		void x(void)
#define END_TEST

typedef int SRunner;
typedef int Suite;
typedef int TCase;

static SRunner *srunner_create(Suite *) { return 0; }
static Suite *suite_create(char *name) { return 0; }
static TCase *tcase_create(char *) { return 0; }
static void suite_add_tcase(Suite*, TCase*) {}
static void srunner_add_suite(SRunner*, Suite*) {}
static void srunner_run_all(SRunner*, int) {}
static int srunner_ntests_failed(SRunner*) { return 0;}
static void tcase_add_test(TCase*, void (*fn)(void)) { fn(); }
static void srunner_free(SRunner*) {}
