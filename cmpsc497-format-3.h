#define STRLEN   16

struct A {
	int num_a; // <0 or set to 0
	int num_b; // >0 or set to 0
	char string_c[STRLEN]; // Must have vowel or add to end
	char string_d[STRLEN]; // Any string
	struct B *ptr_e; // 
	struct C *ptr_f; // 
};
struct B {
	char string_a[STRLEN]; // Any string
	int num_b; // Any integer
	char string_c[STRLEN]; // Any string
	char string_d[STRLEN]; // Capitalize Strings
};
struct C {
	char string_a[STRLEN]; // Any string
	int num_b; // Any integer
	int num_c; // >0 or set to 0
	int num_d; // Any integer
	int num_e; // Any integer
	char string_f[STRLEN]; // Must have vowel or add to end
	char string_g[STRLEN]; // Any string
};
