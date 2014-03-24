#define NULL 0

#include <stdint.h>
#include <cstdlib>

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) ({			\
        const decltype( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})

struct A {
	int x;
};

struct B : public A {
};

int main() {
	A *a = new B();
	container_of(&a->x, A, x);
	return 0;
}
