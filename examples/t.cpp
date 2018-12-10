#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>

int foo(int8_t a)
{
	a++;

	printf("%s %d\n", __FUNCTION__, a);
}

int bar(int8_t a)
{
	a++;

	printf("%s %d\n", __FUNCTION__, a);
}

typedef int (*fptr_t)(int8_t);

static fptr_t fptrs[] = { foo, bar };

int main(int argc, char ** argv)
{
	printf("Hello, world!\n");

	fptrs[atoi(argv[1])](atoi(argv[2]));

	std::string s = "Hello, ";
	s.append(argv[3]);

	std::cout << s << std::endl;

	return 0;
}
