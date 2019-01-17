#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#if 1

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

	return 0;
}
#else
int main(int argc, char **argv)
{
	char buffer[5];
	printf ("Buffer Contains: %s , Size Of Buffer is %zu\n", buffer,sizeof(buffer));
	strcpy(buffer,argv[1]);
	printf ("Buffer Contains: %s , Size Of Buffer is %zu\n", buffer,sizeof(buffer));
}
#endif
