#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>

static int sha1(uint8_t * buf, size_t len, uint8_t * output)
{
	uint8_t digest[SHA_DIGEST_LENGTH];
	SHA_CTX sha1;

	SHA1_Init(&sha1);
	SHA1_Update(&sha1, buf, len);
	SHA1_Final(digest, &sha1);

	memcpy(output, digest, SHA_DIGEST_LENGTH);

	return SHA_DIGEST_LENGTH;
}


static int sha2(uint8_t * buf, size_t len, uint8_t * output)
{
	uint8_t digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, buf, len);
	SHA256_Final(digest, &sha256);

	memcpy(output, digest, SHA256_DIGEST_LENGTH);

	return SHA256_DIGEST_LENGTH;
}

static int sha3(uint8_t * buf, size_t len, uint8_t * output)
{
	uint8_t digest[SHA512_DIGEST_LENGTH];
	SHA512_CTX sha3;

	SHA512_Init(&sha3);
	SHA512_Update(&sha3, buf, len);
	SHA512_Final(digest, &sha3);

	memcpy(output, digest, SHA512_DIGEST_LENGTH);

	return SHA512_DIGEST_LENGTH;
}

typedef int (*fptr_t)(uint8_t *, size_t, uint8_t *);

static fptr_t fptrs[] = { sha1, sha2, sha3 };

int main(int argc, char ** argv)
{
	int func;
	unsigned int i;
	size_t digest_size;
	uint8_t digest[1024];

	if (argc != 1 + 2)
	{
		printf("Usage: %s sha1|sha2|sha3 data\n", argv[0]);

		exit(1);
	}

	/* Is the argument is "shaX"? */
	if (memcmp(argv[1], "sha", 3))
	{
		printf("Please choose a hash between sha1, sha2, sha3\n");

		exit(1);
	}

	func = atoi(argv[1] + 3);

	if ((func < 1) || (func > 3))
	{
		printf("Please choose a hash between sha1, sha2, sha3\n");

		exit(1);
	}

	digest_size = fptrs[func - 1]((uint8_t *)argv[2], strlen(argv[2]), digest);

	for (i = 0; i < digest_size; ++i)
		printf("%08x ", digest[i]);

	printf("\n");

	/* Anyway call sha1 */
	digest_size = sha1((uint8_t *)argv[2], strlen(argv[2]), digest);

	for (i = 0; i < digest_size; ++i)
		printf("%08x ", digest[i]);

	printf("\n");


	/* Anyway call sha1 */
	digest_size = sha1((uint8_t *)argv[2], strlen(argv[2]), digest);

	for (i = 0; i < digest_size; ++i)
		printf("%08x ", digest[i]);

	printf("\n");

	return 0;
}
