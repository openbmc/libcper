#include <libcper/base64.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

void test_base64_encode_good()
{
	int32_t encoded_len = 0;
	const char *data = "f";
	char *encoded = base64_encode((unsigned char *)data, strlen(data),
				      &encoded_len);
	assert(encoded_len == 4);
	assert(memcmp(encoded, "Zg==", encoded_len) == 0);
	free(encoded);
}

void test_base64_decode_good()
{
	int32_t decoded_len = 0;
	const char *data = "Zg==";
	UINT8 *decoded = base64_decode(data, strlen(data), &decoded_len);
	assert(decoded_len == 1);
	assert(decoded[0] == 'f');
	free(decoded);
}
