#include <libcper/base64.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

const char *good_encode_outputs[] = {
	"Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy",
};
const char *good_encode_inputs[] = {
	"f", "fo", "foo", "foob", "fooba", "foobar",
};

void test_base64_encode_good(void)
{
	int32_t encoded_len = 0;
	for (long unsigned int i = 0;
	     i < sizeof(good_encode_inputs) / sizeof(good_encode_inputs[0]);
	     i++) {
		const char *data = good_encode_inputs[i];
		char *encoded = base64_encode((unsigned char *)data,
					      strlen(data), &encoded_len);
		assert((size_t)encoded_len == strlen(good_encode_outputs[i]));
		assert(memcmp(encoded, good_encode_outputs[i], encoded_len) ==
		       0);
		free(encoded);
	}
}

const char *good_decode_inputs[] = {
	"Zg==", "Zg", "Zm8=", "Zm8", "Zm9v",
};
const char *good_decode_outputs[] = {
	"f", "f", "fo", "fo", "foo",
};

void test_base64_decode_good(void)
{
	for (long unsigned int i = 0;
	     i < sizeof(good_decode_inputs) / sizeof(good_decode_inputs[0]);
	     i++) {
		int32_t decoded_len = 0;
		const char *data = good_decode_inputs[i];
		UINT8 *decoded =
			base64_decode(data, strlen(data), &decoded_len);
		assert(decoded != NULL);
		assert((size_t)decoded_len == strlen(good_decode_outputs[i]));
		assert(memcmp(decoded, good_decode_outputs[i], decoded_len) ==
		       0);
		free(decoded);
	}
}
