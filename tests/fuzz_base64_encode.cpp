#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include "libcper/base64.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	INT32 encoded_len = 0;
	CHAR8 *encoded = base64_encode(data, size, &encoded_len);
	if (encoded != NULL) {
		free(encoded);
	}
	return 0;
}
