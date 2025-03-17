#include <assert.h>
#include "libcper/cper-parse.h"
#include "test-utils.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	json_object *ir = cper_buf_to_ir(data, size);
	if (ir == NULL) {
		return 0;
	}

	int valid = schema_validate_from_file(ir, 0 /* single_section */,
					      /*all_valid_bits*/ 0);
	if (!valid) {
		printf("JSON: %s\n", json_object_to_json_string(ir));
	}
	assert(valid);
	json_object_put(ir);

	return 0;
}
