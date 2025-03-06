#include <cstdint>
#include "libcper/cper-parse.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	json_object *ir;
	ir = cper_buf_single_section_to_ir(data, size);
	if (ir != NULL) {
		json_object_put(ir);
	}

	return 0;
}
