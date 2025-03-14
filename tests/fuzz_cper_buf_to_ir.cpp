#include <cassert>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include "libcper/cper-parse.h"
#include <string>
#include <iostream>
#include <span>
#include <libcper/Cper.h>

std::string to_hex(char *input, size_t size)
{
	std::string out;
	for (size_t i = 0; i < size; i++) {
		out += std::format("{:02x}",
				   static_cast<unsigned char>(input[i]));
		if (i % 8 == 7) {
			out += "\n";
		}
	}
	return out;
}

uint8_t *zero_out_reserved_bits(const uint8_t *input, size_t size)
{
	uint8_t *input_copy = (uint8_t *)malloc(size);
	memcpy(input_copy, input, size);
	size_t remaining = size;
	if (remaining < sizeof(EFI_COMMON_ERROR_RECORD_HEADER)) {
			return NULL;
	}

	EFI_COMMON_ERROR_RECORD_HEADER *header = NULL;
	header = (EFI_COMMON_ERROR_RECORD_HEADER *)input;
	remaining -= sizeof(EFI_COMMON_ERROR_RECORD_HEADER);
	input += sizeof(EFI_COMMON_ERROR_RECORD_HEADER);

	// Reserved bits beyond the third bit are reserved.
	header->ValidationBits |= 0X7;
	return input_copy;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	printf("start\n");
	json_object *ir = cper_buf_to_ir(data, size);

	if (ir != NULL) {
		json_object_put(ir);
	}
	uint8_t *data_no_reserved = zero_out_reserved_bits(data, size);

	ir = cper_buf_to_ir(data_no_reserved, size);
	bool data_same = false;
	if (ir != NULL) {
		void *buf = malloc(size);
		FILE *out = fmemopen(buf, size, "w");
		ir_to_cper(ir, out);

		fclose(out);

		//Print the input and output.

		std::cout << "json: " << json_object_to_json_string(ir)
			  << std::endl;
		std::cout << "Input: \n"
			  << to_hex((char *)data, size) << std::endl;
		std::cout << "Output: \n"
			  << to_hex((char *)buf, size) << std::endl;
		json_object_put(ir);


		data_same = memcmp(data, data_no_reserved, size) == 0;
		free(data_no_reserved);

		assert(data_same);

	}
	free(data_no_reserved);


	return 0;
}
