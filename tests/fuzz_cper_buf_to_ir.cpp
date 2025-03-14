#include "libcper/cper-parse.h"
#include "test-utils.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	json_object *ir = cper_buf_to_ir(data, size);
	if (ir == NULL) {
		return 0;
	}
	char *str = strdup(json_object_to_json_string(ir));

	nlohmann::json jsonData = nlohmann::json::parse(str, nullptr, false);
	free(str);
	assert(jsonData.is_discarded() == false);
	std::string error_message;
	static valijson::Schema schema = load_schema(AddRequiredProps::NO);

	int valid = schema_validate_from_file(schema, jsonData, error_message);
	if (!valid) {
		std::cout << "JSON: " << jsonData.dump(4) << std::endl;
		std::cout << "Error: " << error_message << std::endl;
	}
	assert(valid);
	json_object_put(ir);

	return 0;
}
