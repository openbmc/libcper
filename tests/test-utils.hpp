#ifndef CPER_IR_TEST_UTILS_H
#define CPER_IR_TEST_UTILS_H

#include <valijson/adapters/nlohmann_json_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>
#include <nlohmann/json.hpp>

extern "C" {
#include <stdio.h>
#include <libcper/BaseTypes.h>
#include <libcper/generator/sections/gen-section.h>
}

// Controls whether required properties are added to the majority of property
// definitions.  This is useful for unit tests that are validating JSON where
// all fields are valid
enum class AddRequiredProps { YES, NO };

FILE *generate_record_memstream(const char **types, UINT16 num_types,
				char **buf, size_t *buf_size,
				int single_section,
				GEN_VALID_BITS_TEST_TYPE validBitsType);

std::unique_ptr<valijson::Schema>
load_schema(AddRequiredProps add_required_props, int single_section);

int schema_validate_from_file(const valijson::Schema &schema,
			      nlohmann::json &jsonData,
			      std::string &error_message);

nlohmann::json loadJson(const char *filePath);

#endif
