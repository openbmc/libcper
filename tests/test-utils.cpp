/**
 * Defines utility functions for testing CPER-JSON IR output from the cper-parse library.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <filesystem>
#include <vector>
#include <algorithm>
#include "test-utils.hpp"

#include <libcper/BaseTypes.h>
#include <libcper/generator/cper-generate.h>

extern "C" {
#include <jsoncdaccord.h>
#include <json.h>
#include <libcper/log.h>
}

namespace fs = std::filesystem;

// Objects that have mutually exclusive fields (and thereforce can't have both
// required at the same time) can be added to this list.
// Truly optional properties that shouldn't be added to "required" field for
// validating the entire schema with validationbits=1
// In most cases making sure examples set all valid bits is preferable to adding to this list
const static std::vector<std::string> optional_props = {
	{ // Some sections don't parse header correctly?
	  "header",

	  // Each section is optional
	  "GenericProcessor", "Ia32x64Processor", "ArmProcessor", "Memory",
	  "Memory2", "Pcie", "PciBus", "PciComponent", "Firmware",
	  "GenericDmar", "VtdDmar", "IommuDmar", "CcixPer", "CxlProtocol",
	  "CxlComponent", "Nvidia", "Ampere", "Unknown",

	  // CXL?  might have a bug?
	  "partitionID",

	  // CXL protocol
	  "capabilityStructure", "deviceSerial",

	  // CXL component
	  "cxlComponentEventLog", "addressSpace", "errorType",
	  "participationType", "timedOut", "level", "operation", "preciseIP",
	  "restartableIP", "overflow", "uncorrected", "transactionType",

	  // PCIe AER
	  "addressSpace", "errorType", "participationType", "timedOut", "level",
	  "operation", "preciseIP", "restartableIP", "overflow", "uncorrected",
	  "transactionType" }
};

//Returns a ready-for-use memory stream containing a CPER record with the given sections inside.
FILE *generate_record_memstream(const char **types, UINT16 num_types,
				char **buf, size_t *buf_size,
				int single_section,
				GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	//Open a memory stream.
	FILE *stream = open_memstream(buf, buf_size);

	//Generate a section to the stream, close & return.
	if (!single_section) {
		generate_cper_record(const_cast<char **>(types), num_types,
				     stream, validBitsType);
	} else {
		generate_single_section_record(const_cast<char *>(types[0]),
					       stream, validBitsType);
	}
	fclose(stream);

	//Return fmemopen() buffer for reading.
	return fmemopen(*buf, *buf_size, "r");
}

int iterate_make_required_props(json_object *jsonSchema, bool all_valid_bits)
{
	//properties
	json_object *properties =
		json_object_object_get(jsonSchema, "properties");

	if (properties != nullptr) {
		json_object *requrired_arr = json_object_new_array();

		json_object_object_foreach(properties, property_name,
					   property_value)
		{
			bool add_to_required = true;
			const auto it_find_opt_prop = std::ranges::find(
				optional_props, property_name);
			if (it_find_opt_prop != optional_props.end()) {
				add_to_required = false;
			}

			if (add_to_required) {
				//Add to list if property is not optional
				json_object_array_add(
					requrired_arr,
					json_object_new_string(property_name));
			}
		}

		json_object_object_foreach(properties, property_name2,
					   property_value2)
		{
			(void)property_name2;
			if (iterate_make_required_props(property_value2,
							all_valid_bits) < 0) {
				return -1;
			}
		}

		if (all_valid_bits) {
			json_object_object_add(jsonSchema, "required",
					       requrired_arr);
		}
		//json_object_put(requrired_arr);
	}

	// ref
	json_object *ref = json_object_object_get(jsonSchema, "$ref");
	if (ref != nullptr) {
		const char *ref_str = json_object_get_string(ref);
		if (ref_str != nullptr) {
			std::string ref_path = LIBCPER_JSON_SPEC;
			// remove the leading .
			ref_path += std::string(ref_str).substr(1);
			json_object *ref_obj =
				json_object_from_file(ref_path.c_str());
			if (ref_obj == nullptr) {
				printf("Failed to parse file: %s\n",
				       ref_path.c_str());
				return -1;
			}

			if (iterate_make_required_props(ref_obj,
							all_valid_bits) < 0) {
				json_object_put(ref_obj);
				return -1;
			}

			json_object_object_foreach(ref_obj, key, val)
			{
				json_object_object_add(jsonSchema, key,
						       json_object_get(val));
			}
			json_object_object_del(jsonSchema, "$ref");

			json_object_put(ref_obj);
		}
	}

	//oneOf
	const json_object *oneOf = json_object_object_get(jsonSchema, "oneOf");
	if (oneOf != nullptr) {
		size_t num_elements = json_object_array_length(oneOf);

		for (size_t i = 0; i < num_elements; i++) {
			json_object *obj = json_object_array_get_idx(oneOf, i);
			if (iterate_make_required_props(obj, all_valid_bits) <
			    0) {
				return -1;
			}
		}
	}

	//items
	const json_object *items = json_object_object_get(jsonSchema, "items");
	if (items != nullptr) {
		json_object_object_foreach(items, key, val)
		{
			(void)key;
			if (iterate_make_required_props(val, all_valid_bits) <
			    0) {
				return -1;
			}
		}
	}

	return 1;
}

int schema_validate_from_file(json_object *to_test, int single_section,
			      int all_valid_bits)
{
	const char *schema_file;
	if (single_section) {
		schema_file = "cper-json-section-log.json";
	} else {
		schema_file = "cper-json-full-log.json";
	}

	std::string schema_path = LIBCPER_JSON_SPEC;
	schema_path += "/";
	schema_path += schema_file;

	json_object *schema = json_object_from_file(schema_path.c_str());
	if (schema == nullptr) {
		cper_print_log("Could not parse schema file: %s", schema_file);
		return 0;
	}

	if (iterate_make_required_props(schema, all_valid_bits) < 0) {
		printf("Failed to make required props\n");
		json_object_put(schema);
		return -1;
	}

	int err = jdac_validate(to_test, schema);
	if (err == JDAC_ERR_VALID) {
		printf("validation ok\n");
		json_object_put(schema);
		return 1;
	}
	printf("validate failed %d: %s\n", err, jdac_errorstr(err));

	printf("schema: \n%s\n",
	       json_object_to_json_string_ext(schema, JSON_C_TO_STRING_PRETTY));
	printf("to_test: \n%s\n", json_object_to_json_string_ext(
					  to_test, JSON_C_TO_STRING_PRETTY));
	json_object_put(schema);
	return 0;
}
