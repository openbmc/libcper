/**
 * Defines utility functions for testing CPER-JSON IR output from the cper-parse library.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test-utils.h"

#include <libcper/BaseTypes.h>
#include <libcper/generator/cper-generate.h>

#include <validate.h>
#include <json.h>
#include <libcper/log.h>

// Objects that have mutually exclusive fields (and thereforce can't have both
// required at the same time) can be added to this list.
// Truly optional properties that shouldn't be added to "required" field for
// validating the entire schema with validationbits=1
// In most cases making sure examples set all valid bits is preferable to adding to this list
static const char *optional_props[] = {
	// Some sections don't parse header correctly?
	"header",

	// Each section is optional
	"GenericProcessor", "Ia32x64Processor", "ArmProcessor", "Memory",
	"Memory2", "Pcie", "PciBus", "PciComponent", "Firmware", "GenericDmar",
	"VtdDmar", "IommuDmar", "CcixPer", "CxlProtocol", "CxlComponent",
	"Nvidia", "Ampere", "Unknown",

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
	"transactionType"
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
		generate_cper_record((char **)(types), num_types, stream,
				     validBitsType);
	} else {
		generate_single_section_record((char *)(types[0]), stream,
					       validBitsType);
	}
	fclose(stream);

	//Return fmemopen() buffer for reading.
	return fmemopen(*buf, *buf_size, "r");
}

int iterate_make_required_props(json_object *jsonSchema, int all_valid_bits)
{
	//properties
	json_object *properties =
		json_object_object_get(jsonSchema, "properties");

	if (properties != NULL) {
		json_object *requrired_arr = json_object_new_array();

		json_object_object_foreach(properties, property_name,
					   property_value)
		{
			(void)property_value;
			int add_to_required = 1;
			size_t num = sizeof(optional_props) /
				     sizeof(optional_props[0]);
			for (size_t i = 0; i < num; i++) {
				if (strcmp(optional_props[i], property_name) ==
				    0) {
					add_to_required = 0;
					break;
				}
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
				json_object_put(requrired_arr);
				return -1;
			}
		}

		if (all_valid_bits) {
			json_object_object_add(jsonSchema, "required",
					       requrired_arr);
		} else {
			json_object_put(requrired_arr);
		}
	}

	// ref
	json_object *ref = json_object_object_get(jsonSchema, "$ref");
	if (ref != NULL) {
		const char *ref_str = json_object_get_string(ref);
		if (ref_str != NULL) {
			if (strlen(ref_str) < 1) {
				cper_print_log("Failed seek filepath: %s\n",
					       ref_str);
				return -1;
			}
			size_t size =
				strlen(LIBCPER_JSON_SPEC) + strlen(ref_str);
			char *path = (char *)malloc(size);
			int n = snprintf(path, size, "%s%s", LIBCPER_JSON_SPEC,
					 ref_str + 1);
			if (n != (int)size - 1) {
				cper_print_log("Failed concat filepath: %s\n",
					       ref_str);
				free(path);
				return -1;
			}
			json_object *ref_obj = json_object_from_file(path);
			free(path);
			if (ref_obj == NULL) {
				cper_print_log("Failed to parse file: %s\n",
					       ref_str);
				return -1;
			}

			if (iterate_make_required_props(ref_obj,
							all_valid_bits) < 0) {
				json_object_put(ref_obj);
				return -1;
			}

			json_object_object_foreach(ref_obj, key, val)
			{
				// Use json_object_get to increment ref count properly
				json_object *val_copy = json_object_get(val);
				json_object_object_add(jsonSchema, key,
						       val_copy);
			}
			json_object_object_del(jsonSchema, "$ref");

			json_object_put(ref_obj);
		}
	}

	//oneOf
	const json_object *oneOf = json_object_object_get(jsonSchema, "oneOf");
	if (oneOf != NULL) {
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
	if (items != NULL) {
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
	printf("start schema_validate_from_file\n");
	int size = strlen(schema_file) + 1 + strlen(LIBCPER_JSON_SPEC) + 1;
	char *schema_path = malloc(size);
	snprintf(schema_path, size, "%s/%s", LIBCPER_JSON_SPEC, schema_file);

	json_object *schema = json_object_from_file(schema_path);

	if (schema == NULL) {
		cper_print_log("Could not parse schema file: %s", schema_path);
		free(schema_path);
		return 0;
	}
	printf("end iterate_make_required_props\n");
	if (iterate_make_required_props(schema, all_valid_bits) < 0) {
		cper_print_log("Failed to make required props\n");
		json_object_put(schema);
		free(schema_path);
		return -1;
	}
	printf("start schemavalidator_validate\n");
	int err = schemavalidator_validate(to_test, schema);
	if (err == SCHEMAVALIDATOR_ERR_VALID) {
		cper_print_log("validation ok\n");
		json_object_put(schema);
		free(schema_path);
		return 1;
	}
	printf("end schemavalidator_validate\n");
	cper_print_log("validate failed %d: %s\n", err,
		       schemavalidator_errorstr(err));

	json_object_put(schema);
	free(schema_path);
	return 0;
}
