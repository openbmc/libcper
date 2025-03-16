/**
 * Defines utility functions for testing CPER-JSON IR output from the cper-parse library.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include "test-utils.hpp"

#include <libcper/BaseTypes.h>
#include <libcper/generator/cper-generate.h>

namespace fs = std::filesystem;

// Objects that have mutually exclusive fields (and thereforce can't have both
// required at the same time) can be added to this list.
// Truly optional properties that shouldn't be added to "required" field for
// validating the entire schema with validationbits=1
const static std::map<std::string, std::vector<std::string> >
	optional_properties_map = {
		{ "./sections/cper-cxl-protocol.json",
		  { "capabilityStructure", "deviceSerial" } },
		{ "./sections/cper-cxl-component.json",
		  { "cxlComponentEventLog" } },
		{ "./sections/cper-ia32x64-processor.json",
		  { "addressSpace", "errorType", "participationType",
		    "timedOut", "level", "operation", "preciseIP",
		    "restartableIP", "overflow", "uncorrected",
		    "transactionType" } },
	};

nlohmann::json loadJson(const char *filePath)
{
	std::ifstream file(filePath);
	if (!file.is_open()) {
		std::cerr << "Failed to open file: " << filePath << std::endl;
	}
	nlohmann::json out = nlohmann::json::parse(file, nullptr, false);
	return out;
}

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

void iterate_make_required_props(nlohmann::json &jsonSchema,
				 std::vector<std::string> &optional_props)
{
	//id
	const auto it_id = jsonSchema.find("$id");
	if (it_id != jsonSchema.end()) {
		auto id_strptr = it_id->get_ptr<const std::string *>();
		std::string id_str = *id_strptr;
		if (id_str.find("header") != std::string::npos ||
		    id_str.find("section-descriptor") != std::string::npos) {
			return;
		}
	}
	//oneOf
	const auto it_oneof = jsonSchema.find("oneOf");
	if (it_oneof != jsonSchema.end()) {
		//Iterate over oneOf properties
		for (auto &oneOfProp : *it_oneof) {
			iterate_make_required_props(oneOfProp, optional_props);
		}
	}

	//items
	const auto it_items = jsonSchema.find("items");
	if (it_items != jsonSchema.end()) {
		iterate_make_required_props(*it_items, optional_props);
	}
	//required
	const auto it_req = jsonSchema.find("required");
	if (it_req == jsonSchema.end()) {
		return;
	}

	//properties
	const auto it_prop = jsonSchema.find("properties");
	if (it_prop == jsonSchema.end()) {
		return;
	}
	nlohmann::json &propertyFields = *it_prop;
	nlohmann::json::array_t property_list;
	if (propertyFields.is_object()) {
		for (auto &[key, value] : propertyFields.items()) {
			const auto it_find_opt_prop =
				std::find(optional_props.begin(),
					  optional_props.end(), key);
			if (it_find_opt_prop == optional_props.end()) {
				//Add to list if property is not optional
				property_list.push_back(key);
			}

			iterate_make_required_props(value, optional_props);
		}
	}

	*it_req = property_list;
}

// Document loader callback function
const nlohmann::json *documentLoader(const std::string &uri,
				     AddRequiredProps add_required_props)
{
	// Load the schema from a file
	std::unique_ptr<nlohmann::json> ref_schema =
		std::make_unique<nlohmann::json>();
	*ref_schema = loadJson(uri.c_str());
	if (ref_schema->is_discarded()) {
		std::cerr << "Could not open schema file: " << uri << std::endl;
	}
	if (add_required_props == AddRequiredProps::YES) {
		std::vector<std::string> opt = {};
		const auto it_optional_file = optional_properties_map.find(uri);
		if (it_optional_file != optional_properties_map.end()) {
			opt = it_optional_file->second;
		}
		iterate_make_required_props(*ref_schema, opt);
	}

	return ref_schema.release();
}

// Document release callback function
void documentRelease(const nlohmann::json *adapter)
{
	delete adapter; // Free the adapter memory
}

std::unique_ptr<valijson::Schema>
load_schema(AddRequiredProps add_required_props, int single_section)
{
	// Load the schema
	fs::path pathObj(LIBCPER_JSON_SPEC);

	if (single_section) {
		pathObj /= "cper-json-section-log.json";
	} else {
		pathObj /= "cper-json-full-log.json";
	}
	nlohmann::json schema_root = loadJson(pathObj.c_str());
	fs::path base_path(LIBCPER_JSON_SPEC);
	try {
		fs::current_path(base_path);
		// std::cout << "Changed directory to: " << fs::current_path()
		// 	  << std::endl;
	} catch (const fs::filesystem_error &e) {
		std::cerr << "Filesystem error: " << e.what() << std::endl;
	}

	// Parse the json schema into an internal schema format
	std::unique_ptr<valijson::Schema> schema =
		std::make_unique<valijson::Schema>();
	valijson::SchemaParser parser;
	valijson::adapters::NlohmannJsonAdapter schemaDocumentAdapter(
		schema_root);

	// Set up callbacks for resolving external references
	try {
		parser.populateSchema(
			schemaDocumentAdapter, *schema,
			[add_required_props](const std::string &uri) {
				return documentLoader(uri, add_required_props);
			},
			documentRelease);
	} catch (std::exception &e) {
		std::cerr << "Failed to parse schema: " << e.what()
			  << std::endl;
	}
	return schema;
}

int schema_validate_from_file(const valijson::Schema &schema,
			      nlohmann::json &jsonData,
			      std::string &error_message)
{
	// Perform validation
	valijson::Validator validator(valijson::Validator::kStrongTypes);
	valijson::ValidationResults results;
	valijson::adapters::NlohmannJsonAdapter targetDocumentAdapter(jsonData);
	if (!validator.validate(schema, targetDocumentAdapter, &results)) {
		std::cerr << "Validation failed." << std::endl;
		valijson::ValidationResults::Error error;
		unsigned int errorNum = 1;
		while (results.popError(error)) {
			std::string context;
			for (const std::string &str : error.context) {
				context += str;
			}

			std::cout << "Error #" << errorNum << '\n'
				  << "  context: " << context << '\n'
				  << "  desc:    " << error.description << '\n';
			++errorNum;
		}
		return 0;
	}

	error_message = "Schema validation successful";
	return 1;
}
