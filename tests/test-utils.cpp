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

nlohmann::json loadJson(const char *filePath)
{
	std::ifstream file(filePath);
	if (!file.is_open()) {
		std::cerr << "Failed to open file: " << filePath << std::endl;
	}
	// Parse the correct way?
	nlohmann::json out = nlohmann::json::parse(file, nullptr, false);
	// std::cout << "trying to parse schema: " << out << std::endl;
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

// Document loader callback function
const nlohmann::json *documentLoader(const std::string &uri)
{
	// static std::unordered_map<std::string, nlohmann::json> loadedSchemas;

	// Check if the schema is already loaded
	// Load the schema from a file
	nlohmann::json *ref_schema = new nlohmann::json;
	// std::cout << "documentLoader: " << uri << std::endl;
	*ref_schema = loadJson(uri.c_str());
	if (ref_schema->is_discarded()) {
		std::cerr << "Could not open schema file: " << uri << std::endl;
	}
	// std::cout << "documentLoader: " << *ref_schema << std::endl;

	// Return a new adapter for the loaded schema
	//return ref_schema;
	// valijson::adapters::NlohmannJsonAdapter *adapter = new valijson::adapters::NlohmannJsonAdapter(ref_schema);
	// return *adapter
	return ref_schema;
}

// Document release callback function
void documentRelease(const nlohmann::json *adapter)
{
	delete adapter; // Free the adapter memory
}

int schema_validate_from_file(const char *schema_file_path,
			      nlohmann::json jsonData,
			      std::string &error_message)
{
	// Load the schema
	nlohmann::json schema_root = loadJson(schema_file_path);
	if (schema_root.is_discarded()) {
		std::cerr << "Could not open schema file: " << schema_file_path
			  << std::endl;
		return 0;
	}

	fs::path pathObj(schema_file_path);
	fs::path base_path = pathObj.parent_path();
	try {
		fs::current_path(base_path);
		// std::cout << "Changed directory to: " << fs::current_path()
		// 	  << std::endl;
	} catch (const fs::filesystem_error &e) {
		std::cerr << "Filesystem error: " << e.what() << std::endl;
	}

	// Parse the json schema into an internal schema format
	valijson::Schema schema;
	valijson::SchemaParser parser;
	valijson::adapters::NlohmannJsonAdapter schemaDocumentAdapter(
		schema_root);

	// Set up callbacks for resolving external references
	// parser.setDocumentLoader(&documentLoader);
	// parser.setDocumentRelease(&documentRelease);

	try {
		parser.populateSchema(schemaDocumentAdapter, schema,
				      documentLoader, documentRelease);
	} catch (std::exception &e) {
		std::cerr << "Failed to parse schema: " << e.what()
			  << std::endl;
		return 0;
	}

	// std::cout<< "Final schema: " << schema.dump(4) << std::endl;
	// std::cout << "JsonData: " << jsonData << std::endl;

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
			std::vector<std::string>::iterator itr =
				error.context.begin();
			for (; itr != error.context.end(); itr++) {
				context += *itr;
			}

			std::cout << "Error #" << errorNum << std::endl
				  << "  context: " << context << std::endl
				  << "  desc:    " << error.description
				  << std::endl;
			++errorNum;
		}
		return 0;
	}

	error_message = "Schema validation successful";
	// std::cerr << "Validation passed for: " << schema_file_path << std::endl;
	return 1;
}
