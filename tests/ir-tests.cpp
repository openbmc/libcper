/**
 * Defines tests for validating CPER-JSON IR output from the cper-parse library.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <cctype>
#include "gtest/gtest.h"
#include "test-utils.hpp"
#include <json.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <libcper/cper-parse.h>
#include <libcper/json-schema.h>
#include <libcper/generator/cper-generate.h>
#include <libcper/sections/cper-section.h>
#include <libcper/generator/sections/gen-section.h>

namespace fs = std::filesystem;

/*
* Test templates.
*/
static const GEN_VALID_BITS_TEST_TYPE allValidbitsSet = ALL_VALID;
static const GEN_VALID_BITS_TEST_TYPE fixedValidbitsSet = SOME_VALID;
static const int GEN_EXAMPLES = 0;
static const int debug = 0;

void cper_create_examples(const char *section_name)
{
	//Generate full CPER record for the given type.
	fs::path file_path = LIBCPER_EXAMPLES;
	file_path /= section_name;
	fs::path cper_out = file_path.replace_extension("cper");
	fs::path json_out = file_path.replace_extension("json");

	char *buf;
	size_t size;
	FILE *record = generate_record_memstream(&section_name, 1, &buf, &size,
						 0, fixedValidbitsSet);

	// Write example CPER to disk
	std::ofstream outFile(cper_out, std::ios::binary);
	if (!outFile.is_open()) {
		std::cerr << "Failed to create/open CPER output file: "
			  << cper_out << std::endl;
		return;
	}

	char buffer[1024];
	size_t bytesRead;
	while ((bytesRead = fread(buffer, 1, sizeof(buffer), record)) > 0) {
		outFile.write(buffer, bytesRead);
		if (!outFile) {
			std::cerr << "Failed to write to output file."
				  << std::endl;
			outFile.close();
			return;
		}
	}
	outFile.close();

	//Convert to IR, free resources.
	rewind(record);
	json_object *ir = cper_to_ir(record);
	if (ir == NULL) {
		std::cerr << "Empty JSON from CPER bin" << std::endl;
		FAIL();
		return;
	}
	char *str = strdup(json_object_to_json_string(ir));
	nlohmann::json jsonData = nlohmann::json::parse(str, nullptr, false);
	if (jsonData.is_discarded()) {
		std::cerr << "cper_create_examples: JSON parse error:"
			  << std::endl;
	}
	free(str);
	fclose(record);
	free(buf);

	//Write json output to disk
	std::ofstream jsonOutFile(json_out);
	jsonOutFile << std::setw(4) << jsonData << std::endl;
	jsonOutFile.close();
}

//Tests fixed CPER sections for IR validity with an example set.
void cper_example_section_ir_test(const char *section_name)
{
	//Open CPER record for the given type.
	fs::path fpath = LIBCPER_EXAMPLES;
	fpath /= section_name;
	fs::path cper = fpath.replace_extension("cper");
	fs::path json = fpath.replace_extension("json");

	// Do a C style read to obtain FILE*
	FILE *record = fopen(cper.string().c_str(), "rb");
	if (record == NULL) {
		std::cerr
			<< "cper_example_section_ir_test: File cannot be opened/does not exist "
			<< cper << std::endl;
		FAIL() << "cper_example_section_ir_test: File cannot be opened/does not exist";
		return;
	}

	//Convert to IR, free resources.
	json_object *ir = cper_to_ir(record);
	if (ir == NULL) {
		fclose(record);
		std::cerr << "Empty JSON from CPER bin" << std::endl;
		FAIL();
		return;
	}
	const char *str = json_object_to_json_string(ir);
	nlohmann::json jsonData = nlohmann::json::parse(str, nullptr, false);
	if (jsonData.is_discarded()) {
		std::cerr << "cper_example_section_ir_test: JSON parse error:"
			  << std::endl;
		FAIL() << "cper_example_section_ir_test: JSON parse error:";
		fclose(record);
		json_object_put(ir);

		return;
	}
	fclose(record);

	//Open json example file
	nlohmann::json jGolden = loadJson(json.string().c_str());
	if (jGolden.is_discarded()) {
		std::cerr << "Could not open JSON example file: " << json
			  << std::endl;
		FAIL() << "Could not open JSON example file";
	}

	json_object_put(ir);

	EXPECT_EQ(jGolden, jsonData);
}

//Tests a single randomly generated CPER section of the given type to ensure CPER-JSON IR validity.
void cper_log_section_ir_test(const char *section_name, int single_section,
			      GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	//Generate full CPER record for the given type.
	char *buf;
	size_t size;
	FILE *record = generate_record_memstream(&section_name, 1, &buf, &size,
						 single_section, validBitsType);

	//Convert to IR, free resources.
	json_object *ir;
	if (single_section) {
		ir = cper_single_section_to_ir(record);
	} else {
		ir = cper_to_ir(record);
	}

	char *str = strdup(json_object_to_json_string(ir));
	nlohmann::json jsonData = nlohmann::json::parse(str, nullptr, false);
	if (jsonData.is_discarded()) {
		std::cerr << "Could not parse json output" << std::endl;
	}
	free(str);
	fclose(record);
	free(buf);

	//Validate against schema.
	std::string error_message;

	int valid = schema_validate_from_file(LIBCPER_JSON_SPEC, jsonData,
					      error_message);
	json_object_put(ir);
	ASSERT_TRUE(valid)
		<< "IR validation test failed (single section mode = "
		<< single_section << ") with message: " << error_message;
}

//Checks for binary round-trip equality for a given randomly generated CPER record.
void cper_log_section_binary_test(const char *section_name, int single_section,
				  GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	single_section = 1;
	//Generate CPER record for the given type.
	char *buf;
	size_t size;
	FILE *record = generate_record_memstream(&section_name, 1, &buf, &size,
						 single_section, validBitsType);
	if (record == NULL) {
		std::cerr << "Could not generate memstream for binary test"
			  << std::endl;
		return;
	}

	//Convert to IR.
	json_object *ir;
	if (single_section) {
		ir = cper_single_section_to_ir(record);
	} else {
		ir = cper_to_ir(record);
	}

	//Now convert back to binary, and get a stream out.
	char *cper_buf;
	size_t cper_buf_size;
	FILE *stream = open_memstream(&cper_buf, &cper_buf_size);
	if (single_section) {
		ir_single_section_to_cper(ir, stream);
	} else {
		ir_to_cper(ir, stream);
	}
	fclose(stream);

	if (debug) {
		const char *pretty_json_str = json_object_to_json_string_ext(
			ir, JSON_C_TO_STRING_PRETTY);
		printf("cper_log_section_binary_test: JSON:\n%s\n",
		       pretty_json_str);
		printf("Original size: %ld, cper_buf_size:  %ld\n", size,
		       cper_buf_size);
		printf("Size of header %ld\n",
		       sizeof(EFI_COMMON_ERROR_RECORD_HEADER));
		printf("Size of section descriptor %ld\n",
		       sizeof(EFI_ERROR_SECTION_DESCRIPTOR));
		printf("Size of EFI_GENERIC_ERROR_STATUS %ld\n",
		       sizeof(EFI_GENERIC_ERROR_STATUS));

		//Print if round trip is not identical.
		for (size_t i = 0; i < size; i++) {
			uint8_t buf_i = (uint8_t)*(buf + i);
			uint8_t cper_buf_i = (uint8_t)*(cper_buf + i);
			if (buf_i != cper_buf_i) {
				printf("At byte offset %li: Original bin: %x, Final bin: %x\n",
				       i, buf_i, cper_buf_i);
			}
		}
	}

	std::cout << "size: " << size << ", cper_buf_size: " << cper_buf_size
		  << std::endl;
	EXPECT_EQ(std::string_view(buf, size),
		  std::string_view(cper_buf, std::min(size, cper_buf_size)))
		<< "Binary output was not identical to input (single section mode = "
		<< single_section << ").";

	//Free everything up.
	fclose(record);
	free(buf);
	free(cper_buf);
	json_object_put(ir);
}

//Tests randomly generated CPER sections for IR validity of a given type, in both single section mode and full CPER log mode.
void cper_log_section_dual_ir_test(const char *section_name)
{
	cper_log_section_ir_test(section_name, 0, allValidbitsSet);
	cper_log_section_ir_test(section_name, 1, allValidbitsSet);
	//Validate against examples
	cper_example_section_ir_test(section_name);
}

//Tests randomly generated CPER sections for binary compatibility of a given type, in both single section mode and full CPER log mode.
void cper_log_section_dual_binary_test(const char *section_name)
{
	cper_log_section_binary_test(section_name, 0, allValidbitsSet);
	cper_log_section_binary_test(section_name, 1, allValidbitsSet);
}

/*
* Non-single section assertions.
*/
TEST(CompileTimeAssertions, TwoWayConversion)
{
	for (size_t i = 0; i < section_definitions_len; i++) {
		//If a conversion one way exists, a conversion the other way must exist.
		std::string err =
			"If a CPER conversion exists one way, there must be an equivalent method in reverse.";
		if (section_definitions[i].ToCPER != NULL) {
			ASSERT_NE(section_definitions[i].ToIR, nullptr) << err;
		}
		if (section_definitions[i].ToIR != NULL) {
			ASSERT_NE(section_definitions[i].ToCPER, nullptr)
				<< err;
		}
	}
}

TEST(CompileTimeAssertions, ShortcodeNoSpaces)
{
	for (size_t i = 0; i < generator_definitions_len; i++) {
		for (int j = 0;
		     generator_definitions[i].ShortName[j + 1] != '\0'; j++) {
			ASSERT_FALSE(
				isspace(generator_definitions[i].ShortName[j]))
				<< "Illegal space character detected in shortcode '"
				<< generator_definitions[i].ShortName << "'.";
		}
	}
}

/*
* Single section tests.
*/

//Generic processor tests.
TEST(GenericProcessorTests, IRValid)
{
	cper_log_section_dual_ir_test("generic");
}
TEST(GenericProcessorTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("generic");
}

//IA32/x64 tests.
TEST(IA32x64Tests, IRValid)
{
	cper_log_section_dual_ir_test("ia32x64");
}
TEST(IA32x64Tests, BinaryEqual)
{
	cper_log_section_dual_binary_test("ia32x64");
}

// TEST(IPFTests, IRValid) {
//     cper_log_section_dual_ir_test("ipf");
// }

//ARM tests.
TEST(ArmTests, IRValid)
{
	cper_log_section_dual_ir_test("arm");
}
TEST(ArmTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("arm");
}

//Memory tests.
TEST(MemoryTests, IRValid)
{
	cper_log_section_dual_ir_test("memory");
}
TEST(MemoryTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("memory");
}

//Memory 2 tests.
TEST(Memory2Tests, IRValid)
{
	cper_log_section_dual_ir_test("memory2");
}
TEST(Memory2Tests, BinaryEqual)
{
	cper_log_section_dual_binary_test("memory2");
}

//PCIe tests.
TEST(PCIeTests, IRValid)
{
	cper_log_section_dual_ir_test("pcie");
}
TEST(PCIeTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("pcie");
}

//Firmware tests.
TEST(FirmwareTests, IRValid)
{
	cper_log_section_dual_ir_test("firmware");
}
TEST(FirmwareTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("firmware");
}

//PCI Bus tests.
TEST(PCIBusTests, IRValid)
{
	cper_log_section_dual_ir_test("pcibus");
}
TEST(PCIBusTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("pcibus");
}

//PCI Device tests.
TEST(PCIDevTests, IRValid)
{
	cper_log_section_dual_ir_test("pcidev");
}
TEST(PCIDevTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("pcidev");
}

//Generic DMAr tests.
TEST(DMArGenericTests, IRValid)
{
	cper_log_section_dual_ir_test("dmargeneric");
}
TEST(DMArGenericTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("dmargeneric");
}

//VT-d DMAr tests.
TEST(DMArVtdTests, IRValid)
{
	cper_log_section_dual_ir_test("dmarvtd");
}
TEST(DMArVtdTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("dmarvtd");
}

//IOMMU DMAr tests.
TEST(DMArIOMMUTests, IRValid)
{
	cper_log_section_dual_ir_test("dmariommu");
}
TEST(DMArIOMMUTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("dmariommu");
}

//CCIX PER tests.
TEST(CCIXPERTests, IRValid)
{
	cper_log_section_dual_ir_test("ccixper");
}
TEST(CCIXPERTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("ccixper");
}

//CXL Protocol tests.
TEST(CXLProtocolTests, IRValid)
{
	cper_log_section_dual_ir_test("cxlprotocol");
}
TEST(CXLProtocolTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("cxlprotocol");
}

//CXL Component tests.
TEST(CXLComponentTests, IRValid)
{
	cper_log_section_dual_ir_test("cxlcomponent-media");
}
TEST(CXLComponentTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("cxlcomponent-media");
}

//NVIDIA section tests.
TEST(NVIDIASectionTests, IRValid)
{
	cper_log_section_dual_ir_test("nvidia");
}
TEST(NVIDIASectionTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("nvidia");
}

//Unknown section tests.
TEST(UnknownSectionTests, IRValid)
{
	cper_log_section_dual_ir_test("unknown");
}
TEST(UnknownSectionTests, BinaryEqual)
{
	cper_log_section_dual_binary_test("unknown");
}

//Entrypoint for the testing program.
int main()
{
	if (GEN_EXAMPLES) {
		cper_create_examples("arm");
		cper_create_examples("ia32x64");
		cper_create_examples("memory");
		cper_create_examples("memory2");
		cper_create_examples("pcie");
		cper_create_examples("firmware");
		cper_create_examples("pcibus");
		cper_create_examples("pcidev");
		cper_create_examples("dmargeneric");
		cper_create_examples("dmarvtd");
		cper_create_examples("dmariommu");
		cper_create_examples("ccixper");
		cper_create_examples("cxlprotocol");
		cper_create_examples("cxlcomponent-media");
		cper_create_examples("nvidia");
		cper_create_examples("unknown");
	}
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}
