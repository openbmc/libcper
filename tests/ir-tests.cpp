/**
 * Defines tests for validating CPER-JSON IR output from the cper-parse library.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <gtest/gtest.h>
#include "test-utils.h"
#include <json.h>
#include <libcper/cper-parse.h>
#include <libcper/generator/cper-generate.h>
#include <libcper/generator/sections/gen-section.h>
#include <libcper/json-schema.h>
#include <libcper/sections/cper-section.h>

namespace fs = std::filesystem;

/*
* Test templates.
*/
static const GEN_VALID_BITS_TEST_TYPE allValidbitsSet = ALL_VALID;
static const GEN_VALID_BITS_TEST_TYPE fixedValidbitsSet = SOME_VALID;
static const int GEN_EXAMPLES = 0;

static const char *cper_ext = "cperhex";
static const char *json_ext = "json";

struct file_info {
	char *cper_out;
	char *json_out;
};

void free_file_info(file_info *info)
{
	if (info == NULL) {
		return;
	}
	free(info->cper_out);
	free(info->json_out);
	free(info);
}

file_info *file_info_init(const char *section_name)
{
	file_info *info = NULL;
	char *buf = NULL;
	size_t size;
	int ret;

	info = (file_info *)calloc(1, sizeof(file_info));
	if (info == NULL) {
		goto fail;
	}

	size = strlen(LIBCPER_EXAMPLES) + 1 + strlen(section_name) + 1 +
	       strlen(cper_ext) + 1;
	info->cper_out = (char *)malloc(size);
	ret = snprintf(info->cper_out, size, "%s/%s.%s", LIBCPER_EXAMPLES,
		       section_name, cper_ext);
	if (ret != (int)size - 1) {
		printf("snprintf0 failed\n");
		goto fail;
	}
	size = strlen(LIBCPER_EXAMPLES) + 1 + strlen(section_name) + 1 +
	       strlen(json_ext) + 1;
	info->json_out = (char *)malloc(size);
	ret = snprintf(info->json_out, size, "%s/%s.%s", LIBCPER_EXAMPLES,
		       section_name, json_ext);
	if (ret != (int)size - 1) {
		printf("snprintf3 failed\n");
		goto fail;
	}
	free(buf);
	return info;

fail:
	free(buf);
	free_file_info(info);
	return NULL;
}

void cper_create_examples(const char *section_name)
{
	//Generate full CPER record for the given type.
	json_object *ir = NULL;
	size_t size;
	size_t file_size;
	FILE *outFile = NULL;
	std::vector<unsigned char> file_data;
	FILE *record = NULL;
	char *buf = NULL;
	file_info *info = file_info_init(section_name);
	if (info == NULL) {
		goto done;
	}

	record = generate_record_memstream(&section_name, 1, &buf, &size, 0,
					   fixedValidbitsSet);

	// Write example CPER to disk
	outFile = fopen(info->cper_out, "wb");
	if (outFile == NULL) {
		std::cerr << "Failed to create/open CPER output file: "
			  << info->cper_out << std::endl;
		goto done;
	}

	fseek(record, 0, SEEK_END);
	file_size = ftell(record);
	rewind(record);
	file_data.resize(file_size);
	if (fread(file_data.data(), 1, file_data.size(), record) != file_size) {
		std::cerr << "Failed to read CPER data from memstream."
			  << std::endl;
		EXPECT_EQ(false, true);
		fclose(outFile);
		goto done;
	}
	for (size_t index = 0; index < file_data.size(); index++) {
		char hex_str[3];
		int out = snprintf(hex_str, sizeof(hex_str), "%02x",
				   file_data[index]);
		if (out != 2) {
			printf("snprintf1 failed\n");
			goto done;
		}
		fwrite(hex_str, sizeof(char), 2, outFile);
		if (index % 30 == 29) {
			fwrite("\n", sizeof(char), 1, outFile);
		}
	}
	fclose(outFile);

	//Convert to IR, free resources.
	rewind(record);
	ir = cper_to_ir(record);
	if (ir == NULL) {
		std::cerr << "Empty JSON from CPER bin" << std::endl;
		EXPECT_EQ(false, true);
		goto done;
	}

	//Write json output to disk
	json_object_to_file_ext(info->json_out, ir, JSON_C_TO_STRING_PRETTY);
	json_object_put(ir);

done:
	free_file_info(info);
	if (record != NULL) {
		fclose(record);
	}
	if (outFile != NULL) {
		fclose(outFile);
	}
	free(buf);
}

int hex2int(char ch)
{
	if ((ch >= '0') && (ch <= '9')) {
		return ch - '0';
	}
	if ((ch >= 'A') && (ch <= 'F')) {
		return ch - 'A' + 10;
	}
	if ((ch >= 'a') && (ch <= 'f')) {
		return ch - 'a' + 10;
	}
	return -1;
}

std::vector<unsigned char> string_to_binary(const char *source, size_t length)
{
	std::vector<unsigned char> retval;
	bool uppernibble = true;
	for (size_t i = 0; i < length; i++) {
		char c = source[i];
		if (c == '\n') {
			continue;
		}
		int val = hex2int(c);
		if (val < 0) {
			printf("Invalid hex character in test file: %c\n", c);
			return {};
		}

		if (uppernibble) {
			retval.push_back((unsigned char)(val << 4));
		} else {
			retval.back() += (unsigned char)val;
		}
		uppernibble = !uppernibble;
	}
	return retval;
}

//Tests fixed CPER sections for IR validity with an example set.
void cper_example_section_ir_test(const char *section_name)
{
	//Open CPER record for the given type.
	file_info *info = file_info_init(section_name);
	if (info == NULL) {
		return;
	}

	FILE *cper_file = fopen(info->cper_out, "rb");
	if (cper_file == NULL) {
		std::cerr << "Failed to open CPER file: " << info->cper_out
			  << std::endl;
		free_file_info(info);
		FAIL() << "Failed to open CPER file";
		return;
	}
	fseek(cper_file, 0, SEEK_END);
	size_t length = ftell(cper_file);
	fseek(cper_file, 0, SEEK_SET);
	char *buffer = (char *)malloc(length);
	if (!buffer) {
		free_file_info(info);
		return;
	}
	if (fread(buffer, 1, length, cper_file) != length) {
		std::cerr << "Failed to read CPER file: " << info->cper_out
			  << std::endl;
		free(buffer);
		free_file_info(info);
		return;
	}
	fclose(cper_file);

	std::vector<unsigned char> cper_bin = string_to_binary(buffer, length);
	//Convert to IR, free resources.
	json_object *ir = cper_buf_to_ir(cper_bin.data(), cper_bin.size());
	if (ir == NULL) {
		std::cerr << "Empty JSON from CPER bin" << std::endl;
		free(buffer);
		free_file_info(info);
		FAIL();
		return;
	}

	json_object *expected = json_object_from_file(info->json_out);
	EXPECT_NE(expected, nullptr);
	if (expected == nullptr) {
		free(buffer);
		free_file_info(info);
		const char *str = json_object_to_json_string(ir);

		const char *expected_str = json_object_to_json_string(expected);

		EXPECT_EQ(str, expected_str);
		return;
	}

	EXPECT_TRUE(json_object_equal(ir, expected));
	free(buffer);
	json_object_put(ir);
	json_object_put(expected);
	free_file_info(info);
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

	fclose(record);
	free(buf);

	//Validate against schema.
	int valid = schema_validate_from_file(ir, single_section,
					      /*all_valid_bits*/ 1);
	json_object_put(ir);
	EXPECT_GE(valid, 0)
		<< "IR validation test failed (single section mode = "
		<< single_section << ")\n";
}

std::string to_hex(unsigned char *input, size_t size)
{
	std::string out;
	for (unsigned char c : std::span<unsigned char>(input, size)) {
		char hex_str[3];
		int n = snprintf(hex_str, sizeof(hex_str), "%02x", c);
		if (n != 2) {
			printf("snprintf2 failed with code %d\n", n);
			return "";
		}
		out += hex_str[0];
		out += hex_str[1];
	}
	return out;
}

//Checks for binary round-trip equality for a given randomly generated CPER record.
void cper_log_section_binary_test(const char *section_name, int single_section,
				  GEN_VALID_BITS_TEST_TYPE validBitsType)
{
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

	std::cout << "size: " << size << ", cper_buf_size: " << cper_buf_size
		  << std::endl;
	EXPECT_EQ(to_hex((unsigned char *)buf, size),
		  to_hex((unsigned char *)cper_buf,
			 std::min(size, cper_buf_size)))
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
		const char *err =
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
int main(int argc, char **argv)
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
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
