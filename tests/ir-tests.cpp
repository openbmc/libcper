/**
 * Defines tests for validating CPER-JSON IR output from the cper-parse library.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <cctype>
#include "gtest/gtest.h"
#include "test-utils.hpp"
#include <json.h>
#include "../cper-parse.h"
#include "../json-schema.h"
#include "../generator/cper-generate.h"
#include "../sections/cper-section.h"
#include "../generator/sections/gen-section.h"

/*
* Test templates.
*/

//Tests a single randomly generated CPER section of the given type to ensure CPER-JSON IR validity.
void cper_log_section_ir_test(const char *section_name, int single_section)
{
	//Generate full CPER record for the given type.
	char *buf;
	size_t size;
	FILE *record = generate_record_memstream(&section_name, 1, &buf, &size,
						 single_section);

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
	char error_message[JSON_ERROR_MSG_MAX_LEN] = { 0 };
	int valid =
		validate_schema_from_file(LIBCPER_JSON_SPEC, ir, error_message);
	json_object_put(ir);
	ASSERT_TRUE(valid)
		<< "IR validation test failed (single section mode = "
		<< single_section << ") with message: " << error_message;
}

//Checks for binary round-trip equality for a given randomly generated CPER record.
void cper_log_section_binary_test(const char *section_name, int single_section)
{
	//Generate CPER record for the given type.
	char *buf;
	size_t size;
	FILE *record = generate_record_memstream(&section_name, 1, &buf, &size,
						 single_section);

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
	size_t cper_len = ftell(stream);
	fclose(stream);

	//Validate the two are identical.
	ASSERT_GE(size, cper_len);
	ASSERT_EQ(memcmp(buf, cper_buf, cper_len), 0)
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
	cper_log_section_ir_test(section_name, 0);
	cper_log_section_ir_test(section_name, 1);
}

//Tests randomly generated CPER sections for binary compatibility of a given type, in both single section mode and full CPER log mode.
void cper_log_section_dual_binary_test(const char *section_name)
{
	cper_log_section_binary_test(section_name, 0);
	cper_log_section_binary_test(section_name, 1);
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
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}
