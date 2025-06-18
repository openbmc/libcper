/**
 * Describes functions for converting processor-generic CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <string.h>
#include <json.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-generic.h>
#include <libcper/log.h>
#include <string.h>

//Converts the given processor-generic CPER section into JSON IR.
json_object *cper_section_generic_to_ir(const UINT8 *section, UINT32 size,
					char **desc_string)
{
	int outstr_len = 0;
	*desc_string = malloc(SECTION_DESC_STRING_SIZE);
	outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
			      "A Generic Processor Error occurred");
	if (outstr_len < 0) {
		cper_print_log(
			"Error: Could not write to Generic description string\n");
	} else if (outstr_len > SECTION_DESC_STRING_SIZE) {
		cper_print_log("Error: Generic description string truncated\n");
	}

	if (size < sizeof(EFI_PROCESSOR_GENERIC_ERROR_DATA)) {
		return NULL;
	}

	EFI_PROCESSOR_GENERIC_ERROR_DATA *section_generic =
		(EFI_PROCESSOR_GENERIC_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	ValidationTypes ui64Type = {
		UINT_64T, .value.ui64 = section_generic->ValidFields
	};

	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		//Processor type, with human readable name if possible.
		json_object *processor_type = integer_to_readable_pair(
			section_generic->Type,
			sizeof(GENERIC_PROC_TYPES_KEYS) / sizeof(int),
			GENERIC_PROC_TYPES_KEYS, GENERIC_PROC_TYPES_VALUES,
			"Unknown (Reserved)");
		json_object_object_add(section_ir, "processorType",
				       processor_type);
	}

	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		//Processor ISA, with human readable name if possible.
		json_object *processor_isa = integer_to_readable_pair(
			section_generic->Isa,
			sizeof(GENERIC_ISA_TYPES_KEYS) / sizeof(int),
			GENERIC_ISA_TYPES_KEYS, GENERIC_ISA_TYPES_VALUES,
			"Unknown (Reserved)");
		json_object_object_add(section_ir, "processorISA",
				       processor_isa);
	}

	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		//Processor error type, with human readable name if possible.
		json_object *processor_error_type = integer_to_readable_pair(
			section_generic->ErrorType,
			sizeof(GENERIC_ERROR_TYPES_KEYS) / sizeof(int),
			GENERIC_ERROR_TYPES_KEYS, GENERIC_ERROR_TYPES_VALUES,
			"Unknown (Reserved)");
		json_object_object_add(section_ir, "errorType",
				       processor_error_type);
	}

	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		//The operation performed, with a human readable name if possible.
		json_object *operation = integer_to_readable_pair(
			section_generic->Operation,
			sizeof(GENERIC_OPERATION_TYPES_KEYS) / sizeof(int),
			GENERIC_OPERATION_TYPES_KEYS,
			GENERIC_OPERATION_TYPES_VALUES, "Unknown (Reserved)");
		json_object_object_add(section_ir, "operation", operation);
	}

	if (isvalid_prop_to_ir(&ui64Type, 4)) {
		//Flags, additional information about the error.
		json_object *flags =
			bitfield_to_ir(section_generic->Flags, 4,
				       GENERIC_FLAGS_BITFIELD_NAMES);
		json_object_object_add(section_ir, "flags", flags);
	}

	if (isvalid_prop_to_ir(&ui64Type, 5)) {
		//The level of the error.
		json_object_object_add(
			section_ir, "level",
			json_object_new_int(section_generic->Level));
	}

	if (isvalid_prop_to_ir(&ui64Type, 6)) {
		//CPU version information.
		json_object_object_add(
			section_ir, "cpuVersionInfo",
			json_object_new_uint64(section_generic->VersionInfo));
	}

	if (isvalid_prop_to_ir(&ui64Type, 7)) {
		//CPU brand string. May not exist if on ARM.
		add_untrusted_string(section_ir, "cpuBrandString",
				     section_generic->BrandString,
				     sizeof(section_generic->BrandString));
	}

	if (isvalid_prop_to_ir(&ui64Type, 8)) {
		//Remaining 64-bit fields.
		json_object_object_add(
			section_ir, "processorID",
			json_object_new_uint64(section_generic->ApicId));
	}

	if (isvalid_prop_to_ir(&ui64Type, 9)) {
		json_object_object_add(
			section_ir, "targetAddress",
			json_object_new_uint64(section_generic->TargetAddr));
	}

	if (isvalid_prop_to_ir(&ui64Type, 10)) {
		json_object_object_add(
			section_ir, "requestorID",
			json_object_new_uint64(section_generic->RequestorId));
	}

	if (isvalid_prop_to_ir(&ui64Type, 11)) {
		json_object_object_add(
			section_ir, "responderID",
			json_object_new_uint64(section_generic->ResponderId));
	}

	if (isvalid_prop_to_ir(&ui64Type, 12)) {
		json_object_object_add(
			section_ir, "instructionIP",
			json_object_new_uint64(section_generic->InstructionIP));
	}

	return section_ir;
}

//Converts the given CPER-JSON processor-generic error section into CPER binary,
//outputting to the provided stream.
void ir_section_generic_to_cper(json_object *section, FILE *out)
{
	EFI_PROCESSOR_GENERIC_ERROR_DATA *section_cper =
		(EFI_PROCESSOR_GENERIC_ERROR_DATA *)calloc(
			1, sizeof(EFI_PROCESSOR_GENERIC_ERROR_DATA));

	//Validation bits.
	//Remove
	// section_cper->ValidFields = ir_to_bitfield(
	// 	json_object_object_get(section, "validationBits"), 13,
	// 	GENERIC_VALIDATION_BITFIELD_NAMES);
	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;
	//Various name/value pair fields.
	if (json_object_object_get_ex(section, "processorType", &obj)) {
		section_cper->Type = (UINT8)readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 0);
	}
	if (json_object_object_get_ex(section, "processorISA", &obj)) {
		section_cper->Isa = (UINT8)readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 1);
	}
	if (json_object_object_get_ex(section, "errorType", &obj)) {
		section_cper->ErrorType = (UINT8)readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 2);
	}
	if (json_object_object_get_ex(section, "operation", &obj)) {
		section_cper->Operation = (UINT8)readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 3);
	}
	//Flags.
	if (json_object_object_get_ex(section, "flags", &obj)) {
		section_cper->Flags = (UINT8)ir_to_bitfield(
			obj, 4, GENERIC_FLAGS_BITFIELD_NAMES);
		add_to_valid_bitfield(&ui64Type, 4);
	}

	//Various numeric/string fields.
	if (json_object_object_get_ex(section, "level", &obj)) {
		section_cper->Level = (UINT8)json_object_get_int(obj);
		add_to_valid_bitfield(&ui64Type, 5);
	}
	if (json_object_object_get_ex(section, "cpuVersionInfo", &obj)) {
		section_cper->VersionInfo = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 6);
	}
	if (json_object_object_get_ex(section, "processorID", &obj)) {
		section_cper->ApicId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 8);
	}
	if (json_object_object_get_ex(section, "targetAddress", &obj)) {
		section_cper->TargetAddr = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 9);
	}
	if (json_object_object_get_ex(section, "requestorID", &obj)) {
		section_cper->RequestorId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 10);
	}
	if (json_object_object_get_ex(section, "responderID", &obj)) {
		section_cper->ResponderId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 11);
	}
	if (json_object_object_get_ex(section, "instructionIP", &obj)) {
		section_cper->InstructionIP = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 12);
	}

	//CPU brand string.
	if (json_object_object_get_ex(section, "cpuBrandString", &obj)) {
		const char *brand_string = json_object_get_string(obj);
		if (brand_string != NULL) {
			strncpy(section_cper->BrandString, brand_string,
				sizeof(section_cper->BrandString) - 1);
			section_cper
				->BrandString[sizeof(section_cper->BrandString) -
					      1] = '\0';
		}
		add_to_valid_bitfield(&ui64Type, 7);
	}
	section_cper->ValidFields = ui64Type.value.ui64;

	//Write & flush out to file, free memory.
	fwrite(section_cper, sizeof(EFI_PROCESSOR_GENERIC_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}
