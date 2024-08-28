/**
 * Describes functions for converting processor-generic CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <string.h>
#include <json.h>
#include "../edk/Cper.h"
#include "../cper-utils.h"
#include "cper-section-generic.h"

//Converts the given processor-generic CPER section into JSON IR.
json_object *cper_section_generic_to_ir(void *section)
{
	EFI_PROCESSOR_GENERIC_ERROR_DATA *section_generic =
		(EFI_PROCESSOR_GENERIC_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Validation bits.
	json_object *validation =
		bitfield_to_ir(section_generic->ValidFields, 13,
			       GENERIC_VALIDATION_BITFIELD_NAMES);
	json_object_object_add(section_ir, "validationBits", validation);

	//Processor type, with human readable name if possible.
	json_object *processor_type = integer_to_readable_pair(
		section_generic->Type,
		sizeof(GENERIC_PROC_TYPES_KEYS) / sizeof(int),
		GENERIC_PROC_TYPES_KEYS, GENERIC_PROC_TYPES_VALUES,
		"Unknown (Reserved)");
	json_object_object_add(section_ir, "processorType", processor_type);

	//Processor ISA, with human readable name if possible.
	json_object *processor_isa = integer_to_readable_pair(
		section_generic->Isa,
		sizeof(GENERIC_ISA_TYPES_KEYS) / sizeof(int),
		GENERIC_ISA_TYPES_KEYS, GENERIC_ISA_TYPES_VALUES,
		"Unknown (Reserved)");
	json_object_object_add(section_ir, "processorISA", processor_isa);

	//Processor error type, with human readable name if possible.
	json_object *processor_error_type = integer_to_readable_pair(
		section_generic->ErrorType,
		sizeof(GENERIC_ERROR_TYPES_KEYS) / sizeof(int),
		GENERIC_ERROR_TYPES_KEYS, GENERIC_ERROR_TYPES_VALUES,
		"Unknown (Reserved)");
	json_object_object_add(section_ir, "errorType", processor_error_type);

	//The operation performed, with a human readable name if possible.
	json_object *operation = integer_to_readable_pair(
		section_generic->Operation,
		sizeof(GENERIC_OPERATION_TYPES_KEYS) / sizeof(int),
		GENERIC_OPERATION_TYPES_KEYS, GENERIC_OPERATION_TYPES_VALUES,
		"Unknown (Reserved)");
	json_object_object_add(section_ir, "operation", operation);

	//Flags, additional information about the error.
	json_object *flags = bitfield_to_ir(section_generic->Flags, 4,
					    GENERIC_FLAGS_BITFIELD_NAMES);
	json_object_object_add(section_ir, "flags", flags);

	//The level of the error.
	json_object_object_add(section_ir, "level",
			       json_object_new_int(section_generic->Level));

	//CPU version information.
	json_object_object_add(
		section_ir, "cpuVersionInfo",
		json_object_new_uint64(section_generic->VersionInfo));

	//CPU brand string. May not exist if on ARM.
	json_object_object_add(
		section_ir, "cpuBrandString",
		json_object_new_string(section_generic->BrandString));

	//Remaining 64-bit fields.
	json_object_object_add(section_ir, "processorID",
			       json_object_new_uint64(section_generic->ApicId));
	json_object_object_add(
		section_ir, "targetAddress",
		json_object_new_uint64(section_generic->TargetAddr));
	json_object_object_add(
		section_ir, "requestorID",
		json_object_new_uint64(section_generic->RequestorId));
	json_object_object_add(
		section_ir, "responderID",
		json_object_new_uint64(section_generic->ResponderId));
	json_object_object_add(
		section_ir, "instructionIP",
		json_object_new_uint64(section_generic->InstructionIP));

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
	section_cper->ValidFields = ir_to_bitfield(
		json_object_object_get(section, "validationBits"), 13,
		GENERIC_VALIDATION_BITFIELD_NAMES);

	//Various name/value pair fields.
	section_cper->Type = (UINT8)readable_pair_to_integer(
		json_object_object_get(section, "processorType"));
	section_cper->Isa = (UINT8)readable_pair_to_integer(
		json_object_object_get(section, "processorISA"));
	section_cper->ErrorType = (UINT8)readable_pair_to_integer(
		json_object_object_get(section, "errorType"));
	section_cper->Operation = (UINT8)readable_pair_to_integer(
		json_object_object_get(section, "operation"));

	//Flags.
	section_cper->Flags =
		(UINT8)ir_to_bitfield(json_object_object_get(section, "flags"),
				      4, GENERIC_FLAGS_BITFIELD_NAMES);

	//Various numeric/string fields.
	section_cper->Level = (UINT8)json_object_get_int(
		json_object_object_get(section, "level"));
	section_cper->VersionInfo = json_object_get_uint64(
		json_object_object_get(section, "cpuVersionInfo"));
	section_cper->ApicId = json_object_get_uint64(
		json_object_object_get(section, "processorID"));
	section_cper->TargetAddr = json_object_get_uint64(
		json_object_object_get(section, "targetAddress"));
	section_cper->RequestorId = json_object_get_uint64(
		json_object_object_get(section, "requestorID"));
	section_cper->ResponderId = json_object_get_uint64(
		json_object_object_get(section, "responderID"));
	section_cper->InstructionIP = json_object_get_uint64(
		json_object_object_get(section, "instructionIP"));

	//CPU brand string.
	const char *brand_string = json_object_get_string(
		json_object_object_get(section, "cpuBrandString"));
	if (brand_string != NULL) {
		strncpy(section_cper->BrandString, brand_string,
			sizeof(section_cper->BrandString) - 1);
		section_cper
			->BrandString[sizeof(section_cper->BrandString) - 1] =
			'\0';
	}

	//Write & flush out to file, free memory.
	fwrite(section_cper, sizeof(EFI_PROCESSOR_GENERIC_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}
