/**
 * Describes functions for converting memory error CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <json.h>
#include "../edk/Cper.h"
#include "../cper-utils.h"
#include "cper-section-memory.h"

//Converts a single memory error CPER section into JSON IR.
json_object *cper_section_platform_memory_to_ir(void *section)
{
	EFI_PLATFORM_MEMORY_ERROR_DATA *memory_error =
		(EFI_PLATFORM_MEMORY_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Validation bitfield.
	json_object *validation =
		bitfield_to_ir(memory_error->ValidFields, 22,
			       MEMORY_ERROR_VALID_BITFIELD_NAMES);
	json_object_object_add(section_ir, "validationBits", validation);

	//Error status.
	json_object *error_status =
		cper_generic_error_status_to_ir(&memory_error->ErrorStatus);
	json_object_object_add(section_ir, "errorStatus", error_status);

	//Bank.
	json_object *bank = json_object_new_object();
	if ((memory_error->ValidFields >> 5) & 0x1) {
		//Entire bank address mode.
		json_object_object_add(
			bank, "value",
			json_object_new_uint64(memory_error->Bank));
	} else {
		//Address/group address mode.
		json_object_object_add(
			bank, "address",
			json_object_new_uint64(memory_error->Bank & 0xFF));
		json_object_object_add(
			bank, "group",
			json_object_new_uint64(memory_error->Bank >> 8));
	}
	json_object_object_add(section_ir, "bank", bank);

	//Memory error type.
	json_object *memory_error_type = integer_to_readable_pair(
		memory_error->ErrorType, 16, MEMORY_ERROR_TYPES_KEYS,
		MEMORY_ERROR_TYPES_VALUES, "Unknown (Reserved)");
	json_object_object_add(section_ir, "memoryErrorType",
			       memory_error_type);

	//"Extended" row/column indication field + misc.
	json_object *extended = json_object_new_object();
	json_object_object_add(extended, "rowBit16",
			       json_object_new_boolean(memory_error->Extended &
						       0x1));
	json_object_object_add(
		extended, "rowBit17",
		json_object_new_boolean((memory_error->Extended >> 1) & 0x1));
	json_object_object_add(extended, "chipIdentification",
			       json_object_new_int(memory_error->Extended >>
						   5));
	json_object_object_add(section_ir, "extended", extended);

	//Miscellaneous numeric fields.
	json_object_object_add(
		section_ir, "physicalAddress",
		json_object_new_uint64(memory_error->PhysicalAddress));
	json_object_object_add(
		section_ir, "physicalAddressMask",
		json_object_new_uint64(memory_error->PhysicalAddressMask));
	json_object_object_add(section_ir, "node",
			       json_object_new_uint64(memory_error->Node));
	json_object_object_add(section_ir, "card",
			       json_object_new_uint64(memory_error->Card));
	json_object_object_add(
		section_ir, "moduleRank",
		json_object_new_uint64(memory_error->ModuleRank));
	json_object_object_add(section_ir, "device",
			       json_object_new_uint64(memory_error->Device));
	json_object_object_add(section_ir, "row",
			       json_object_new_uint64(memory_error->Row));
	json_object_object_add(section_ir, "column",
			       json_object_new_uint64(memory_error->Column));
	json_object_object_add(
		section_ir, "bitPosition",
		json_object_new_uint64(memory_error->BitPosition));
	json_object_object_add(
		section_ir, "requestorID",
		json_object_new_uint64(memory_error->RequestorId));
	json_object_object_add(
		section_ir, "responderID",
		json_object_new_uint64(memory_error->ResponderId));
	json_object_object_add(section_ir, "targetID",
			       json_object_new_uint64(memory_error->TargetId));
	json_object_object_add(section_ir, "rankNumber",
			       json_object_new_uint64(memory_error->RankNum));
	json_object_object_add(
		section_ir, "cardSmbiosHandle",
		json_object_new_uint64(memory_error->CardHandle));
	json_object_object_add(
		section_ir, "moduleSmbiosHandle",
		json_object_new_uint64(memory_error->ModuleHandle));

	return section_ir;
}

//Converts a single memory error 2 CPER section into JSON IR.
json_object *cper_section_platform_memory2_to_ir(void *section)
{
	EFI_PLATFORM_MEMORY2_ERROR_DATA *memory_error =
		(EFI_PLATFORM_MEMORY2_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Validation bits.
	json_object *validation =
		bitfield_to_ir(memory_error->ValidFields, 22,
			       MEMORY_ERROR_2_VALID_BITFIELD_NAMES);
	json_object_object_add(section_ir, "validationBits", validation);

	//Error status.
	json_object *error_status =
		cper_generic_error_status_to_ir(&memory_error->ErrorStatus);
	json_object_object_add(section_ir, "errorStatus", error_status);

	//Bank.
	json_object *bank = json_object_new_object();
	if ((memory_error->ValidFields >> 5) & 0x1) {
		//Entire bank address mode.
		json_object_object_add(
			bank, "value",
			json_object_new_uint64(memory_error->Bank));
	} else {
		//Address/group address mode.
		json_object_object_add(
			bank, "address",
			json_object_new_uint64(memory_error->Bank & 0xFF));
		json_object_object_add(
			bank, "group",
			json_object_new_uint64(memory_error->Bank >> 8));
	}
	json_object_object_add(section_ir, "bank", bank);

	//Memory error type.
	json_object *memory_error_type = integer_to_readable_pair(
		memory_error->MemErrorType, 16, MEMORY_ERROR_TYPES_KEYS,
		MEMORY_ERROR_TYPES_VALUES, "Unknown (Reserved)");
	json_object_object_add(section_ir, "memoryErrorType",
			       memory_error_type);

	//Status.
	json_object *status = json_object_new_object();
	json_object_object_add(status, "value",
			       json_object_new_int(memory_error->Status));
	json_object_object_add(
		status, "state",
		json_object_new_string((memory_error->Status & 0x1) == 0 ?
					       "Corrected" :
					       "Uncorrected"));
	json_object_object_add(section_ir, "status", status);

	//Miscellaneous numeric fields.
	json_object_object_add(
		section_ir, "physicalAddress",
		json_object_new_uint64(memory_error->PhysicalAddress));
	json_object_object_add(
		section_ir, "physicalAddressMask",
		json_object_new_uint64(memory_error->PhysicalAddressMask));
	json_object_object_add(section_ir, "node",
			       json_object_new_uint64(memory_error->Node));
	json_object_object_add(section_ir, "card",
			       json_object_new_uint64(memory_error->Card));
	json_object_object_add(section_ir, "module",
			       json_object_new_uint64(memory_error->Module));
	json_object_object_add(section_ir, "device",
			       json_object_new_uint64(memory_error->Device));
	json_object_object_add(section_ir, "row",
			       json_object_new_uint64(memory_error->Row));
	json_object_object_add(section_ir, "column",
			       json_object_new_uint64(memory_error->Column));
	json_object_object_add(section_ir, "rank",
			       json_object_new_uint64(memory_error->Rank));
	json_object_object_add(
		section_ir, "bitPosition",
		json_object_new_uint64(memory_error->BitPosition));
	json_object_object_add(section_ir, "chipID",
			       json_object_new_uint64(memory_error->ChipId));
	json_object_object_add(
		section_ir, "requestorID",
		json_object_new_uint64(memory_error->RequestorId));
	json_object_object_add(
		section_ir, "responderID",
		json_object_new_uint64(memory_error->ResponderId));
	json_object_object_add(section_ir, "targetID",
			       json_object_new_uint64(memory_error->TargetId));
	json_object_object_add(
		section_ir, "cardSmbiosHandle",
		json_object_new_uint64(memory_error->CardHandle));
	json_object_object_add(
		section_ir, "moduleSmbiosHandle",
		json_object_new_uint64(memory_error->ModuleHandle));

	return section_ir;
}

//Converts a single Memory Error IR section into CPER binary, outputting to the provided stream.
void ir_section_memory_to_cper(json_object *section, FILE *out)
{
	EFI_PLATFORM_MEMORY_ERROR_DATA *section_cper =
		(EFI_PLATFORM_MEMORY_ERROR_DATA *)calloc(
			1, sizeof(EFI_PLATFORM_MEMORY_ERROR_DATA));

	//Validation bits.
	section_cper->ValidFields = ir_to_bitfield(
		json_object_object_get(section, "validationBits"), 22,
		MEMORY_ERROR_VALID_BITFIELD_NAMES);

	//Error status.
	ir_generic_error_status_to_cper(json_object_object_get(section,
							       "errorStatus"),
					&section_cper->ErrorStatus);

	//Bank.
	json_object *bank = json_object_object_get(section, "bank");
	if ((section_cper->ValidFields >> 5) & 0x1) {
		//Bank just uses simple address.
		section_cper->Bank = (UINT16)json_object_get_uint64(
			json_object_object_get(bank, "value"));
	} else {
		//Bank uses address/group style address.
		UINT16 address = (UINT8)json_object_get_uint64(
			json_object_object_get(bank, "address"));
		UINT16 group = (UINT8)json_object_get_uint64(
			json_object_object_get(bank, "group"));
		section_cper->Bank = address + (group << 8);
	}

	//"Extended" field.
	json_object *extended = json_object_object_get(section, "extended");
	section_cper->Extended = 0;
	section_cper->Extended |= json_object_get_boolean(
		json_object_object_get(extended, "rowBit16"));
	section_cper->Extended |=
		json_object_get_boolean(
			json_object_object_get(extended, "rowBit17"))
		<< 1;
	section_cper->Extended |= json_object_get_int(json_object_object_get(
					  extended, "chipIdentification"))
				  << 5;

	//Miscellaneous value fields.
	section_cper->ErrorType = (UINT8)readable_pair_to_integer(
		json_object_object_get(section, "memoryErrorType"));
	section_cper->PhysicalAddress = json_object_get_uint64(
		json_object_object_get(section, "physicalAddress"));
	section_cper->PhysicalAddressMask = json_object_get_uint64(
		json_object_object_get(section, "physicalAddressMask"));
	section_cper->Node = (UINT16)json_object_get_uint64(
		json_object_object_get(section, "node"));
	section_cper->Card = (UINT16)json_object_get_uint64(
		json_object_object_get(section, "card"));
	section_cper->ModuleRank = (UINT16)json_object_get_uint64(
		json_object_object_get(section, "moduleRank"));
	section_cper->Device = (UINT16)json_object_get_uint64(
		json_object_object_get(section, "device"));
	section_cper->Row = (UINT16)json_object_get_uint64(
		json_object_object_get(section, "row"));
	section_cper->Column = (UINT16)json_object_get_uint64(
		json_object_object_get(section, "column"));
	section_cper->BitPosition = (UINT16)json_object_get_uint64(
		json_object_object_get(section, "bitPosition"));
	section_cper->RequestorId = json_object_get_uint64(
		json_object_object_get(section, "requestorID"));
	section_cper->ResponderId = json_object_get_uint64(
		json_object_object_get(section, "responderID"));
	section_cper->TargetId = json_object_get_uint64(
		json_object_object_get(section, "targetID"));
	section_cper->RankNum = (UINT16)json_object_get_uint64(
		json_object_object_get(section, "rankNumber"));
	section_cper->CardHandle = (UINT16)json_object_get_uint64(
		json_object_object_get(section, "cardSmbiosHandle"));
	section_cper->ModuleHandle = (UINT16)json_object_get_uint64(
		json_object_object_get(section, "moduleSmbiosHandle"));

	//Write to stream, free up resources.
	fwrite(section_cper, sizeof(EFI_PLATFORM_MEMORY_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}

//Converts a single Memory Error 2 IR section into CPER binary, outputting to the provided stream.
void ir_section_memory2_to_cper(json_object *section, FILE *out)
{
	EFI_PLATFORM_MEMORY2_ERROR_DATA *section_cper =
		(EFI_PLATFORM_MEMORY2_ERROR_DATA *)calloc(
			1, sizeof(EFI_PLATFORM_MEMORY2_ERROR_DATA));

	//Validation bits.
	section_cper->ValidFields = ir_to_bitfield(
		json_object_object_get(section, "validationBits"), 22,
		MEMORY_ERROR_2_VALID_BITFIELD_NAMES);

	//Error status.
	ir_generic_error_status_to_cper(json_object_object_get(section,
							       "errorStatus"),
					&section_cper->ErrorStatus);

	//Bank.
	json_object *bank = json_object_object_get(section, "bank");
	if ((section_cper->ValidFields >> 5) & 0x1) {
		//Bank just uses simple address.
		section_cper->Bank = (UINT16)json_object_get_uint64(
			json_object_object_get(bank, "value"));
	} else {
		//Bank uses address/group style address.
		UINT16 address = (UINT8)json_object_get_uint64(
			json_object_object_get(bank, "address"));
		UINT16 group = (UINT8)json_object_get_uint64(
			json_object_object_get(bank, "group"));
		section_cper->Bank = address + (group << 8);
	}

	//Miscellaneous value fields.
	section_cper->MemErrorType = readable_pair_to_integer(
		json_object_object_get(section, "memoryErrorType"));
	section_cper->Status = (UINT8)readable_pair_to_integer(
		json_object_object_get(section, "status"));
	section_cper->PhysicalAddress = json_object_get_uint64(
		json_object_object_get(section, "physicalAddress"));
	section_cper->PhysicalAddressMask = json_object_get_uint64(
		json_object_object_get(section, "physicalAddressMask"));
	section_cper->Node = (UINT16)json_object_get_uint64(
		json_object_object_get(section, "node"));
	section_cper->Card = (UINT16)json_object_get_uint64(
		json_object_object_get(section, "card"));
	section_cper->Module = (UINT32)json_object_get_uint64(
		json_object_object_get(section, "module"));
	section_cper->Device = (UINT32)json_object_get_uint64(
		json_object_object_get(section, "device"));
	section_cper->Row = (UINT32)json_object_get_uint64(
		json_object_object_get(section, "row"));
	section_cper->Column = (UINT32)json_object_get_uint64(
		json_object_object_get(section, "column"));
	section_cper->Rank = (UINT32)json_object_get_uint64(
		json_object_object_get(section, "rank"));
	section_cper->BitPosition = (UINT32)json_object_get_uint64(
		json_object_object_get(section, "bitPosition"));
	section_cper->ChipId = (UINT8)json_object_get_uint64(
		json_object_object_get(section, "chipID"));
	section_cper->RequestorId = json_object_get_uint64(
		json_object_object_get(section, "requestorID"));
	section_cper->ResponderId = json_object_get_uint64(
		json_object_object_get(section, "responderID"));
	section_cper->TargetId = json_object_get_uint64(
		json_object_object_get(section, "targetID"));
	section_cper->CardHandle = (UINT32)json_object_get_uint64(
		json_object_object_get(section, "cardSmbiosHandle"));
	section_cper->ModuleHandle = (UINT32)json_object_get_uint64(
		json_object_object_get(section, "moduleSmbiosHandle"));

	//Write to stream, free up resources.
	fwrite(section_cper, sizeof(EFI_PLATFORM_MEMORY2_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}
