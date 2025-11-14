/**
 * Describes functions for converting memory error CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <json.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-memory.h>
#include <libcper/log.h>
#include <string.h>

//Converts a single memory error CPER section into JSON IR.
json_object *cper_section_platform_memory_to_ir(const UINT8 *section,
						UINT32 size, char **desc_string)
{
	int outstr_len = 0;
	*desc_string = calloc(1, SECTION_DESC_STRING_SIZE);
	if (size < sizeof(EFI_PLATFORM_MEMORY_ERROR_DATA)) {
		return NULL;
	}

	EFI_PLATFORM_MEMORY_ERROR_DATA *memory_error =
		(EFI_PLATFORM_MEMORY_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = memory_error->ValidFields };

	//Error status.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *error_status = cper_generic_error_status_to_ir(
			&memory_error->ErrorStatus);
		json_object_object_add(section_ir, "errorStatus", error_status);
	}

	//Bank
	json_object *bank = json_object_new_object();
	if (isvalid_prop_to_ir(&ui64Type, 6)) {
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
	const char *mem_type_str = NULL;
	if (isvalid_prop_to_ir(&ui64Type, 14)) {
		json_object *memory_error_type = integer_to_readable_pair(
			memory_error->ErrorType, 16, MEMORY_ERROR_TYPES_KEYS,
			MEMORY_ERROR_TYPES_VALUES, "Unknown (Reserved)");
		json_object_object_add(section_ir, "memoryErrorType",
				       memory_error_type);
		mem_type_str = json_object_get_string(
			json_object_object_get(memory_error_type, "name"));
	}
	if (mem_type_str != NULL) {
		outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
				      "A %s Memory Error occurred",
				      mem_type_str);
	} else {
		outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
				      "An Unknown Memory Error occurred");
	}
	if (outstr_len < 0) {
		cper_print_log(
			"Error: Could not write to Memory description string\n");
	} else if (outstr_len > SECTION_DESC_STRING_SIZE) {
		cper_print_log(
			"Error: Memory description string truncated: %s\n",
			*desc_string);
	}
	//"Extended" row/column indication field + misc.
	if (isvalid_prop_to_ir(&ui64Type, 18)) {
		json_object *extended = json_object_new_object();
		json_object_object_add(
			extended, "rowBit16",
			json_object_new_boolean(memory_error->Extended & 0x1));
		json_object_object_add(
			extended, "rowBit17",
			json_object_new_boolean((memory_error->Extended >> 1) &
						0x1));
		if (isvalid_prop_to_ir(&ui64Type, 21)) {
			json_object_object_add(
				extended, "chipIdentification",
				json_object_new_int(memory_error->Extended >>
						    5));
		}
		json_object_object_add(section_ir, "extended", extended);
	}

	if (isvalid_prop_to_ir(&ui64Type, 16)) {
		json_object_object_add(
			section_ir, "cardSmbiosHandle",
			json_object_new_uint64(memory_error->CardHandle));
	}
	if (isvalid_prop_to_ir(&ui64Type, 17)) {
		json_object_object_add(
			section_ir, "moduleSmbiosHandle",
			json_object_new_uint64(memory_error->ModuleHandle));
	}

	//Miscellaneous numeric fields.
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		json_object_object_add(
			section_ir, "physicalAddress",
			json_object_new_uint64(memory_error->PhysicalAddress));

		char hexstring_buf[EFI_UINT64_HEX_STRING_LEN];
		snprintf(hexstring_buf, EFI_UINT64_HEX_STRING_LEN, "0x%016llX",
			 memory_error->PhysicalAddress);
		json_object_object_add(section_ir, "physicalAddressHex",
				       json_object_new_string(hexstring_buf));
		char physical_address_desc[EFI_ERROR_DESCRIPTION_STRING_LEN];
		outstr_len = snprintf(physical_address_desc,
				      EFI_ERROR_DESCRIPTION_STRING_LEN,
				      " at address 0x%016llX",
				      memory_error->PhysicalAddress);
		if (outstr_len < 0) {
			cper_print_log(
				"Error: Could not write to physical address description string\n");
		} else if (outstr_len > EFI_ERROR_DESCRIPTION_STRING_LEN) {
			cper_print_log(
				"Error: Physical address description string truncated: %s\n",
				physical_address_desc);
		} else {
			if (strlen(physical_address_desc) +
				    strlen(*desc_string) <
			    SECTION_DESC_STRING_SIZE) {
				strncat(*desc_string, physical_address_desc,
					outstr_len);
			} else {
				cper_print_log(
					"Error: Memory description string too long, not added to description string: %s\n",
					physical_address_desc);
			}
		}
	}
	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		json_object_object_add(
			section_ir, "physicalAddressMask",
			json_object_new_uint64(
				memory_error->PhysicalAddressMask));
	}
	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		json_object_object_add(
			section_ir, "node",
			json_object_new_uint64(memory_error->Node));
		char node_desc[EFI_ERROR_DESCRIPTION_STRING_LEN];
		outstr_len = snprintf(node_desc,
				      EFI_ERROR_DESCRIPTION_STRING_LEN,
				      " at node %d", memory_error->Node);
		if (outstr_len < 0) {
			cper_print_log(
				"Error: Could not write to node description string\n");
		} else if (outstr_len > EFI_ERROR_DESCRIPTION_STRING_LEN) {
			cper_print_log(
				"Error: Node description string truncated: %s\n",
				node_desc);
		} else {
			if (strlen(node_desc) + strlen(*desc_string) <
			    SECTION_DESC_STRING_SIZE) {
				strncat(*desc_string, node_desc, outstr_len);
			} else {
				cper_print_log(
					"Error: Memory description string too long, not added to description string: %s\n",
					node_desc);
			}
		}
	}

	if (isvalid_prop_to_ir(&ui64Type, 4)) {
		json_object_object_add(
			section_ir, "card",
			json_object_new_uint64(memory_error->Card));
	}
	if (isvalid_prop_to_ir(&ui64Type, 5)) {
		json_object_object_add(
			section_ir, "moduleRank",
			json_object_new_uint64(memory_error->ModuleRank));
	}
	if (isvalid_prop_to_ir(&ui64Type, 7)) {
		json_object_object_add(
			section_ir, "device",
			json_object_new_uint64(memory_error->Device));
	}
	if (isvalid_prop_to_ir(&ui64Type, 8)) {
		json_object_object_add(
			section_ir, "row",
			json_object_new_uint64(memory_error->Row));
	}
	if (isvalid_prop_to_ir(&ui64Type, 9)) {
		json_object_object_add(
			section_ir, "column",
			json_object_new_uint64(memory_error->Column));
	}
	if (isvalid_prop_to_ir(&ui64Type, 10)) {
		json_object_object_add(
			section_ir, "bitPosition",
			json_object_new_uint64(memory_error->BitPosition));
	}
	if (isvalid_prop_to_ir(&ui64Type, 11)) {
		json_object_object_add(
			section_ir, "requestorID",
			json_object_new_uint64(memory_error->RequestorId));
	}
	if (isvalid_prop_to_ir(&ui64Type, 12)) {
		json_object_object_add(
			section_ir, "responderID",
			json_object_new_uint64(memory_error->ResponderId));
	}
	if (isvalid_prop_to_ir(&ui64Type, 13)) {
		json_object_object_add(
			section_ir, "targetID",
			json_object_new_uint64(memory_error->TargetId));
	}
	if (isvalid_prop_to_ir(&ui64Type, 15)) {
		json_object_object_add(
			section_ir, "rankNumber",
			json_object_new_uint64(memory_error->RankNum));
	}

	return section_ir;
}

//Converts a single memory error 2 CPER section into JSON IR.
json_object *cper_section_platform_memory2_to_ir(const UINT8 *section,
						 UINT32 size,
						 char **desc_string)
{
	int outstr_len = 0;
	*desc_string = calloc(1, SECTION_DESC_STRING_SIZE);

	if (size < sizeof(EFI_PLATFORM_MEMORY2_ERROR_DATA)) {
		return NULL;
	}

	EFI_PLATFORM_MEMORY2_ERROR_DATA *memory_error =
		(EFI_PLATFORM_MEMORY2_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = memory_error->ValidFields };

	//Error status.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *error_status = cper_generic_error_status_to_ir(
			&memory_error->ErrorStatus);
		json_object_object_add(section_ir, "errorStatus", error_status);
	}

	//Bank.
	json_object *bank = json_object_new_object();
	if (isvalid_prop_to_ir(&ui64Type, 6)) {
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
	const char *mem_type_str = NULL;
	if (isvalid_prop_to_ir(&ui64Type, 13)) {
		json_object *memory_error_type = integer_to_readable_pair(
			memory_error->MemErrorType, 16, MEMORY_ERROR_TYPES_KEYS,
			MEMORY_ERROR_TYPES_VALUES, "Unknown (Reserved)");
		json_object_object_add(section_ir, "memoryErrorType",
				       memory_error_type);
		mem_type_str = json_object_get_string(
			json_object_object_get(memory_error_type, "name"));
	}
	if (mem_type_str != NULL) {
		outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
				      "A %s Memory Error occurred",
				      mem_type_str);
	} else {
		outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
				      "An Unknown Memory Error occurred");
	}
	if (outstr_len < 0) {
		cper_print_log(
			"Error: Could not write to Memory2 description string\n");
	} else if (outstr_len > SECTION_DESC_STRING_SIZE) {
		cper_print_log(
			"Error: Memory2 description string truncated: %s\n",
			*desc_string);
	}
	//Status.
	if (isvalid_prop_to_ir(&ui64Type, 14)) {
		json_object *status = json_object_new_object();
		json_object_object_add(
			status, "value",
			json_object_new_int(memory_error->Status));
		json_object_object_add(
			status, "state",
			json_object_new_string((memory_error->Status & 0x1) ==
							       0 ?
						       "Corrected" :
						       "Uncorrected"));
		json_object_object_add(section_ir, "status", status);
	}

	//Miscellaneous numeric fields.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object_object_add(
			section_ir, "physicalAddress",
			json_object_new_uint64(memory_error->PhysicalAddress));
		char physical_address_desc[EFI_ERROR_DESCRIPTION_STRING_LEN];
		outstr_len = snprintf(physical_address_desc,
				      EFI_ERROR_DESCRIPTION_STRING_LEN,
				      " at address 0x%016llX",
				      memory_error->PhysicalAddress);
		if (outstr_len < 0) {
			cper_print_log(
				"Error: Could not write to physical address description string\n");
		} else if (outstr_len > EFI_ERROR_DESCRIPTION_STRING_LEN) {
			cper_print_log(
				"Error: Physical address description string truncated: %s\n",
				physical_address_desc);
		} else {
			if (strlen(physical_address_desc) +
				    strlen(*desc_string) <
			    SECTION_DESC_STRING_SIZE) {
				strncat(*desc_string, physical_address_desc,
					outstr_len);
			} else {
				cper_print_log(
					"Error: Memory2 description string too long, not added to description string: %s\n",
					physical_address_desc);
			}
		}
	}

	char hexstring_buf[EFI_UINT64_HEX_STRING_LEN];
	snprintf(hexstring_buf, EFI_UINT64_HEX_STRING_LEN, "0x%016llX",
		 memory_error->PhysicalAddress);
	json_object_object_add(section_ir, "physicalAddressHex",
			       json_object_new_string(hexstring_buf));

	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		json_object_object_add(
			section_ir, "physicalAddressMask",
			json_object_new_uint64(
				memory_error->PhysicalAddressMask));
	}
	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		json_object_object_add(
			section_ir, "node",
			json_object_new_uint64(memory_error->Node));
		char node_desc[EFI_ERROR_DESCRIPTION_STRING_LEN];
		outstr_len = snprintf(node_desc,
				      EFI_ERROR_DESCRIPTION_STRING_LEN,
				      " on node %d", memory_error->Node);
		if (outstr_len < 0) {
			cper_print_log(
				"Error: Could not write to node description string\n");
		} else if (outstr_len > EFI_ERROR_DESCRIPTION_STRING_LEN) {
			cper_print_log(
				"Error: Node description string truncated: %s\n",
				node_desc);
		} else {
			if (strlen(node_desc) + strlen(*desc_string) <
			    SECTION_DESC_STRING_SIZE) {
				strncat(*desc_string, node_desc, outstr_len);
			} else {
				cper_print_log(
					"Error: Memory2 description string too long, not added to description string: %s\n",
					node_desc);
			}
		}
	}
	if (isvalid_prop_to_ir(&ui64Type, 4)) {
		json_object_object_add(
			section_ir, "card",
			json_object_new_uint64(memory_error->Card));
	}
	if (isvalid_prop_to_ir(&ui64Type, 5)) {
		json_object_object_add(
			section_ir, "module",
			json_object_new_uint64(memory_error->Module));
	}
	if (isvalid_prop_to_ir(&ui64Type, 7)) {
		json_object_object_add(
			section_ir, "device",
			json_object_new_uint64(memory_error->Device));
	}
	if (isvalid_prop_to_ir(&ui64Type, 8)) {
		json_object_object_add(
			section_ir, "row",
			json_object_new_uint64(memory_error->Row));
	}
	if (isvalid_prop_to_ir(&ui64Type, 9)) {
		json_object_object_add(
			section_ir, "column",
			json_object_new_uint64(memory_error->Column));
	}
	if (isvalid_prop_to_ir(&ui64Type, 10)) {
		json_object_object_add(
			section_ir, "rank",
			json_object_new_uint64(memory_error->Rank));
	}
	if (isvalid_prop_to_ir(&ui64Type, 11)) {
		json_object_object_add(
			section_ir, "bitPosition",
			json_object_new_uint64(memory_error->BitPosition));
	}
	if (isvalid_prop_to_ir(&ui64Type, 12)) {
		json_object_object_add(
			section_ir, "chipID",
			json_object_new_uint64(memory_error->ChipId));
	}
	if (isvalid_prop_to_ir(&ui64Type, 15)) {
		json_object_object_add(
			section_ir, "requestorID",
			json_object_new_uint64(memory_error->RequestorId));
	}
	if (isvalid_prop_to_ir(&ui64Type, 16)) {
		json_object_object_add(
			section_ir, "responderID",
			json_object_new_uint64(memory_error->ResponderId));
	}
	if (isvalid_prop_to_ir(&ui64Type, 17)) {
		json_object_object_add(
			section_ir, "targetID",
			json_object_new_uint64(memory_error->TargetId));
	}
	if (isvalid_prop_to_ir(&ui64Type, 18)) {
		json_object_object_add(
			section_ir, "cardSmbiosHandle",
			json_object_new_uint64(memory_error->CardHandle));
	}
	if (isvalid_prop_to_ir(&ui64Type, 19)) {
		json_object_object_add(
			section_ir, "moduleSmbiosHandle",
			json_object_new_uint64(memory_error->ModuleHandle));
	}

	return section_ir;
}

//Converts a single Memory Error IR section into CPER binary, outputting to the provided stream.
void ir_section_memory_to_cper(json_object *section, FILE *out)
{
	EFI_PLATFORM_MEMORY_ERROR_DATA *section_cper =
		(EFI_PLATFORM_MEMORY_ERROR_DATA *)calloc(
			1, sizeof(EFI_PLATFORM_MEMORY_ERROR_DATA));

	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;

	//Error status.
	if (json_object_object_get_ex(section, "errorStatus", &obj)) {
		ir_generic_error_status_to_cper(obj,
						&section_cper->ErrorStatus);
		add_to_valid_bitfield(&ui64Type, 0);
	}

	//Bank.
	if (json_object_object_get_ex(section, "bank", &obj)) {
		json_object *bank = obj;
		if (json_object_object_get_ex(bank, "value", &obj)) {
			//Bank just uses simple address.
			section_cper->Bank =
				(UINT16)json_object_get_uint64(obj);
			add_to_valid_bitfield(&ui64Type, 6);
		} else {
			//Bank uses address/group style address.
			UINT16 address = (UINT8)json_object_get_uint64(
				json_object_object_get(bank, "address"));
			UINT16 group = (UINT8)json_object_get_uint64(
				json_object_object_get(bank, "group"));
			section_cper->Bank = address + (group << 8);
			add_to_valid_bitfield(&ui64Type, 19);
			add_to_valid_bitfield(&ui64Type, 20);
		}
	}

	//"Extended" field.
	if (json_object_object_get_ex(section, "extended", &obj)) {
		json_object *extended = obj;
		section_cper->Extended = 0;
		section_cper->Extended |= json_object_get_boolean(
			json_object_object_get(extended, "rowBit16"));
		section_cper->Extended |=
			json_object_get_boolean(
				json_object_object_get(extended, "rowBit17"))
			<< 1;
		if (json_object_object_get_ex(extended, "chipIdentification",
					      &obj)) {
			section_cper->Extended |= json_object_get_int(obj) << 5;
			add_to_valid_bitfield(&ui64Type, 21);
		}
		add_to_valid_bitfield(&ui64Type, 18);
	}

	//Miscellaneous value fields.
	if (json_object_object_get_ex(section, "memoryErrorType", &obj)) {
		section_cper->ErrorType = (UINT8)readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 14);
	}
	if (json_object_object_get_ex(section, "physicalAddress", &obj)) {
		section_cper->PhysicalAddress = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 1);
	}
	if (json_object_object_get_ex(section, "physicalAddressMask", &obj)) {
		section_cper->PhysicalAddressMask = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 2);
	}
	if (json_object_object_get_ex(section, "node", &obj)) {
		section_cper->Node = (UINT16)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 3);
	}
	if (json_object_object_get_ex(section, "card", &obj)) {
		section_cper->Card = (UINT16)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 4);
	}
	if (json_object_object_get_ex(section, "moduleRank", &obj)) {
		section_cper->ModuleRank = (UINT16)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 5);
	}
	if (json_object_object_get_ex(section, "device", &obj)) {
		section_cper->Device = (UINT16)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 7);
	}
	if (json_object_object_get_ex(section, "row", &obj)) {
		section_cper->Row = (UINT16)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 8);
	}
	if (json_object_object_get_ex(section, "column", &obj)) {
		section_cper->Column = (UINT16)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 9);
	}
	if (json_object_object_get_ex(section, "bitPosition", &obj)) {
		section_cper->BitPosition = (UINT16)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 10);
	}
	if (json_object_object_get_ex(section, "requestorID", &obj)) {
		section_cper->RequestorId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 11);
	}
	if (json_object_object_get_ex(section, "responderID", &obj)) {
		section_cper->ResponderId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 12);
	}
	if (json_object_object_get_ex(section, "targetID", &obj)) {
		section_cper->TargetId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 13);
	}
	if (json_object_object_get_ex(section, "rankNumber", &obj)) {
		section_cper->RankNum = (UINT16)json_object_get_uint64(
			json_object_object_get(section, "rankNumber"));
		add_to_valid_bitfield(&ui64Type, 15);
	}
	if (json_object_object_get_ex(section, "cardSmbiosHandle", &obj)) {
		section_cper->CardHandle = (UINT16)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 16);
	}
	if (json_object_object_get_ex(section, "moduleSmbiosHandle", &obj)) {
		section_cper->ModuleHandle =
			(UINT16)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 17);
	}
	section_cper->ValidFields = ui64Type.value.ui64;

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
	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;

	//Error status.
	if (json_object_object_get_ex(section, "errorStatus", &obj)) {
		ir_generic_error_status_to_cper(obj,
						&section_cper->ErrorStatus);
		add_to_valid_bitfield(&ui64Type, 0);
	}

	//Bank.
	json_object *bank = json_object_object_get(section, "bank");
	if (json_object_object_get_ex(bank, "value", &obj)) {
		//Bank just uses simple address.
		section_cper->Bank = (UINT16)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 6);
	} else {
		//Bank uses address/group style address.
		UINT16 address = (UINT8)json_object_get_uint64(
			json_object_object_get(bank, "address"));
		UINT16 group = (UINT8)json_object_get_uint64(
			json_object_object_get(bank, "group"));
		section_cper->Bank = address + (group << 8);
		add_to_valid_bitfield(&ui64Type, 20);
		add_to_valid_bitfield(&ui64Type, 21);
	}

	//Miscellaneous value fields.
	if (json_object_object_get_ex(section, "memoryErrorType", &obj)) {
		section_cper->MemErrorType = readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 13);
	}
	if (json_object_object_get_ex(section, "status", &obj)) {
		section_cper->Status = (UINT8)readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 14);
	}
	if (json_object_object_get_ex(section, "physicalAddress", &obj)) {
		section_cper->PhysicalAddress = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 1);
	}
	if (json_object_object_get_ex(section, "physicalAddressMask", &obj)) {
		section_cper->PhysicalAddressMask = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 2);
	}
	if (json_object_object_get_ex(section, "node", &obj)) {
		section_cper->Node = (UINT16)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 3);
	}
	if (json_object_object_get_ex(section, "card", &obj)) {
		section_cper->Card = (UINT16)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 4);
	}
	if (json_object_object_get_ex(section, "module", &obj)) {
		section_cper->Module = (UINT32)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 5);
	}
	if (json_object_object_get_ex(section, "device", &obj)) {
		section_cper->Device = (UINT32)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 7);
	}
	if (json_object_object_get_ex(section, "row", &obj)) {
		section_cper->Row = (UINT32)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 8);
	}
	if (json_object_object_get_ex(section, "column", &obj)) {
		section_cper->Column = (UINT32)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 9);
	}
	if (json_object_object_get_ex(section, "rank", &obj)) {
		section_cper->Rank = (UINT32)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 10);
	}
	if (json_object_object_get_ex(section, "bitPosition", &obj)) {
		section_cper->BitPosition = (UINT32)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 11);
	}
	if (json_object_object_get_ex(section, "chipID", &obj)) {
		section_cper->ChipId = (UINT8)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 12);
	}
	if (json_object_object_get_ex(section, "requestorID", &obj)) {
		section_cper->RequestorId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 15);
	}
	if (json_object_object_get_ex(section, "responderID", &obj)) {
		section_cper->ResponderId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 16);
	}
	if (json_object_object_get_ex(section, "targetID", &obj)) {
		section_cper->TargetId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 17);
	}
	if (json_object_object_get_ex(section, "cardSmbiosHandle", &obj)) {
		section_cper->CardHandle = (UINT32)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 18);
	}
	if (json_object_object_get_ex(section, "moduleSmbiosHandle", &obj)) {
		section_cper->ModuleHandle =
			(UINT32)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 19);
	}

	section_cper->ValidFields = ui64Type.value.ui64;

	//Write to stream, free up resources.
	fwrite(section_cper, sizeof(EFI_PLATFORM_MEMORY2_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}
