/**
 * Describes functions for converting firmware CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <json.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-firmware.h>
#include <libcper/log.h>
#include <string.h>

//Converts a single firmware CPER section into JSON IR.
json_object *cper_section_firmware_to_ir(const UINT8 *section, UINT32 size,
					 char **desc_string)
{
	int outstr_len = 0;
	*desc_string = NULL;
	if (size < sizeof(EFI_FIRMWARE_ERROR_DATA)) {
		cper_print_log("Error: Firmware section too small\n");
		return NULL;
	}

	*desc_string = calloc(1, SECTION_DESC_STRING_SIZE);
	if (*desc_string == NULL) {
		cper_print_log(
			"Error: Failed to allocate Firmware desc string\n");
		return NULL;
	}
	outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
			      "A Firmware Error occurred");
	if (outstr_len < 0) {
		cper_print_log(
			"Error: Could not write to Firmware description string\n");
	} else if (outstr_len > SECTION_DESC_STRING_SIZE) {
		cper_print_log(
			"Error: Firmware description string truncated\n");
	}

	EFI_FIRMWARE_ERROR_DATA *firmware_error =
		(EFI_FIRMWARE_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Record type.
	json_object *record_type = integer_to_readable_pair(
		firmware_error->ErrorType, 3, FIRMWARE_ERROR_RECORD_TYPES_KEYS,
		FIRMWARE_ERROR_RECORD_TYPES_VALUES, "Unknown (Reserved)");
	json_object_object_add(section_ir, "errorRecordType", record_type);

	//Revision, record identifier.
	add_int(section_ir, "revision", firmware_error->Revision);
	add_uint(section_ir, "recordID", firmware_error->RecordId);

	//Record GUID.
	add_guid(section_ir, "recordIDGUID", &firmware_error->RecordIdGuid);

	return section_ir;
}

//Converts a single firmware CPER-JSON section into CPER binary, outputting to the given stream.
void ir_section_firmware_to_cper(json_object *section, FILE *out)
{
	EFI_FIRMWARE_ERROR_DATA *section_cper =
		(EFI_FIRMWARE_ERROR_DATA *)calloc(
			1, sizeof(EFI_FIRMWARE_ERROR_DATA));

	//Record fields.
	section_cper->ErrorType = readable_pair_to_integer(
		json_object_object_get(section, "errorRecordType"));
	section_cper->Revision = json_object_get_int(
		json_object_object_get(section, "revision"));
	section_cper->RecordId = json_object_get_uint64(
		json_object_object_get(section, "recordID"));
	string_to_guid(&section_cper->RecordIdGuid,
		       json_object_get_string(json_object_object_get(
			       section, "recordIDGUID")));

	//Write to stream, free resources.
	fwrite(section_cper, sizeof(EFI_FIRMWARE_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}
