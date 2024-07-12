/**
 * Describes functions for converting firmware CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <json.h>
#include "../edk/Cper.h"
#include "../cper-utils.h"
#include "cper-section-firmware.h"

//Converts a single firmware CPER section into JSON IR.
json_object *cper_section_firmware_to_ir(void *section)
{
	EFI_FIRMWARE_ERROR_DATA *firmware_error =
		(EFI_FIRMWARE_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Record type.
	json_object *record_type = integer_to_readable_pair(
		firmware_error->ErrorType, 3, FIRMWARE_ERROR_RECORD_TYPES_KEYS,
		FIRMWARE_ERROR_RECORD_TYPES_VALUES, "Unknown (Reserved)");
	json_object_object_add(section_ir, "errorRecordType", record_type);

	//Revision, record identifier.
	json_object_object_add(section_ir, "revision",
			       json_object_new_int(firmware_error->Revision));
	json_object_object_add(
		section_ir, "recordID",
		json_object_new_uint64(firmware_error->RecordId));

	//Record GUID.
	char record_id_guid[GUID_STRING_LENGTH];
	guid_to_string(record_id_guid, &firmware_error->RecordIdGuid);
	json_object_object_add(section_ir, "recordIDGUID",
			       json_object_new_string(record_id_guid));

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
