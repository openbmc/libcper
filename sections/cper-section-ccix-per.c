/**
 * Describes functions for converting CCIX PER log CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <string.h>
#include <json.h>
#include <libcper/base64.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-ccix-per.h>
#include <libcper/log.h>
#include <string.h>

//Converts a single CCIX PER log CPER section into JSON IR.
json_object *cper_section_ccix_per_to_ir(const UINT8 *section, UINT32 size,
					 char **desc_string)
{
	*desc_string = malloc(SECTION_DESC_STRING_SIZE);
	strncpy(*desc_string, "A CCIX PER Log Error occurred",
		SECTION_DESC_STRING_SIZE);

	if (size < sizeof(EFI_CCIX_PER_LOG_DATA)) {
		return NULL;
	}

	EFI_CCIX_PER_LOG_DATA *ccix_error = (EFI_CCIX_PER_LOG_DATA *)section;

	if (size < ccix_error->Length) {
		return NULL;
	}

	json_object *section_ir = json_object_new_object();
	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = ccix_error->ValidBits };

	//Length (bytes) for the entire structure.
	json_object_object_add(section_ir, "length",
			       json_object_new_uint64(ccix_error->Length));

	//CCIX source/port IDs.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object_object_add(
			section_ir, "ccixSourceID",
			json_object_new_int(ccix_error->CcixSourceId));
	}
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		json_object_object_add(
			section_ir, "ccixPortID",
			json_object_new_int(ccix_error->CcixPortId));
	}

	//CCIX PER Log.
	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		//This is formatted as described in Section 7.3.2 of CCIX Base Specification (Rev 1.0).
		const UINT8 *cur_pos = (const UINT8 *)(ccix_error + 1);
		int remaining_length =
			ccix_error->Length - sizeof(EFI_CCIX_PER_LOG_DATA);
		if (remaining_length > 0) {
			int32_t encoded_len = 0;

			char *encoded = base64_encode((UINT8 *)cur_pos,
						      remaining_length,
						      &encoded_len);
			if (encoded == NULL) {
				cper_print_log(
					"Failed to allocate encode output buffer. \n");
			} else {
				json_object_object_add(
					section_ir, "ccixPERLog",
					json_object_new_string_len(
						encoded, encoded_len));
				free(encoded);
			}
		}
	}

	return section_ir;
}

//Converts a single CCIX PER CPER-JSON section into CPER binary, outputting to the given stream.
void ir_section_ccix_per_to_cper(json_object *section, FILE *out)
{
	EFI_CCIX_PER_LOG_DATA *section_cper = (EFI_CCIX_PER_LOG_DATA *)calloc(
		1, sizeof(EFI_CCIX_PER_LOG_DATA));

	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;

	//Length.
	section_cper->Length = json_object_get_uint64(
		json_object_object_get(section, "length"));

	//Validation bits.
	section_cper->ValidBits = ir_to_bitfield(
		json_object_object_get(section, "validationBits"), 3,
		CCIX_PER_ERROR_VALID_BITFIELD_NAMES);

	//CCIX source/port IDs.
	if (json_object_object_get_ex(section, "ccixSourceID", &obj)) {
		section_cper->CcixSourceId = (UINT8)json_object_get_int(obj);
		add_to_valid_bitfield(&ui64Type, 0);
	}
	if (json_object_object_get_ex(section, "ccixPortID", &obj)) {
		section_cper->CcixPortId = (UINT8)json_object_get_int(obj);
		add_to_valid_bitfield(&ui64Type, 1);
	}

	bool perlog_exists = false;
	if (json_object_object_get_ex(section, "ccixPERLog", &obj)) {
		perlog_exists = true;
		add_to_valid_bitfield(&ui64Type, 2);
	}
	section_cper->ValidBits = ui64Type.value.ui64;

	//Write header out to stream.
	fwrite(section_cper, sizeof(EFI_CCIX_PER_LOG_DATA), 1, out);
	fflush(out);

	//Write CCIX PER log itself to stream.
	if (perlog_exists) {
		json_object *encoded = obj;
		int32_t decoded_len = 0;

		UINT8 *decoded = base64_decode(
			json_object_get_string(encoded),
			json_object_get_string_len(encoded), &decoded_len);
		if (decoded == NULL) {
			cper_print_log(
				"Failed to allocate decode output buffer. \n");
		} else {
			fwrite(decoded, decoded_len, 1, out);
			fflush(out);
			free(decoded);
		}
	}
	//Free resources.
	free(section_cper);
}
