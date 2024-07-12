/**
 * Describes functions for converting CCIX PER log CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <string.h>
#include <json.h>
#include "libbase64.h"
#include "../edk/Cper.h"
#include "../cper-utils.h"
#include "cper-section-ccix-per.h"

//Converts a single CCIX PER log CPER section into JSON IR.
json_object *cper_section_ccix_per_to_ir(void *section)
{
	EFI_CCIX_PER_LOG_DATA *ccix_error = (EFI_CCIX_PER_LOG_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Length (bytes) for the entire structure.
	json_object_object_add(section_ir, "length",
			       json_object_new_uint64(ccix_error->Length));

	//Validation bits.
	json_object *validation = bitfield_to_ir(
		ccix_error->ValidBits, 3, CCIX_PER_ERROR_VALID_BITFIELD_NAMES);
	json_object_object_add(section_ir, "validationBits", validation);

	//CCIX source/port IDs.
	json_object_object_add(section_ir, "ccixSourceID",
			       json_object_new_int(ccix_error->CcixSourceId));
	json_object_object_add(section_ir, "ccixPortID",
			       json_object_new_int(ccix_error->CcixPortId));

	//CCIX PER Log.
	//This is formatted as described in Section 7.3.2 of CCIX Base Specification (Rev 1.0).
	const char *cur_pos = (const char *)(ccix_error + 1);
	int remaining_length =
		ccix_error->Length - sizeof(EFI_CCIX_PER_LOG_DATA);
	if (remaining_length > 0) {
		char *encoded = malloc(2 * remaining_length);
		size_t encoded_len = 0;
		if (!encoded) {
			printf("Failed to allocate encode output buffer. \n");
		} else {
			base64_encode((const char *)cur_pos, remaining_length,
				      encoded, &encoded_len, 0);
			json_object_object_add(section_ir, "ccixPERLog",
					       json_object_new_string_len(
						       encoded, encoded_len));
			free(encoded);
		}
	}

	return section_ir;
}

//Converts a single CCIX PER CPER-JSON section into CPER binary, outputting to the given stream.
void ir_section_ccix_per_to_cper(json_object *section, FILE *out)
{
	EFI_CCIX_PER_LOG_DATA *section_cper = (EFI_CCIX_PER_LOG_DATA *)calloc(
		1, sizeof(EFI_CCIX_PER_LOG_DATA));

	//Length.
	section_cper->Length = json_object_get_uint64(
		json_object_object_get(section, "length"));

	//Validation bits.
	section_cper->ValidBits = ir_to_bitfield(
		json_object_object_get(section, "validationBits"), 3,
		CCIX_PER_ERROR_VALID_BITFIELD_NAMES);

	//CCIX source/port IDs.
	section_cper->CcixSourceId = (UINT8)json_object_get_int(
		json_object_object_get(section, "ccixSourceID"));
	section_cper->CcixPortId = (UINT8)json_object_get_int(
		json_object_object_get(section, "ccixPortID"));

	//Write header out to stream.
	fwrite(section_cper, sizeof(EFI_CCIX_PER_LOG_DATA), 1, out);
	fflush(out);

	//Write CCIX PER log itself to stream.
	json_object *encoded = json_object_object_get(section, "ccixPERLog");
	char *decoded = malloc(json_object_get_string_len(encoded));
	size_t decoded_len = 0;
	if (!decoded) {
		printf("Failed to allocate decode output buffer. \n");
	} else {
		base64_decode(json_object_get_string(encoded),
			      json_object_get_string_len(encoded), decoded,
			      &decoded_len, 0);
		fwrite(decoded, decoded_len, 1, out);
		fflush(out);
	}

	//Free resources.
	free(decoded);
	free(section_cper);
}
