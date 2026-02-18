/**
 * Describes functions for converting Info-action-ppr sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Custom Section Generator
 **/
#include <stdio.h>
#include <string.h>
#include <json.h>
#include <libcper/Cper.h>
#include <libcper/sections/cper-section-platform-action-event.h>
#include <libcper/cper-utils.h>
#include <libcper/base64.h>

//Converts the given Info-action-ppr CPER section into JSON IR.
json_object *cper_section_platform_action_event_to_ir(const UINT8 *section, UINT32 size)
{
	json_object *section_ir = json_object_new_object();
	
	//For now, just encode the raw data as base64 since the section structure
	//is not yet defined. You can add specific field parsing here later.
	INT32 encoded_len = 0;
	char *encoded = base64_encode(section, size, &encoded_len);
	json_object_object_add(section_ir, "data",
			       json_object_new_string(encoded));
	free(encoded);
	
	return section_ir;
}

//Converts a single Info-action-ppr JSON IR section into CPER binary, outputting to the given stream.
void ir_section_platform_action_event_to_cper(json_object *section, FILE *out)
{
	//For now, decode from base64. You can add specific field handling here later.
	json_object *encoded = json_object_object_get(section, "data");
	if (encoded != NULL) {
		INT32 decoded_len = 0;
		UINT8 *decoded = base64_decode(json_object_get_string(encoded),
					    strlen(json_object_get_string(encoded)),
					    &decoded_len);
		fwrite(decoded, decoded_len, 1, out);
		fflush(out);
		free(decoded);
	}
}
