/**
 * Describes functions for converting processor-generic CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 *         drewwalton@microsoft.com
 **/

#include <stdio.h>
#include <string.h>
#include <json.h>
#include <libcper/Cpad.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cpad-section-os-generic.h>
#include <libcper/log.h>

//Converts the given OS-generic CPad section into JSON IR.
// This is a prototype implementation; the OS Generic CPAD section is not defined
// in the CPAD specification at this time.
json_object *cpad_section_os_generic_to_ir(const UINT8 *section, UINT32 size)
{
	if (size < sizeof(OS_GENERIC_CPAD_DATA)) {
		return NULL;
	}

	OS_GENERIC_CPAD_DATA *section_generic =
		(OS_GENERIC_CPAD_DATA *)section;
	json_object *section_ir = json_object_new_object();

	json_object_object_add(section_ir, "operation", 
		json_object_new_uint64(section_generic->Operation));
	json_object_object_add(section_ir, "targetAddress", 
		json_object_new_uint64(section_generic->TargetAddr));
	json_object_object_add(section_ir, "parameter1", 
		json_object_new_uint64(section_generic->Parameter1));
	json_object_object_add(section_ir, "parameter2", 
		json_object_new_uint64(section_generic->Parameter2));
	json_object_object_add(section_ir, "parameter3", 
		json_object_new_uint64(section_generic->Parameter3));
	return section_ir;
}

//Converts the given CPAD-JSON OS-generic error section into CPAD binary,
//outputting to the provided stream.
// This is a prototype implementation; the OS Generic CPAD section is not defined
// in the CPAD specification at this time.
void ir_section_os_generic_to_cpad(json_object *section_ir, FILE *out)
{
	OS_GENERIC_CPAD_DATA *section_cpad =
		(OS_GENERIC_CPAD_DATA *)calloc(
			1, sizeof(OS_GENERIC_CPAD_DATA));

	//Various name/value pair fields.
	
	section_cpad->Operation = (UINT64)json_object_get_uint64(
		json_object_object_get(section_ir, "operation"));
	section_cpad->TargetAddr = (UINT64)json_object_get_uint64(
		json_object_object_get(section_ir, "targetAddress"));
	section_cpad->Parameter1 = (UINT64)json_object_get_uint64(
		json_object_object_get(section_ir, "parameter1"));
	section_cpad->Parameter2 = (UINT64)json_object_get_uint64(
		json_object_object_get(section_ir, "parameter2"));
	section_cpad->Parameter3 = (UINT64)json_object_get_uint64(
		json_object_object_get(section_ir, "parameter3"));


	//Write & flush out to file, free memory.
	fwrite(section_cpad, sizeof(OS_GENERIC_CPAD_DATA), 1, out);
	fflush(out);
	free(section_cpad);
}
