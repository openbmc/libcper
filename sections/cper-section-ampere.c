#include <stdio.h>
#include <json.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-ampere.h>
#include <libcper/log.h>
#include <string.h>

//Converts the given processor-generic CPER section into JSON IR.
json_object *cper_section_ampere_to_ir(const UINT8 *section, UINT32 size,
				       char **desc_string)
{
	*desc_string = malloc(SECTION_DESC_STRING_SIZE);
	snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
		 "An Ampere Error occurred");

	if (size < sizeof(EFI_AMPERE_ERROR_DATA)) {
		return NULL;
	}

	EFI_AMPERE_ERROR_DATA *record = (EFI_AMPERE_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	json_object_object_add(section_ir, "typeId",
			       json_object_new_int(record->TypeId));
	json_object_object_add(section_ir, "subTypeId",
			       json_object_new_int(record->SubtypeId));
	json_object_object_add(section_ir, "instanceId",
			       json_object_new_int(record->InstanceId));

	return section_ir;
}

//Converts a single CPER-JSON ARM error section into CPER binary, outputting to the given stream.
void ir_section_ampere_to_cper(json_object *section, FILE *out)
{
	EFI_AMPERE_ERROR_DATA *section_cper = (EFI_AMPERE_ERROR_DATA *)calloc(
		1, sizeof(EFI_AMPERE_ERROR_DATA));

	//Count of error/context info structures.
	section_cper->TypeId =
		json_object_get_int(json_object_object_get(section, "typeId"));
	section_cper->SubtypeId = json_object_get_int(
		json_object_object_get(section, "subTypeId"));
	section_cper->InstanceId = json_object_get_int(
		json_object_object_get(section, "instanceId"));

	//Flush header to stream.
	fwrite(section_cper, sizeof(EFI_AMPERE_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}
