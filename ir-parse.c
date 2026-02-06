/**
 * Describes functions for parsing JSON IR CPER data into binary CPER format.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <string.h>
#include <json.h>
#include <libcper/log.h>
#include <libcper/base64.h>
#include <libcper/Cper.h>
#include <libcper/cper-parse.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section.h>

//Private pre-declarations.
void ir_header_to_cper(json_object *header_ir,
		       EFI_COMMON_ERROR_RECORD_HEADER *header);
void ir_section_descriptor_to_cper(json_object *section_descriptor_ir,
				   EFI_ERROR_SECTION_DESCRIPTOR *descriptor);
void ir_section_to_cper(json_object *section,
			EFI_ERROR_SECTION_DESCRIPTOR *descriptor, FILE *out);

//Converts the given JSON IR CPER representation into CPER binary format, piped to the provided file stream.
//This function performs no validation of the IR against the CPER-JSON specification. To ensure a safe call,
//use validate_schema() from json-schema.h before attempting to call this function.
void ir_to_cper(json_object *ir, FILE *out)
{
	//Create the CPER header.
	EFI_COMMON_ERROR_RECORD_HEADER *header __attribute__((cleanup(freep)));
	header = (EFI_COMMON_ERROR_RECORD_HEADER *)calloc(
		1, sizeof(EFI_COMMON_ERROR_RECORD_HEADER));
	ir_header_to_cper(json_object_object_get(ir, "header"), header);
	fwrite(header, sizeof(EFI_COMMON_ERROR_RECORD_HEADER), 1, out);
	fflush(out);

	//Create the CPER section descriptors.
	json_object *section_descriptors =
		json_object_object_get(ir, "sectionDescriptors");
	if (section_descriptors == NULL) {
		cper_print_log("Invalid CPER file: No section descriptors.\n");
		return;
	}
	int amt_descriptors = json_object_array_length(section_descriptors);
	EFI_ERROR_SECTION_DESCRIPTOR *descriptors[amt_descriptors];
	for (int i = 0; i < amt_descriptors; i++) {
		descriptors[i] = (EFI_ERROR_SECTION_DESCRIPTOR *)calloc(
			1, sizeof(EFI_ERROR_SECTION_DESCRIPTOR));
		ir_section_descriptor_to_cper(
			json_object_array_get_idx(section_descriptors, i),
			descriptors[i]);
		fwrite(descriptors[i], sizeof(EFI_ERROR_SECTION_DESCRIPTOR), 1,
		       out);
		fflush(out);
	}

	//Run through each section in turn.
	json_object *sections = json_object_object_get(ir, "sections");
	if (sections == NULL) {
		cper_print_log("Invalid CPER file: No sections.\n");
		return;
	}
	int amt_sections = json_object_array_length(sections);
	if (amt_sections == amt_descriptors) {
		for (int i = 0; i < amt_sections; i++) {
			//Get the section itself from the IR.
			json_object *section =
				json_object_array_get_idx(sections, i);

			//Convert.
			ir_section_to_cper(section, descriptors[i], out);
		}
	}

	//Free all remaining resources.
	for (int i = 0; i < amt_descriptors; i++) {
		free(descriptors[i]);
	}
}

//Converts a CPER-JSON IR header to a CPER header structure.
void ir_header_to_cper(json_object *header_ir,
		       EFI_COMMON_ERROR_RECORD_HEADER *header)
{
	header->SignatureStart = 0x52455043; //CPER

	//Revision.
	json_object *revision = json_object_object_get(header_ir, "revision");
	int minor =
		json_object_get_int(json_object_object_get(revision, "minor"));
	int major =
		json_object_get_int(json_object_object_get(revision, "major"));
	header->Revision = minor + (major << 8);

	header->SignatureEnd = 0xFFFFFFFF;

	//Section count.
	int section_count = json_object_get_int(
		json_object_object_get(header_ir, "sectionCount"));
	header->SectionCount = (UINT16)section_count;

	//Error severity.
	json_object *severity = json_object_object_get(header_ir, "severity");
	header->ErrorSeverity = (UINT32)json_object_get_uint64(
		json_object_object_get(severity, "code"));

	//Validation bits.
	ValidationTypes ui32Type = { UINT_32T, .value.ui32 = 0 };
	struct json_object *obj = NULL;

	//Record length.
	header->RecordLength = (UINT32)json_object_get_uint64(
		json_object_object_get(header_ir, "recordLength"));

	//Timestamp, if present.
	if (json_object_object_get_ex(header_ir, "timestamp", &obj)) {
		json_object *timestamp = obj;
		if (timestamp != NULL) {
			string_to_timestamp(&header->TimeStamp,
					    json_object_get_string(timestamp));
			header->TimeStamp.Flag = json_object_get_boolean(
				json_object_object_get(header_ir,
						       "timestampIsPrecise"));
		}
		add_to_valid_bitfield(&ui32Type, 1);
	}

	//Various GUIDs.
	json_object *platform_id;
	json_object_object_get_ex(header_ir, "platformID", &platform_id);
	json_object *partition_id;
	json_object_object_get_ex(header_ir, "partitionID", &partition_id);
	if (platform_id != NULL) {
		string_to_guid(&header->PlatformID,
			       json_object_get_string(platform_id));
		add_to_valid_bitfield(&ui32Type, 0);
	}
	if (partition_id != NULL) {
		string_to_guid(&header->PartitionID,
			       json_object_get_string(partition_id));
		add_to_valid_bitfield(&ui32Type, 2);
	}
	string_to_guid(&header->CreatorID,
		       json_object_get_string(
			       json_object_object_get(header_ir, "creatorID")));

	//Notification type.
	json_object *notification_type =
		json_object_object_get(header_ir, "notificationType");
	string_to_guid(&header->NotificationType,
		       json_object_get_string(json_object_object_get(
			       notification_type, "guid")));

	//Record ID, persistence info.
	header->RecordID = json_object_get_uint64(
		json_object_object_get(header_ir, "recordID"));
	header->PersistenceInfo = json_object_get_uint64(
		json_object_object_get(header_ir, "persistenceInfo"));

	//Flags.
	json_object *flags = json_object_object_get(header_ir, "flags");
	header->Flags = (UINT32)json_object_get_uint64(
		json_object_object_get(flags, "value"));

	header->ValidationBits = ui32Type.value.ui32;
}

//Converts a single given IR section into CPER, outputting to the given stream.
void ir_section_to_cper(json_object *section,
			EFI_ERROR_SECTION_DESCRIPTOR *descriptor, FILE *out)
{
	json_object *ir = NULL;

	//Find the correct section type, and parse.
	CPER_SECTION_DEFINITION *definition =
		select_section_by_guid(&descriptor->SectionType);
	if (definition == NULL) {
		cper_print_log("Unknown section type guid\n");
	} else {
		ir = json_object_object_get(section, definition->ShortName);
		definition->ToCPER(ir, out);
	}

	//If unknown GUID, so read as a base64 unknown section.
	if (ir == NULL) {
		ir = json_object_object_get(section, "Unknown");
		json_object *encoded = json_object_object_get(ir, "data");

		int32_t decoded_len = 0;

		UINT8 *decoded = base64_decode(
			json_object_get_string(encoded),
			json_object_get_string_len(encoded), &decoded_len);
		if (decoded == NULL) {
			cper_print_log(
				"Failed to allocate decode output buffer. \n");
		} else {
			fwrite(decoded, decoded_len, 1, out);
			free(decoded);
		}
	}
}

//Converts a single CPER-JSON IR section descriptor into a CPER structure.
void ir_section_descriptor_to_cper(json_object *section_descriptor_ir,
				   EFI_ERROR_SECTION_DESCRIPTOR *descriptor)
{
	//Section offset, length.
	descriptor->SectionOffset = (UINT32)json_object_get_uint64(
		json_object_object_get(section_descriptor_ir, "sectionOffset"));
	descriptor->SectionLength = (UINT32)json_object_get_uint64(
		json_object_object_get(section_descriptor_ir, "sectionLength"));

	//Revision.
	json_object *revision =
		json_object_object_get(section_descriptor_ir, "revision");
	int minor =
		json_object_get_int(json_object_object_get(revision, "minor"));
	int major =
		json_object_get_int(json_object_object_get(revision, "major"));
	descriptor->Revision = minor + (major << 8);

	//Validation bits, flags.
	ValidationTypes ui8Type = { UINT_8T, .value.ui8 = 0 };
	struct json_object *obj = NULL;

	descriptor->SectionFlags = ir_to_bitfield(
		json_object_object_get(section_descriptor_ir, "flags"), 8,
		CPER_SECTION_DESCRIPTOR_FLAGS_BITFIELD_NAMES);

	//Section type.
	json_object *section_type =
		json_object_object_get(section_descriptor_ir, "sectionType");
	string_to_guid(&descriptor->SectionType,
		       json_object_get_string(
			       json_object_object_get(section_type, "data")));

	//FRU ID, if present.
	if (json_object_object_get_ex(section_descriptor_ir, "fruID", &obj)) {
		json_object *fru_id = obj;
		if (fru_id != NULL) {
			string_to_guid(&descriptor->FruId,
				       json_object_get_string(fru_id));
			add_to_valid_bitfield(&ui8Type, 0);
		}
	}

	//Severity code.
	json_object *severity =
		json_object_object_get(section_descriptor_ir, "severity");
	descriptor->Severity = (UINT32)json_object_get_uint64(
		json_object_object_get(severity, "code"));

	//FRU text, if present.
	if (json_object_object_get_ex(section_descriptor_ir, "fruText", &obj)) {
		json_object *fru_text = obj;
		if (fru_text != NULL) {
			strncpy(descriptor->FruString,
				json_object_get_string(fru_text),
				sizeof(descriptor->FruString) - 1);
			descriptor
				->FruString[sizeof(descriptor->FruString) - 1] =
				'\0';
			add_to_valid_bitfield(&ui8Type, 1);
		}
	}
	descriptor->SecValidMask = ui8Type.value.ui8;
}

//Converts IR for a given single section format CPER record into CPER binary.
void ir_single_section_to_cper(json_object *ir, FILE *out)
{
	//Create & write a section descriptor to file.
	EFI_ERROR_SECTION_DESCRIPTOR section_descriptor;
	memset(&section_descriptor, 0, sizeof(section_descriptor));

	ir_section_descriptor_to_cper(
		json_object_object_get(ir, "sectionDescriptor"),
		&section_descriptor);
	fwrite(&section_descriptor, sizeof(section_descriptor), 1, out);

	//Write section to file.
	ir_section_to_cper(json_object_object_get(ir, "section"),
			   &section_descriptor, out);

	fflush(out);
}
