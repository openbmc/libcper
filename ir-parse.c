/**
 * Describes functions for parsing JSON IR CPER data into binary CPER format.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <string.h>
#include <json.h>
#include "libbase64.h"
#include "edk/Cper.h"
#include "cper-parse.h"
#include "cper-utils.h"
#include "sections/cper-section.h"

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
	EFI_COMMON_ERROR_RECORD_HEADER *header =
		(EFI_COMMON_ERROR_RECORD_HEADER *)calloc(
			1, sizeof(EFI_COMMON_ERROR_RECORD_HEADER));
	ir_header_to_cper(json_object_object_get(ir, "header"), header);
	fwrite(header, sizeof(EFI_COMMON_ERROR_RECORD_HEADER), 1, out);
	fflush(out);

	//Create the CPER section descriptors.
	json_object *section_descriptors =
		json_object_object_get(ir, "sectionDescriptors");
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
	free(header);
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
	header->ValidationBits = ir_to_bitfield(
		json_object_object_get(header_ir, "validationBits"), 3,
		CPER_HEADER_VALID_BITFIELD_NAMES);

	//Record length.
	header->RecordLength = (UINT32)json_object_get_uint64(
		json_object_object_get(header_ir, "recordLength"));

	//Timestamp, if present.
	json_object *timestamp = json_object_object_get(header_ir, "timestamp");
	if (timestamp != NULL) {
		string_to_timestamp(&header->TimeStamp,
				    json_object_get_string(timestamp));
		header->TimeStamp.Flag = json_object_get_boolean(
			json_object_object_get(header_ir,
					       "timestampIsPrecise"));
	}

	//Various GUIDs.
	json_object *platform_id =
		json_object_object_get(header_ir, "platformID");
	json_object *partition_id =
		json_object_object_get(header_ir, "partitionID");
	if (platform_id != NULL) {
		string_to_guid(&header->PlatformID,
			       json_object_get_string(platform_id));
	}
	if (partition_id != NULL) {
		string_to_guid(&header->PartitionID,
			       json_object_get_string(partition_id));
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
}

//Converts a single given IR section into CPER, outputting to the given stream.
void ir_section_to_cper(json_object *section,
			EFI_ERROR_SECTION_DESCRIPTOR *descriptor, FILE *out)
{
	//Find the correct section type, and parse.
	int section_converted = 0;
	for (size_t i = 0; i < section_definitions_len; i++) {
		if (guid_equal(section_definitions[i].Guid,
			       &descriptor->SectionType) &&
		    section_definitions[i].ToCPER != NULL) {
			section_definitions[i].ToCPER(section, out);
			section_converted = 1;
			break;
		}
	}

	//If unknown GUID, so read as a base64 unknown section.
	if (!section_converted) {
		json_object *encoded = json_object_object_get(section, "data");
		char *decoded = malloc(json_object_get_string_len(encoded));
		size_t decoded_len = 0;
		if (!decoded) {
			printf("Failed to allocate decode output buffer. \n");
		} else {
			base64_decode(json_object_get_string(encoded),
				      json_object_get_string_len(encoded),
				      decoded, &decoded_len, 0);
			fwrite(decoded, decoded_len, 1, out);
			fflush(out);
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
	descriptor->SecValidMask = ir_to_bitfield(
		json_object_object_get(section_descriptor_ir, "validationBits"),
		2, CPER_SECTION_DESCRIPTOR_VALID_BITFIELD_NAMES);
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
	json_object *fru_id =
		json_object_object_get(section_descriptor_ir, "fruID");
	if (fru_id != NULL) {
		string_to_guid(&descriptor->FruId,
			       json_object_get_string(fru_id));
	}

	//Severity code.
	json_object *severity =
		json_object_object_get(section_descriptor_ir, "severity");
	descriptor->Severity = (UINT32)json_object_get_uint64(
		json_object_object_get(severity, "code"));

	//FRU text, if present.
	json_object *fru_text =
		json_object_object_get(section_descriptor_ir, "fruText");
	if (fru_text != NULL) {
		strncpy(descriptor->FruString, json_object_get_string(fru_text),
			20);
	}
}

//Converts IR for a given single section format CPER record into CPER binary.
void ir_single_section_to_cper(json_object *ir, FILE *out)
{
	//Create & write a section descriptor to file.
	EFI_ERROR_SECTION_DESCRIPTOR *section_descriptor =
		(EFI_ERROR_SECTION_DESCRIPTOR *)calloc(
			1, sizeof(EFI_ERROR_SECTION_DESCRIPTOR));
	ir_section_descriptor_to_cper(
		json_object_object_get(ir, "sectionDescriptor"),
		section_descriptor);
	fwrite(section_descriptor, sizeof(EFI_ERROR_SECTION_DESCRIPTOR), 1,
	       out);
	fflush(out);

	//Write section to file.
	ir_section_to_cper(json_object_object_get(ir, "section"),
			   section_descriptor, out);

	//Free remaining resources.
	free(section_descriptor);
}
