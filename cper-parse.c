/**
 * Describes high level functions for converting an entire CPER log, and functions for parsing
 * CPER headers and section descriptions into an intermediate JSON format.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <json.h>
#include "base64.h"
#include "edk/Cper.h"
#include "cper-parse.h"
#include "cper-utils.h"
#include "sections/cper-section.h"

//Private pre-definitions.
json_object *cper_header_to_ir(EFI_COMMON_ERROR_RECORD_HEADER *header);
json_object *
cper_section_descriptor_to_ir(EFI_ERROR_SECTION_DESCRIPTOR *section_descriptor);
json_object *cper_section_to_ir(FILE *handle, long base_pos,
				EFI_ERROR_SECTION_DESCRIPTOR *descriptor);

//Reads a CPER log file at the given file location, and returns an intermediate
//JSON representation of this CPER record.
json_object *cper_to_ir(FILE *cper_file)
{
	//Read the current file pointer location as the base of the record.
	long base_pos = ftell(cper_file);

	//Ensure this is really a CPER log.
	EFI_COMMON_ERROR_RECORD_HEADER header;
	if (fread(&header, sizeof(EFI_COMMON_ERROR_RECORD_HEADER), 1,
		  cper_file) != 1) {
		printf("Invalid CPER file: Invalid length (log too short).\n");
		return NULL;
	}

	//Check if the header contains the magic bytes ("CPER").
	if (header.SignatureStart != EFI_ERROR_RECORD_SIGNATURE_START) {
		printf("Invalid CPER file: Invalid header (incorrect signature).\n");
		return NULL;
	}

	//Create the header JSON object from the read bytes.
	json_object *header_ir = cper_header_to_ir(&header);

	//Read the appropriate number of section descriptors & sections, and convert them into IR format.
	json_object *section_descriptors_ir = json_object_new_array();
	json_object *sections_ir = json_object_new_array();
	for (int i = 0; i < header.SectionCount; i++) {
		//Create the section descriptor.
		EFI_ERROR_SECTION_DESCRIPTOR section_descriptor;
		if (fread(&section_descriptor,
			  sizeof(EFI_ERROR_SECTION_DESCRIPTOR), 1,
			  cper_file) != 1) {
			printf("Invalid number of section headers: Header states %d sections, could not read section %d.\n",
			       header.SectionCount, i + 1);
			// Free json objects
			json_object_put(sections_ir);
			json_object_put(section_descriptors_ir);
			json_object_put(header_ir);
			return NULL;
		}
		json_object_array_add(
			section_descriptors_ir,
			cper_section_descriptor_to_ir(&section_descriptor));

		//Read the section itself.
		json_object_array_add(sections_ir,
				      cper_section_to_ir(cper_file, base_pos,
							 &section_descriptor));
	}

	//Add the header, section descriptors, and sections to a parent object.
	json_object *parent = json_object_new_object();
	json_object_object_add(parent, "header", header_ir);
	json_object_object_add(parent, "sectionDescriptors",
			       section_descriptors_ir);
	json_object_object_add(parent, "sections", sections_ir);

	return parent;
}

//Converts a parsed CPER record header into intermediate JSON object format.
json_object *cper_header_to_ir(EFI_COMMON_ERROR_RECORD_HEADER *header)
{
	json_object *header_ir = json_object_new_object();

	//Revision/version information.
	json_object_object_add(header_ir, "revision",
			       revision_to_ir(header->Revision));

	//Section count.
	json_object_object_add(header_ir, "sectionCount",
			       json_object_new_int(header->SectionCount));

	//Error severity (with interpreted string version).
	json_object *error_severity = json_object_new_object();
	json_object_object_add(error_severity, "code",
			       json_object_new_uint64(header->ErrorSeverity));
	json_object_object_add(error_severity, "name",
			       json_object_new_string(severity_to_string(
				       header->ErrorSeverity)));
	json_object_object_add(header_ir, "severity", error_severity);

	//The validation bits for each section.
	json_object *validation_bits = bitfield_to_ir(
		header->ValidationBits, 3, CPER_HEADER_VALID_BITFIELD_NAMES);
	json_object_object_add(header_ir, "validationBits", validation_bits);

	//Total length of the record (including headers) in bytes.
	json_object_object_add(header_ir, "recordLength",
			       json_object_new_uint64(header->RecordLength));

	//If a timestamp exists according to validation bits, then add it.
	if (header->ValidationBits & 0x2) {
		char timestamp_string[TIMESTAMP_LENGTH];
		timestamp_to_string(timestamp_string, &header->TimeStamp);

		json_object_object_add(
			header_ir, "timestamp",
			json_object_new_string(timestamp_string));
		json_object_object_add(
			header_ir, "timestampIsPrecise",
			json_object_new_boolean(header->TimeStamp.Flag));
	}

	//If a platform ID exists according to the validation bits, then add it.
	if (header->ValidationBits & 0x1) {
		char platform_string[GUID_STRING_LENGTH];
		guid_to_string(platform_string, &header->PlatformID);
		json_object_object_add(header_ir, "platformID",
				       json_object_new_string(platform_string));
	}

	//If a partition ID exists according to the validation bits, then add it.
	if (header->ValidationBits & 0x4) {
		char partition_string[GUID_STRING_LENGTH];
		guid_to_string(partition_string, &header->PartitionID);
		json_object_object_add(
			header_ir, "partitionID",
			json_object_new_string(partition_string));
	}

	//Creator ID of the header.
	char creator_string[GUID_STRING_LENGTH];
	guid_to_string(creator_string, &header->CreatorID);
	json_object_object_add(header_ir, "creatorID",
			       json_object_new_string(creator_string));

	//Notification type for the header. Some defined types are available.
	json_object *notification_type = json_object_new_object();
	char notification_type_string[GUID_STRING_LENGTH];
	guid_to_string(notification_type_string, &header->NotificationType);
	json_object_object_add(
		notification_type, "guid",
		json_object_new_string(notification_type_string));

	//Add the human readable notification type if possible.
	char *notification_type_readable = "Unknown";
	if (guid_equal(&header->NotificationType,
		       &gEfiEventNotificationTypeCmcGuid)) {
		notification_type_readable = "CMC";
	} else if (guid_equal(&header->NotificationType,
			      &gEfiEventNotificationTypeCpeGuid)) {
		notification_type_readable = "CPE";
	} else if (guid_equal(&header->NotificationType,
			      &gEfiEventNotificationTypeMceGuid)) {
		notification_type_readable = "MCE";
	} else if (guid_equal(&header->NotificationType,
			      &gEfiEventNotificationTypePcieGuid)) {
		notification_type_readable = "PCIe";
	} else if (guid_equal(&header->NotificationType,
			      &gEfiEventNotificationTypeInitGuid)) {
		notification_type_readable = "INIT";
	} else if (guid_equal(&header->NotificationType,
			      &gEfiEventNotificationTypeNmiGuid)) {
		notification_type_readable = "NMI";
	} else if (guid_equal(&header->NotificationType,
			      &gEfiEventNotificationTypeBootGuid)) {
		notification_type_readable = "Boot";
	} else if (guid_equal(&header->NotificationType,
			      &gEfiEventNotificationTypeDmarGuid)) {
		notification_type_readable = "DMAr";
	} else if (guid_equal(&header->NotificationType,
			      &gEfiEventNotificationTypeSeaGuid)) {
		notification_type_readable = "SEA";
	} else if (guid_equal(&header->NotificationType,
			      &gEfiEventNotificationTypeSeiGuid)) {
		notification_type_readable = "SEI";
	} else if (guid_equal(&header->NotificationType,
			      &gEfiEventNotificationTypePeiGuid)) {
		notification_type_readable = "PEI";
	} else if (guid_equal(&header->NotificationType,
			      &gEfiEventNotificationTypeCxlGuid)) {
		notification_type_readable = "CXL Component";
	}
	json_object_object_add(
		notification_type, "type",
		json_object_new_string(notification_type_readable));
	json_object_object_add(header_ir, "notificationType",
			       notification_type);

	//The record ID for this record, unique on a given system.
	json_object_object_add(header_ir, "recordID",
			       json_object_new_uint64(header->RecordID));

	//Flag for the record, and a human readable form.
	json_object *flags = integer_to_readable_pair(
		header->Flags,
		sizeof(CPER_HEADER_FLAG_TYPES_KEYS) / sizeof(int),
		CPER_HEADER_FLAG_TYPES_KEYS, CPER_HEADER_FLAG_TYPES_VALUES,
		"Unknown");
	json_object_object_add(header_ir, "flags", flags);

	//Persistence information. Outside the scope of specification, so just a uint32 here.
	json_object_object_add(header_ir, "persistenceInfo",
			       json_object_new_uint64(header->PersistenceInfo));
	return header_ir;
}

//Converts the given EFI section descriptor into JSON IR format.
json_object *
cper_section_descriptor_to_ir(EFI_ERROR_SECTION_DESCRIPTOR *section_descriptor)
{
	json_object *section_descriptor_ir = json_object_new_object();

	//The offset of the section from the base of the record header, length.
	json_object_object_add(
		section_descriptor_ir, "sectionOffset",
		json_object_new_uint64(section_descriptor->SectionOffset));
	json_object_object_add(
		section_descriptor_ir, "sectionLength",
		json_object_new_uint64(section_descriptor->SectionLength));

	//Revision.
	json_object_object_add(section_descriptor_ir, "revision",
			       revision_to_ir(section_descriptor->Revision));

	//Validation bits.
	json_object *validation_bits =
		bitfield_to_ir(section_descriptor->SecValidMask, 2,
			       CPER_SECTION_DESCRIPTOR_VALID_BITFIELD_NAMES);
	json_object_object_add(section_descriptor_ir, "validationBits",
			       validation_bits);

	//Flag bits.
	json_object *flags =
		bitfield_to_ir(section_descriptor->SectionFlags, 8,
			       CPER_SECTION_DESCRIPTOR_FLAGS_BITFIELD_NAMES);
	json_object_object_add(section_descriptor_ir, "flags", flags);

	//Section type (GUID).
	json_object *section_type = json_object_new_object();
	char section_type_string[GUID_STRING_LENGTH];
	guid_to_string(section_type_string, &section_descriptor->SectionType);
	json_object_object_add(section_type, "data",
			       json_object_new_string(section_type_string));

	//Readable section type, if possible.
	const char *section_type_readable = "Unknown";
	for (size_t i = 0; i < section_definitions_len; i++) {
		if (guid_equal(section_definitions[i].Guid,
			       &section_descriptor->SectionType)) {
			section_type_readable =
				section_definitions[i].ReadableName;
			break;
		}
	}

	json_object_object_add(section_type, "type",
			       json_object_new_string(section_type_readable));
	json_object_object_add(section_descriptor_ir, "sectionType",
			       section_type);

	//If validation bits indicate it exists, add FRU ID.
	if (section_descriptor->SecValidMask & 0x1) {
		char fru_id_string[GUID_STRING_LENGTH];
		guid_to_string(fru_id_string, &section_descriptor->FruId);
		json_object_object_add(section_descriptor_ir, "fruID",
				       json_object_new_string(fru_id_string));
	}

	//If validation bits indicate it exists, add FRU text.
	if ((section_descriptor->SecValidMask & 0x2) >> 1) {
		json_object_object_add(
			section_descriptor_ir, "fruText",
			json_object_new_string(section_descriptor->FruString));
	}

	//Section severity.
	json_object *section_severity = json_object_new_object();
	json_object_object_add(
		section_severity, "code",
		json_object_new_uint64(section_descriptor->Severity));
	json_object_object_add(section_severity, "name",
			       json_object_new_string(severity_to_string(
				       section_descriptor->Severity)));
	json_object_object_add(section_descriptor_ir, "severity",
			       section_severity);

	return section_descriptor_ir;
}

//Converts the section described by a single given section descriptor.
json_object *cper_section_to_ir(FILE *handle, long base_pos,
				EFI_ERROR_SECTION_DESCRIPTOR *descriptor)
{
	//Save our current position in the stream.
	long position = ftell(handle);

	//Read section as described by the section descriptor.
	fseek(handle, base_pos + descriptor->SectionOffset, SEEK_SET);
	void *section = malloc(descriptor->SectionLength);
	if (fread(section, descriptor->SectionLength, 1, handle) != 1) {
		printf("Section read failed: Could not read %u bytes from global offset %d.\n",
		       descriptor->SectionLength, descriptor->SectionOffset);
		free(section);
		return NULL;
	}

	//Seek back to our original position.
	fseek(handle, position, SEEK_SET);

	//Parse section to IR based on GUID.
	json_object *result = NULL;
	int section_converted = 0;
	for (size_t i = 0; i < section_definitions_len; i++) {
		if (guid_equal(section_definitions[i].Guid,
			       &descriptor->SectionType) &&
		    section_definitions[i].ToIR != NULL) {
			result = section_definitions[i].ToIR(section);
			section_converted = 1;
			break;
		}
	}

	//Was it an unknown GUID/failed read?
	if (!section_converted) {
		//Output the data as formatted base64.
		result = json_object_new_object();

		int32_t encoded_len = 0;
		char *encoded = base64_encode(
			section, descriptor->SectionLength, &encoded_len);
		if (encoded == NULL) {
			printf("Failed to allocate encode output buffer. \n");
		} else {
			json_object_object_add(result, "data",
					       json_object_new_string_len(
						       encoded, encoded_len));
			free(encoded);
		}
	}
	//Free section memory, return result.
	free(section);
	return result;
}

//Converts a single CPER section, without a header but with a section descriptor, to JSON.
json_object *cper_single_section_to_ir(FILE *cper_section_file)
{
	json_object *ir = json_object_new_object();

	//Read the current file pointer location as base record position.
	long base_pos = ftell(cper_section_file);

	//Read the section descriptor out.
	EFI_ERROR_SECTION_DESCRIPTOR section_descriptor;
	if (fread(&section_descriptor, sizeof(EFI_ERROR_SECTION_DESCRIPTOR), 1,
		  cper_section_file) != 1) {
		printf("Failed to read section descriptor for CPER single section (fread() returned an unexpected value).\n");
		return NULL;
	}

	//Convert the section descriptor to IR.
	json_object *section_descriptor_ir =
		cper_section_descriptor_to_ir(&section_descriptor);
	json_object_object_add(ir, "sectionDescriptor", section_descriptor_ir);

	//Parse the single section.
	json_object *section_ir = cper_section_to_ir(
		cper_section_file, base_pos, &section_descriptor);
	json_object_object_add(ir, "section", section_ir);

	return ir;
}
