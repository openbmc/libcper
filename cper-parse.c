/**
 * Describes high level functions for converting an entire CPER log, and functions for parsing
 * CPER headers and section descriptions into an intermediate JSON format.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <json.h>

#include <libcper/base64.h>
#include <libcper/Cper.h>
#include <libcper/cper-parse.h>
#include <libcper/cper-parse-str.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section.h>

//Private pre-definitions.
json_object *cper_header_to_ir(EFI_COMMON_ERROR_RECORD_HEADER *header);
json_object *
cper_section_descriptor_to_ir(EFI_ERROR_SECTION_DESCRIPTOR *section_descriptor);

json_object *cper_buf_section_to_ir(const void *cper_section_buf, size_t size,
				    EFI_ERROR_SECTION_DESCRIPTOR *descriptor);

json_object *cper_buf_to_ir(const unsigned char *cper_buf, size_t size)
{
	json_object *parent = NULL;
	json_object *header_ir = NULL;
	json_object *section_descriptors_ir = NULL;
	json_object *sections_ir = NULL;

	const unsigned char *pos = cper_buf;
	unsigned int remaining = size;

	if (remaining < sizeof(EFI_COMMON_ERROR_RECORD_HEADER)) {
		printf("Invalid CPER file: Invalid header (incorrect signature).\n");
		goto fail;
	}

	EFI_COMMON_ERROR_RECORD_HEADER *header = NULL;
	header = (EFI_COMMON_ERROR_RECORD_HEADER *)cper_buf;
	pos += sizeof(EFI_COMMON_ERROR_RECORD_HEADER);
	remaining -= sizeof(EFI_COMMON_ERROR_RECORD_HEADER);
	if (header->SignatureStart != EFI_ERROR_RECORD_SIGNATURE_START) {
		printf("Invalid CPER file: Invalid header (incorrect signature).\n");
		goto fail;
	}
	if (header->SectionCount == 0) {
		printf("Invalid CPER file: Invalid section count (0).\n");
		goto fail;
	}
	if (remaining < sizeof(EFI_ERROR_SECTION_DESCRIPTOR)) {
		printf("Invalid CPER file: Invalid section descriptor (section offset + length > size).\n");
		goto fail;
	}

	//Create the header JSON object from the read bytes.
	parent = json_object_new_object();
	header_ir = cper_header_to_ir(header);

	json_object_object_add(parent, "header", header_ir);

	//Read the appropriate number of section descriptors & sections, and convert them into IR format.
	section_descriptors_ir = json_object_new_array();
	sections_ir = json_object_new_array();
	for (int i = 0; i < header->SectionCount; i++) {
		//Create the section descriptor.
		if (remaining < sizeof(EFI_ERROR_SECTION_DESCRIPTOR)) {
			printf("Invalid number of section headers: Header states %d sections, could not read section %d.\n",
			       header->SectionCount, i + 1);
			goto fail;
		}

		EFI_ERROR_SECTION_DESCRIPTOR *section_descriptor;
		section_descriptor = (EFI_ERROR_SECTION_DESCRIPTOR *)(pos);
		pos += sizeof(EFI_ERROR_SECTION_DESCRIPTOR);
		remaining -= sizeof(EFI_ERROR_SECTION_DESCRIPTOR);

		if (section_descriptor->SectionOffset > size) {
			printf("Invalid section descriptor: Section offset > size.\n");
			goto fail;
		}

		if (section_descriptor->SectionLength <= 0) {
			printf("Invalid section descriptor: Section length <= 0.\n");
			goto fail;
		}

		if (section_descriptor->SectionOffset >
		    UINT_MAX - section_descriptor->SectionLength) {
			printf("Invalid section descriptor: Section offset + length would overflow.\n");
			goto fail;
		}

		if (section_descriptor->SectionOffset +
			    section_descriptor->SectionLength >
		    size) {
			printf("Invalid section descriptor: Section offset + length > size.\n");
			goto fail;
		}

		const unsigned char *section_begin =
			cper_buf + section_descriptor->SectionOffset;

		json_object_array_add(
			section_descriptors_ir,
			cper_section_descriptor_to_ir(section_descriptor));

		//Read the section itself.
		json_object *section_ir = cper_buf_section_to_ir(
			section_begin, section_descriptor->SectionLength,
			section_descriptor);
		json_object_array_add(sections_ir, section_ir);
	}

	//Add the header, section descriptors, and sections to a parent object.
	json_object_object_add(parent, "sectionDescriptors",
			       section_descriptors_ir);
	json_object_object_add(parent, "sections", sections_ir);

	return parent;

fail:
	json_object_put(sections_ir);
	json_object_put(section_descriptors_ir);
	json_object_put(parent);
	printf("Failed to parse CPER file.\n");
	return NULL;
}

//Reads a CPER log file at the given file location, and returns an intermediate
//JSON representation of this CPER record.
json_object *cper_to_ir(FILE *cper_file)
{
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
	fseek(cper_file, -sizeof(EFI_COMMON_ERROR_RECORD_HEADER), SEEK_CUR);
	unsigned char *cper_buf = malloc(header.RecordLength);
	if (fread(cper_buf, header.RecordLength, 1, cper_file) != 1) {
		printf("File read failed\n");
		free(cper_buf);
		return NULL;
	}

	json_object *ir = cper_buf_to_ir(cper_buf, header.RecordLength);
	free(cper_buf);
	return ir;
}

char *cper_to_str_ir(FILE *cper_file)
{
	json_object *jobj = cper_to_ir(cper_file);
	char *str = jobj ? strdup(json_object_to_json_string(jobj)) : NULL;

	json_object_put(jobj);
	return str;
}

char *cperbuf_to_str_ir(const unsigned char *cper, size_t size)
{
	FILE *cper_file = fmemopen((void *)cper, size, "r");

	return cper_file ? cper_to_str_ir(cper_file) : NULL;
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

	//Total length of the record (including headers) in bytes.
	json_object_object_add(header_ir, "recordLength",
			       json_object_new_uint64(header->RecordLength));

	//If a timestamp exists according to validation bits, then add it.
	if (header->ValidationBits & 0x2) {
		char timestamp_string[TIMESTAMP_LENGTH];
		int ret = timestamp_to_string(
			timestamp_string, TIMESTAMP_LENGTH, &header->TimeStamp);
		if (ret < 0) {
			printf("Failed to convert timestamp to string\n");
			json_object_put(header_ir);
			return NULL;
		}
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
		int fru_text_len = 0;
		for (;
		     fru_text_len < (int)sizeof(section_descriptor->FruString);
		     fru_text_len++) {
			char c = section_descriptor->FruString[fru_text_len];
			if (c < 0) {
				//printf("Fru text contains non-ASCII character\n");
				fru_text_len = -1;
				break;
			}
			if (c == '\0') {
				break;
			}
		}
		if (fru_text_len >= 0) {
			json_object_object_add(
				section_descriptor_ir, "fruText",
				json_object_new_string_len(
					section_descriptor->FruString,
					fru_text_len));
		}
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

json_object *read_section(const unsigned char *cper_section_buf,
			  CPER_SECTION_DEFINITION *definition,
			  json_object **section_ir)
{
	*section_ir = definition->ToIR(cper_section_buf);

	json_object *result = json_object_new_object();
	json_object_object_add(result, definition->ShortName, *section_ir);
	return result;
}

//Converts the section described by a single given section descriptor.
json_object *cper_buf_section_to_ir(const void *cper_section_buf, size_t size,
				    EFI_ERROR_SECTION_DESCRIPTOR *descriptor)
{
	if (descriptor->SectionLength > size) {
		printf("Invalid CPER file: Invalid header (incorrect signature).\n");
		return NULL;
	}

	//Parse section to IR based on GUID.
	json_object *result = NULL;

	json_object *section_ir = NULL;
	int section_converted = 0;
	for (size_t i = 0; i < section_definitions_len; i++) {
		if (!guid_equal(section_definitions[i].Guid,
				&descriptor->SectionType)) {
			continue;
		}
		result = read_section(cper_section_buf, &section_definitions[i],
				      &section_ir);
		section_converted = 1;
		break;
	}

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	// It's unlikely fuzzing can reliably come up with a correct guid, given how
	// much entropy there is.  If we're in fuzzing mode, and if we haven't found
	// a match, try to force a match so we get some coverage.  Note, we still
	// want coverage of the section failed to convert code, so treat index ==
	// size as section failed to convert.
	if (!section_converted) {
		unsigned char index = 0;
		if (index > 0) {
			index = descriptor->SectionType.Data1 %
				section_definitions_len;
		}
		if (index < section_definitions_len) {
			result = read_section(cper_section_buf,
					      &section_definitions[index],
					      &section_ir);
			section_converted = 1;
		}
	}
#endif

	//Was it an unknown GUID/failed read?
	if (!section_converted) {
		//Output the data as formatted base64.
		int32_t encoded_len = 0;
		char *encoded = base64_encode(cper_section_buf,
					      descriptor->SectionLength,
					      &encoded_len);
		if (encoded == NULL) {
			//printf("Failed to allocate encode output buffer. \n");
		} else {
			section_ir = json_object_new_object();
			json_object_object_add(section_ir, "data",
					       json_object_new_string_len(
						       encoded, encoded_len));
			free(encoded);

			result = json_object_new_object();
			json_object_object_add(result, "Unknown", section_ir);
		}
	}

	return result;
}

json_object *cper_buf_single_section_to_ir(const unsigned char *cper_buf,
					   size_t size)
{
	const unsigned char *cper_end;
	const unsigned char *section_begin;
	json_object *ir;

	cper_end = cper_buf + size;

	//Read the section descriptor out.
	EFI_ERROR_SECTION_DESCRIPTOR *section_descriptor;
	if (sizeof(EFI_ERROR_SECTION_DESCRIPTOR) > size) {
		printf("Size of cper buffer was too small to read section descriptor %zu\n", size);
		return NULL;
	}

	ir = json_object_new_object();
	section_descriptor = (EFI_ERROR_SECTION_DESCRIPTOR *)cper_buf;
	//Convert the section descriptor to IR.
	json_object *section_descriptor_ir =
		cper_section_descriptor_to_ir(section_descriptor);
	json_object_object_add(ir, "sectionDescriptor", section_descriptor_ir);
	section_begin = cper_buf + section_descriptor->SectionOffset;

	if (section_begin + section_descriptor->SectionLength >= cper_end) {
		json_object_put(ir);
		//printf("Invalid CPER file: Invalid section descriptor (section offset + length > size).\n");
		return NULL;
	}

	const unsigned char *section =
		cper_buf + section_descriptor->SectionOffset;

	//Parse the single section.
	json_object *section_ir = cper_buf_section_to_ir(
		section, section_descriptor->SectionLength, section_descriptor);
	json_object_object_add(ir, "section", section_ir);
	return ir;
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
		json_object_put(ir);
		return NULL;
	}

	//Convert the section descriptor to IR.
	json_object *section_descriptor_ir =
		cper_section_descriptor_to_ir(&section_descriptor);
	json_object_object_add(ir, "sectionDescriptor", section_descriptor_ir);

	//Save our current position in the stream.
	long position = ftell(cper_section_file);

	//Read section as described by the section descriptor.
	fseek(cper_section_file, base_pos + section_descriptor.SectionOffset,
	      SEEK_SET);
	void *section = malloc(section_descriptor.SectionLength);
	if (fread(section, section_descriptor.SectionLength, 1,
		  cper_section_file) != 1) {
		printf("Section read failed: Could not read %u bytes from global offset %d.\n",
		       section_descriptor.SectionLength,
		       section_descriptor.SectionOffset);
		json_object_put(ir);
		free(section);
		return NULL;
	}

	//Seek back to our original position.
	fseek(cper_section_file, position, SEEK_SET);

	//Parse the single section.
	json_object *section_ir = cper_buf_section_to_ir(
		section, section_descriptor.SectionLength, &section_descriptor);
	json_object_object_add(ir, "section", section_ir);
	free(section);
	return ir;
}

char *cperbuf_single_section_to_str_ir(const unsigned char *cper_section,
				       size_t size)
{
	json_object *jobj = cper_buf_single_section_to_ir(cper_section, size);
	char *str = jobj ? strdup(json_object_to_json_string(jobj)) : NULL;

	json_object_put(jobj);
	return str;
}
