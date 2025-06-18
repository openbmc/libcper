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
#include <libcper/log.h>
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

static int header_signature_valid(EFI_COMMON_ERROR_RECORD_HEADER *header)
{
	if (header->SignatureStart != EFI_ERROR_RECORD_SIGNATURE_START) {
		cper_print_log(
			"Invalid CPER file: Invalid header (incorrect signature). %x\n",
			header->SignatureStart);
		return 0;
	}
	if (header->SignatureEnd != EFI_ERROR_RECORD_SIGNATURE_END) {
		cper_print_log(
			"Invalid CPER file: Invalid header (incorrect signature end). %x\n",
			header->SignatureEnd);
		return 0;
	}
	if (header->SectionCount == 0) {
		cper_print_log(
			"Invalid CPER file: Invalid section count (0).\n");
		return 0;
	}
	return 1;
}

int header_valid(const char *cper_buf, size_t size)
{
	if (size < sizeof(EFI_COMMON_ERROR_RECORD_HEADER)) {
		return 0;
	}
	EFI_COMMON_ERROR_RECORD_HEADER *header =
		(EFI_COMMON_ERROR_RECORD_HEADER *)cper_buf;
	if (!header_signature_valid(header)) {
		return 0;
	}
	return header_signature_valid(header);
}

json_object *cper_buf_to_ir(const unsigned char *cper_buf, size_t size)
{
	json_object *parent = NULL;
	json_object *header_ir = NULL;
	json_object *section_descriptors_ir = NULL;
	json_object *sections_ir = NULL;

	const unsigned char *pos = cper_buf;
	unsigned int remaining = size;
	if (size < sizeof(EFI_COMMON_ERROR_RECORD_HEADER)) {
		goto fail;
	}
	EFI_COMMON_ERROR_RECORD_HEADER *header =
		(EFI_COMMON_ERROR_RECORD_HEADER *)cper_buf;
	if (!header_signature_valid(header)) {
		goto fail;
	}
	pos += sizeof(EFI_COMMON_ERROR_RECORD_HEADER);
	remaining -= sizeof(EFI_COMMON_ERROR_RECORD_HEADER);

	if (remaining < sizeof(EFI_ERROR_SECTION_DESCRIPTOR)) {
		cper_print_log(
			"Invalid CPER file: Invalid section descriptor (section offset + length > size).\n");
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
			cper_print_log(
				"Invalid number of section headers: Header states %d sections, could not read section %d.\n",
				header->SectionCount, i + 1);
			goto fail;
		}

		EFI_ERROR_SECTION_DESCRIPTOR *section_descriptor;
		section_descriptor = (EFI_ERROR_SECTION_DESCRIPTOR *)(pos);
		pos += sizeof(EFI_ERROR_SECTION_DESCRIPTOR);
		remaining -= sizeof(EFI_ERROR_SECTION_DESCRIPTOR);

		if (section_descriptor->SectionOffset > size) {
			cper_print_log(
				"Invalid section descriptor: Section offset > size.\n");
			goto fail;
		}

		if (section_descriptor->SectionLength <= 0) {
			cper_print_log(
				"Invalid section descriptor: Section length <= 0.\n");
			goto fail;
		}

		if (section_descriptor->SectionOffset >
		    UINT_MAX - section_descriptor->SectionLength) {
			cper_print_log(
				"Invalid section descriptor: Section offset + length would overflow.\n");
			goto fail;
		}

		if (section_descriptor->SectionOffset +
			    section_descriptor->SectionLength >
		    size) {
			cper_print_log(
				"Invalid section descriptor: Section offset + length > size.\n");
			goto fail;
		}

		const unsigned char *section_begin =
			cper_buf + section_descriptor->SectionOffset;
		json_object *section_descriptor_ir =
			cper_section_descriptor_to_ir(section_descriptor);

		json_object_array_add(section_descriptors_ir,
				      section_descriptor_ir);

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
	cper_print_log("Failed to parse CPER file.\n");
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
		cper_print_log(
			"Invalid CPER file: Invalid length (log too short).\n");
		return NULL;
	}

	//Check if the header contains the magic bytes ("CPER").
	if (header.SignatureStart != EFI_ERROR_RECORD_SIGNATURE_START) {
		cper_print_log(
			"Invalid CPER file: Invalid header (incorrect signature).\n");
		return NULL;
	}
	fseek(cper_file, -sizeof(EFI_COMMON_ERROR_RECORD_HEADER), SEEK_CUR);
	unsigned char *cper_buf = malloc(header.RecordLength);
	int bytes_read = fread(cper_buf, 1, header.RecordLength, cper_file);
	if (bytes_read < 0) {
		cper_print_log("File read failed with code %u\n", bytes_read);
		free(cper_buf);
		return NULL;
	}
	if ((UINT32)bytes_read != header.RecordLength) {
		int position = ftell(cper_file);
		cper_print_log(
			"File read failed file was %u bytes, expecting %u bytes from header.\n",
			position, header.RecordLength);
		free(cper_buf);
		return NULL;
	}

	json_object *ir = cper_buf_to_ir(cper_buf, bytes_read);
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
		if (timestamp_to_string(timestamp_string, TIMESTAMP_LENGTH,
					&header->TimeStamp) >= 0) {
			json_object_object_add(
				header_ir, "timestamp",
				json_object_new_string(timestamp_string));

			json_object_object_add(header_ir, "timestampIsPrecise",
					       json_object_new_boolean(
						       header->TimeStamp.Flag));
		}
	}

	//If a platform ID exists according to the validation bits, then add it.
	if (header->ValidationBits & 0x1) {
		add_guid(header_ir, "platformID", &header->PlatformID);
	}

	//If a partition ID exists according to the validation bits, then add it.
	if (header->ValidationBits & 0x4) {
		add_guid(header_ir, "partitionID", &header->PartitionID);
	}

	//Creator ID of the header.
	add_guid(header_ir, "creatorID", &header->CreatorID);
	//Notification type for the header. Some defined types are available.
	json_object *notification_type = json_object_new_object();
	add_guid(notification_type, "guid", &header->NotificationType);

	//Add the human readable notification type if possible.
	const char *notification_type_readable = "Unknown";

	EFI_GUID *guids[] = {
		&gEfiEventNotificationTypeCmcGuid,
		&gEfiEventNotificationTypeCpeGuid,
		&gEfiEventNotificationTypeMceGuid,
		&gEfiEventNotificationTypePcieGuid,
		&gEfiEventNotificationTypeInitGuid,
		&gEfiEventNotificationTypeNmiGuid,
		&gEfiEventNotificationTypeBootGuid,
		&gEfiEventNotificationTypeDmarGuid,
		&gEfiEventNotificationTypeSeaGuid,
		&gEfiEventNotificationTypeSeiGuid,
		&gEfiEventNotificationTypePeiGuid,
		&gEfiEventNotificationTypeCxlGuid,
	};

	const char *readable_names[] = {
		"CMC",	"CPE",	"MCE", "PCIe", "INIT", "NMI",
		"Boot", "DMAr", "SEA", "SEI",  "PEI",  "CXL Component"
	};

	int index = select_guid_from_list(&header->NotificationType, guids,
					  sizeof(guids) / sizeof(EFI_GUID *));
	if (index < (int)(sizeof(readable_names) / sizeof(char *))) {
		notification_type_readable = readable_names[index];
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

	add_guid(section_type, "data", &section_descriptor->SectionType);
	//Readable section type, if possible.
	const char *section_type_readable = "Unknown";

	CPER_SECTION_DEFINITION *section =
		select_section_by_guid(&section_descriptor->SectionType);
	if (section != NULL) {
		section_type_readable = section->ReadableName;
	}

	json_object_object_add(section_type, "type",
			       json_object_new_string(section_type_readable));
	json_object_object_add(section_descriptor_ir, "sectionType",
			       section_type);

	//If validation bits indicate it exists, add FRU ID.
	if (section_descriptor->SecValidMask & 0x1) {
		add_guid(section_descriptor_ir, "fruID",
			 &section_descriptor->FruId);
	}

	//If validation bits indicate it exists, add FRU text.
	if ((section_descriptor->SecValidMask & 0x2) >> 1) {
		add_untrusted_string(section_descriptor_ir, "fruText",
				     section_descriptor->FruString,
				     sizeof(section_descriptor->FruString));
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

json_object *read_section(const unsigned char *cper_section_buf, size_t size,
			  CPER_SECTION_DEFINITION *definition)
{
	if (definition->ToIR == NULL) {
		return NULL;
	}
	char *desc_string = NULL;

	json_object *section_ir =
		definition->ToIR(cper_section_buf, size, &desc_string);
	if (section_ir == NULL) {
		return NULL;
	}
	json_object *result = json_object_new_object();
	if (desc_string != NULL) {
		json_object_object_add(result, "message",
				       json_object_new_string(desc_string));
		free(desc_string);
	}
	json_object_object_add(result, definition->ShortName, section_ir);
	return result;
}

CPER_SECTION_DEFINITION *select_section_by_guid(EFI_GUID *guid)
{
	size_t i = 0;
	for (; i < section_definitions_len; i++) {
		if (guid_equal(guid, section_definitions[i].Guid)) {
			break;
		}
	}
	// It's unlikely fuzzing can reliably come up with a correct guid, given how
	// much entropy there is.  If we're in fuzzing mode, and if we haven't found
	// a match, try to force a match so we get some coverage.  Note, we still
	// want coverage of the section failed to convert code, so treat index ==
	// size as section failed to convert.
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	if (i == section_definitions_len) {
		i = guid->Data1 % (section_definitions_len + 1);
	}
#endif
	if (i < section_definitions_len) {
		return &section_definitions[i];
	}

	return NULL;
}

//Converts the section described by a single given section descriptor.
json_object *cper_buf_section_to_ir(const void *cper_section_buf, size_t size,
				    EFI_ERROR_SECTION_DESCRIPTOR *descriptor)
{
	if (descriptor->SectionLength > size) {
		cper_print_log(
			"Invalid CPER file: Invalid header (incorrect signature).\n");
		return NULL;
	}

	//Parse section to IR based on GUID.
	json_object *result = NULL;
	json_object *section_ir = NULL;

	CPER_SECTION_DEFINITION *section =
		select_section_by_guid(&descriptor->SectionType);
	if (section == NULL) {
		cper_print_log("Unknown section type guid\n");
	} else {
		result = read_section(cper_section_buf, size, section);
	}

	//Was it an unknown GUID/failed read?
	if (result == NULL) {
		//Output the data as formatted base64.
		int32_t encoded_len = 0;
		char *encoded = base64_encode(cper_section_buf,
					      descriptor->SectionLength,
					      &encoded_len);
		if (encoded == NULL) {
			cper_print_log(
				"Failed to allocate encode output buffer. \n");
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
	if (result == NULL) {
		cper_print_log("RETURNING NULL!! !!\n");
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
		cper_print_log(
			"Size of cper buffer was too small to read section descriptor %zu\n",
			size);
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
		//cper_print_log("Invalid CPER file: Invalid section descriptor (section offset + length > size).\n");
		return NULL;
	}

	const unsigned char *section =
		cper_buf + section_descriptor->SectionOffset;

	//Parse the single section.
	json_object *section_ir = cper_buf_section_to_ir(
		section, section_descriptor->SectionLength, section_descriptor);
	if (section_ir == NULL) {
		cper_print_log("RETURNING NULL2!! !!\n");
	}
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
		cper_print_log(
			"Failed to read section descriptor for CPER single section (fread() returned an unexpected value).\n");
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
		cper_print_log(
			"Section read failed: Could not read %u bytes from global offset %d.\n",
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
