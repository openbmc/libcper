/**
 * Describes high level functions for converting an entire CPER log, and functions for parsing
 * CPER headers and section descriptions into an intermediate JSON format.
 *
 * Author: Lawrence.Tang@arm.com
 *         drewwalton@microsoft.com
 **/

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <json.h>

#include <libcper/base64.h>
#include <libcper/Cpad.h>
#include <libcper/log.h>
#include <libcper/cpad-parse.h>
#include <libcper/cpad-parse-str.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cpad-section.h>

//Private pre-definitions.
json_object *cpad_header_to_ir(CPAD_HEADER *header);
json_object *
cpad_section_descriptor_to_ir(CPAD_SECTION_DESCRIPTOR *section_descriptor);

json_object *cpad_buf_section_to_ir(const void *cpad_section_buf, size_t size,
				    CPAD_SECTION_DESCRIPTOR *descriptor);

static int header_signature_valid(CPAD_HEADER *header)
{
	if (header->SignatureStart != CPAD_SIGNATURE_START) {
		cper_print_log(
			"Invalid CPAD file: Invalid header (incorrect signature). %x\n",
			header->SignatureStart);
		return 0;
	}
	if (header->SignatureEnd != CPAD_SIGNATURE_END) {
		cper_print_log(
			"Invalid CPAD file: Invalid header (incorrect signature end). %x\n",
			header->SignatureEnd);
		return 0;
	}
	if (header->SectionCount == 0) {
		cper_print_log(
			"Invalid CPAD file: Invalid section count (0).\n");
		return 0;
	}
	// FIXME: PlatformID, PartitionID valid-flags-are-set checks?
	return 1;
}

int cpad_header_valid(const char *cpad_buf, size_t size)
{
	if (size < sizeof(CPAD_HEADER)) {
		return 0;
	}
	CPAD_HEADER *header =
		(CPAD_HEADER *)cpad_buf;
	if (!header_signature_valid(header)) {
		return 0;
	}
	return header_signature_valid(header);
}

json_object *cpad_buf_to_ir(const unsigned char *cpad_buf, size_t size)
{
	json_object *parent = NULL;
	json_object *header_ir = NULL;
	json_object *section_descriptors_ir = NULL;
	json_object *sections_ir = NULL;

	const unsigned char *pos = cpad_buf;
	unsigned int remaining = size;
	if (size < sizeof(CPAD_HEADER)) {
		goto fail;
	}
	CPAD_HEADER *header = (CPAD_HEADER *)cpad_buf;
	if (!header_signature_valid(header)) {
		goto fail;
	}
	pos += sizeof(CPAD_HEADER);
	remaining -= sizeof(CPAD_HEADER);

	if (remaining < sizeof(CPAD_SECTION_DESCRIPTOR)) {
		cper_print_log(
			"Invalid CPAD file: Invalid CPAD section descriptor (section offset + length > size).\n");
		goto fail;
	}

	//Create the header JSON object from the read bytes.
	parent = json_object_new_object();
	header_ir = cpad_header_to_ir(header);

	json_object_object_add(parent, "header", header_ir);

	//Read the appropriate number of section descriptors & sections, and convert them into IR format.
	section_descriptors_ir = json_object_new_array();
	sections_ir = json_object_new_array();
	for (int i = 0; i < header->SectionCount; i++) {
		//Create the section descriptor.
		if (remaining < sizeof(CPAD_SECTION_DESCRIPTOR)) {
			cper_print_log(
				"Invalid number of CPAD section headers: Header states %d sections, could not read section %d.\n",
				header->SectionCount, i + 1);
			goto fail;
		}

		CPAD_SECTION_DESCRIPTOR *section_descriptor;
		section_descriptor = (CPAD_SECTION_DESCRIPTOR *)(pos);
		pos += sizeof(CPAD_SECTION_DESCRIPTOR);
		remaining -= sizeof(CPAD_SECTION_DESCRIPTOR);
		if (section_descriptor->SectionOffset > size) {
			cper_print_log(
				"Invalid CPADsection descriptor: Section offset > size.\n");
			goto fail;
		}
 
		if (section_descriptor->SectionLength <= 0) {
			cper_print_log(
				"Invalid CPAD section descriptor: Section length <= 0.\n");
			goto fail;
		}

		if (section_descriptor->SectionOffset >
		    UINT_MAX - section_descriptor->SectionLength) {
			cper_print_log(
				"Invalid CPAD section descriptor: Section offset + length would overflow.\n");
			goto fail;
		}

		if (section_descriptor->SectionOffset +
			    section_descriptor->SectionLength >
		    size) {
			cper_print_log(
				"Invalid CPAD section descriptor: Section offset + length > size.\n");
			goto fail;
		}

		const unsigned char *section_begin =
			cpad_buf + section_descriptor->SectionOffset;
		json_object *section_descriptor_ir =
			cpad_section_descriptor_to_ir(section_descriptor);

		json_object_array_add(section_descriptors_ir,
				      section_descriptor_ir);

		//Read the section itself.
		json_object *section_ir = cpad_buf_section_to_ir(
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
	cper_print_log("Failed to parse CPAD file.\n");
	return NULL;
}

//Reads a CPAD log file at the given file location, and returns an intermediate
//JSON representation of this CPAD record.
json_object *cpad_to_ir(FILE *cpad_file)
{
	//Ensure this is really a CPAD log.
	CPAD_HEADER header;
	if (fread(&header, sizeof(CPAD_HEADER), 1,
		  cpad_file) != 1) {
		cper_print_log(
			"Invalid CPAD file: Invalid length (log too short).\n");
		return NULL;
	}

	//Check if the header contains the magic bytes ("CPAD").
	if (header.SignatureStart != CPAD_SIGNATURE_START) {
		cper_print_log(
			"Invalid CPAD file: Invalid header (incorrect signature).\n");
		return NULL;
	}
	fseek(cpad_file, -sizeof(CPAD_HEADER), SEEK_CUR);
	unsigned char *cpad_buf = malloc(header.RecordLength);
	int bytes_read = fread(cpad_buf, 1, header.RecordLength, cpad_file);
	if (bytes_read < 0) {
		cper_print_log("File read failed with code %u\n", bytes_read);
		free(cpad_buf);
		return NULL;
	}
	if ((UINT32)bytes_read != header.RecordLength) {
		int position = ftell(cpad_file);
		cper_print_log(
			"File read failed file was %u bytes, expecting %u bytes from header.\n",
			position, header.RecordLength);
		free(cpad_buf);
		return NULL;
	}

	json_object *ir = cpad_buf_to_ir(cpad_buf, bytes_read);
	free(cpad_buf);
	return ir;
}

char *cpad_to_str_ir(FILE *cpad_file)
{
	json_object *jobj = cpad_to_ir(cpad_file);
	char *str = jobj ? strdup(json_object_to_json_string(jobj)) : NULL;

	json_object_put(jobj);
	return str;
}

char *cpadbuf_to_str_ir(const unsigned char *cpad, size_t size)
{
	FILE *cpad_file = fmemopen((void *)cpad, size, "r");

	return cpad_file ? cpad_to_str_ir(cpad_file) : NULL;
}

//Converts a parsed CPAD record header into intermediate JSON object format.
json_object *cpad_header_to_ir(CPAD_HEADER *header)
{
	json_object *header_ir = json_object_new_object();

	//Revision/version information.
	json_object_object_add(header_ir, "revision",
			       revision_to_ir(header->Revision));

	//Section count.
	json_object_object_add(header_ir, "sectionCount",
			       json_object_new_int(header->SectionCount));

	//CPAD Urgency	
	json_object_object_add(header_ir, "urgency", cpad_urgency_to_ir(
		(CPAD_URGENCY_BITFIELD *)&header->Urgency));

	//CPAD Confidence.
	json_object_object_add(header_ir, "confidence",
			       json_object_new_int(header->Confidence));

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

	//Total length of the record (including headers) in bytes.
	json_object_object_add(header_ir, "recordLength",
			       json_object_new_uint64(header->RecordLength));

	// FIXME: Throw an error if platformID is not valid?  It is needed to route CPADs
	//If a platform ID exists according to the validation bits, then add it.
	if (header->ValidationBits & 0x1) {
		add_guid(header_ir, "platformID", &header->PlatformID);
	}

	// FIXME: Throw an error if partitionID is not valid?  It is needed to route CPADs
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

	json_object_object_add(
		notification_type, "type",
		json_object_new_string(notification_type_readable));
	json_object_object_add(header_ir, "notificationType",
			       notification_type);

	//The record ID for this record, unique on a given system.
	json_object_object_add(header_ir, "recordID",
			       json_object_new_uint64(header->RecordID));

	//Flags. Currently Reserved field, read as uint32.
	json_object_object_add(header_ir, "flags",
			       json_object_new_uint64(header->Flags));

	return header_ir;
}

//Converts the given EFI section descriptor into JSON IR format.
json_object *
cpad_section_descriptor_to_ir(CPAD_SECTION_DESCRIPTOR *section_descriptor)
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
	json_object_object_add(section_descriptor_ir, "flags",
			       json_object_new_int(section_descriptor->Flags));

	//Section type (GUID).
	json_object *section_type = json_object_new_object();

	add_guid(section_type, "data", &section_descriptor->SectionType);
	//Readable section type, if possible.
	const char *section_type_readable = "Unknown";

	CPAD_SECTION_DEFINITION *section =
		cpad_select_section_by_guid(&section_descriptor->SectionType);
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

	//CPAD Urgency	
	json_object_object_add(section_descriptor_ir, "urgency", cpad_urgency_to_ir(
		(CPAD_URGENCY_BITFIELD *)&section_descriptor->Urgency));

	//CPAD Confidence.
	json_object_object_add(section_descriptor_ir, "confidence",
			       json_object_new_int(section_descriptor->Confidence));

	//CPAD Action.
	/*
	      "ActionID": {
            "code": 0x0001,
            "name": "Reboot"  // Will be "Proprietary Action" if in proprietary range
        },
	*/
	json_object *section_action = json_object_new_object();
	add_int_hex_16(section_action, "code", section_descriptor->ActionID);
	json_object_object_add(section_action, "name",
			       json_object_new_string(action_to_string(
				       section_descriptor->ActionID)));
	json_object_object_add(section_descriptor_ir, "actionID",
			       section_action);

	return section_descriptor_ir;
}

json_object *cpad_read_section(const unsigned char *cpad_section_buf, size_t size,
			  CPAD_SECTION_DEFINITION *definition)
{
	if (definition->ToIR == NULL) {
		return NULL;
	}
	json_object *section_ir = definition->ToIR(cpad_section_buf, size);
	if (section_ir == NULL) {
		return NULL;
	}
	json_object *result = json_object_new_object();
	json_object_object_add(result, definition->ShortName, section_ir);
	return result;
}

CPAD_SECTION_DEFINITION *cpad_select_section_by_guid(EFI_GUID *guid)
{
	size_t i = 0;
	for (; i < cpad_section_definitions_len; i++) {
		if (guid_equal(guid, cpad_section_definitions[i].Guid)) {
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
	if (i < cpad_section_definitions_len) {
		return &cpad_section_definitions[i];
	}

	return NULL;
}

//Converts the section described by a single given section descriptor.
json_object *cpad_buf_section_to_ir(const void *cpad_section_buf, size_t size,
				    CPAD_SECTION_DESCRIPTOR *descriptor)
{
	if (descriptor->SectionLength > size) {
		cper_print_log(
			"Invalid CPAD file: Invalid header (incorrect size).\n");
		return NULL;
	}

	//Parse section to IR based on GUID.
	json_object *result = NULL;
	json_object *section_ir = NULL;

	CPAD_SECTION_DEFINITION *section =
		cpad_select_section_by_guid(&descriptor->SectionType);
	if (section == NULL) {
		cper_print_log("Unknown section type guid\n");
	} else {
		result = cpad_read_section(cpad_section_buf, size, section);
	}

	//Was it an unknown GUID/failed read?
	if (result == NULL) {
		//Output the data as formatted base64.
		int32_t encoded_len = 0;
		char *encoded = base64_encode(cpad_section_buf,
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

json_object *cpad_buf_single_section_to_ir(const unsigned char *cpad_buf,
					   size_t size)
{
	const unsigned char *cpad_end;
	const unsigned char *section_begin;
	json_object *ir;

	cpad_end = cpad_buf + size;

	//Read the section descriptor out.
	CPAD_SECTION_DESCRIPTOR *section_descriptor;
	if (sizeof(CPAD_SECTION_DESCRIPTOR) > size) {
		cper_print_log(
			"Size of cpad_buf was too small to read section descriptor %zu\n",
			size);
		return NULL;
	}

	ir = json_object_new_object();
	section_descriptor = (CPAD_SECTION_DESCRIPTOR *)cpad_buf;
	//Convert the section descriptor to IR.
	json_object *section_descriptor_ir =
		cpad_section_descriptor_to_ir(section_descriptor);
	json_object_object_add(ir, "sectionDescriptor", section_descriptor_ir);
	section_begin = cpad_buf + section_descriptor->SectionOffset;

	if (section_begin + section_descriptor->SectionLength >= cpad_end) {
		json_object_put(ir);
		//cper_print_log("Invalid CPAD file: Invalid section descriptor (section offset + length > size).\n");
		return NULL;
	}

	const unsigned char *section =
		cpad_buf + section_descriptor->SectionOffset;

	//Parse the single section.
	json_object *section_ir = cpad_buf_section_to_ir(
		section, section_descriptor->SectionLength, section_descriptor);
	if (section_ir == NULL) {
		cper_print_log("RETURNING NULL2!! !!\n");
	}
	json_object_object_add(ir, "section", section_ir);
	return ir;
}

//Converts a single CPER section, without a header but with a section descriptor, to JSON.
json_object *cpad_single_section_to_ir(FILE *cpad_section_file)
{
	json_object *ir = json_object_new_object();

	//Read the current file pointer location as base record position.
	long base_pos = ftell(cpad_section_file);

	//Read the section descriptor out.
	CPAD_SECTION_DESCRIPTOR section_descriptor;
	if (fread(&section_descriptor, sizeof(CPAD_SECTION_DESCRIPTOR), 1,
		  cpad_section_file) != 1) {
		cper_print_log(
			"Failed to read section descriptor for CPAD single section (fread() returned an unexpected value).\n");
		json_object_put(ir);
		return NULL;
	}

	//Convert the section descriptor to IR.
	json_object *section_descriptor_ir =
		cpad_section_descriptor_to_ir(&section_descriptor);
	json_object_object_add(ir, "sectionDescriptor", section_descriptor_ir);

	//Save our current position in the stream.
	long position = ftell(cpad_section_file);
	//Read section as described by the section descriptor.
	fseek(cpad_section_file, base_pos + section_descriptor.SectionOffset,
	      SEEK_SET);
	void *section = malloc(section_descriptor.SectionLength);
	if (fread(section, section_descriptor.SectionLength, 1,
		  cpad_section_file) != 1) {
		cper_print_log(
			"Section read failed: Could not read %u bytes from global offset %d.\n",
			section_descriptor.SectionLength,
			section_descriptor.SectionOffset);
		json_object_put(ir);
		free(section);
		return NULL;
	}

	//Seek back to our original position.
	fseek(cpad_section_file, position, SEEK_SET);

	//Parse the single section.
	json_object *section_ir = cpad_buf_section_to_ir(
		section, section_descriptor.SectionLength, &section_descriptor);
	json_object_object_add(ir, "section", section_ir);
	free(section);
	return ir;
}

char *cpadbuf_single_section_to_str_ir(const unsigned char *cpad_section,
				       size_t size)
{
	json_object *jobj = cpad_buf_single_section_to_ir(cpad_section, size);
	char *str = jobj ? strdup(json_object_to_json_string(jobj)) : NULL;

	json_object_put(jobj);
	return str;
}
