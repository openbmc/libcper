/**
 * Describes functions for converting MTIA (Meta Training and Inference
 * Accelerator) OEM CPER sections from binary and JSON format into an
 * intermediate format.
 **/

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <json.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-mtia.h>
#include <libcper/log.h>

//Distinct from the CPER_SEVERITY_TYPES, so kept local to the MTIA section.
static const char *const MTIA_SEVERITY_NAMES[] = { "Info", "Warning",
						   "Recoverable", "Fatal" };

static const char *mtia_severity_name(UINT8 severity)
{
	if (severity <
	    (sizeof(MTIA_SEVERITY_NAMES) / sizeof(MTIA_SEVERITY_NAMES[0]))) {
		return MTIA_SEVERITY_NAMES[severity];
	}
	return "Unknown";
}

//Reads a hex string field into a fixed-length byte array, leaving it
//zeroed (as set up by the caller's calloc) if the field is missing or
//its decoded length does not match.
static void mtia_get_bytes_hex(json_object *obj, const char *field_name,
			       UINT8 *out, size_t out_len)
{
	size_t len = 0;
	UINT8 *bytes = get_bytes_hex(obj, field_name, &len);
	if (bytes == NULL) {
		return;
	}
	if (len != out_len) {
		cper_print_log("MTIA %s invalid len=%zu\n", field_name, len);
		free(bytes);
		return;
	}
	memcpy(out, bytes, out_len);
	free(bytes);
}

//Converts a single MTIA CPER section into JSON IR.
json_object *cper_section_mtia_to_ir(const UINT8 *section, UINT32 size,
				     char **desc_string)
{
	*desc_string = malloc(SECTION_DESC_STRING_SIZE);

	if (size < sizeof(EFI_MTIA_ERROR_DATA)) {
		free(*desc_string);
		*desc_string = NULL;
		return NULL;
	}

	if (size > sizeof(EFI_MTIA_ERROR_DATA)) {
		cper_print_log(
			"Warning: MTIA section has %u trailing bytes (HIVE extension) that are not decoded\n",
			(unsigned int)(size - sizeof(EFI_MTIA_ERROR_DATA)));
	}

	EFI_MTIA_ERROR_DATA *record = (EFI_MTIA_ERROR_DATA *)section;

	int outstr_len =
		snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
			 "An MTIA Error (severity %s, event %u) occurred",
			 mtia_severity_name(record->Severity),
			 (unsigned int)record->EventId);
	if (outstr_len < 0) {
		cper_print_log(
			"Error: Could not write to MTIA description string\n");
	} else if (outstr_len >= SECTION_DESC_STRING_SIZE) {
		cper_print_log("Error: MTIA description string truncated\n");
	}

	json_object *section_ir = json_object_new_object();

	//MTIA section header.
	json_object *header_ir = json_object_new_object();
	//Version is a packed word: byte 0 = minor, byte 1 = major.
	char version_string[16];
	snprintf(version_string, sizeof(version_string), "v%u.%u",
		 (unsigned int)((record->Version >> 8) & 0xFF),
		 (unsigned int)(record->Version & 0xFF));
	json_object_object_add(header_ir, "version",
			       json_object_new_string(version_string));
	add_int(header_ir, "recordSize", record->RecordSize);
	if (record->RecordSize != sizeof(EFI_MTIA_ERROR_DATA)) {
		cper_print_log(
			"Warning: MTIA recordSize (%u) does not match expected size (%zu)\n",
			(unsigned int)record->RecordSize,
			sizeof(EFI_MTIA_ERROR_DATA));
	}
	add_int_hex_64(header_ir, "validationBits", record->ValidationBits);
	add_bytes_hex(header_ir, "deviceId", record->DeviceId,
		      sizeof(record->DeviceId));
	add_bytes_hex(header_ir, "deviceSerial", record->DeviceSerial,
		      sizeof(record->DeviceSerial));
	add_int_hex_8(header_ir, "reserved1", record->Reserved1);
	json_object_object_add(section_ir, "sectionHeader", header_ir);

	//Event record common.
	json_object *event_ir = json_object_new_object();
	//Timestamp is an unsigned 64-bit event time in nanoseconds.
	json_object_object_add(event_ir, "timestamp",
			       json_object_new_uint64(record->Timestamp));
	add_int(event_ir, "eventId", record->EventId);
	json_object *severity_ir = json_object_new_object();
	add_int(severity_ir, "value", record->Severity);
	json_object_object_add(
		severity_ir, "name",
		json_object_new_string(mtia_severity_name(record->Severity)));
	json_object_object_add(event_ir, "severity", severity_ir);
	add_int(event_ir, "scope", record->Scope);
	add_int(event_ir, "deviceId", record->ChipId);
	add_int(event_ir, "platformId", record->PlatformId);
	add_int(event_ir, "skuId", record->SkuId);
	add_int(event_ir, "chipletId", record->ChipletId);
	add_int(event_ir, "moduleId", record->ModuleId);
	add_int_hex_8(event_ir, "flags", record->Flags);
	add_int(event_ir, "detailFormatId", record->DetailFormatId);
	add_int(event_ir, "detailLength", record->DetailLength);
	if (record->DetailLength > sizeof(record->EventDetailRaw)) {
		cper_print_log(
			"Warning: MTIA detailLength (%u) exceeds eventDetailRaw size (%zu)\n",
			(unsigned int)record->DetailLength,
			sizeof(record->EventDetailRaw));
	}
	add_bytes_hex(event_ir, "reserved2", record->Reserved2,
		      sizeof(record->Reserved2));
	json_object_object_add(section_ir, "eventRecordCommon", event_ir);

	//Event detail raw.
	add_bytes_hex(section_ir, "eventDetailRaw", record->EventDetailRaw,
		      sizeof(record->EventDetailRaw));

	return section_ir;
}

//Converts a single MTIA CPER-JSON section into CPER binary, outputting to the given stream.
void ir_section_mtia_to_cper(json_object *section, FILE *out)
{
	EFI_MTIA_ERROR_DATA *section_cper =
		(EFI_MTIA_ERROR_DATA *)calloc(1, sizeof(EFI_MTIA_ERROR_DATA));

	//MTIA section header.
	json_object *header_ir =
		json_object_object_get(section, "sectionHeader");
	//Version string "v<major>.<minor>" packs into byte 1 (major) and byte 0 (minor).
	unsigned int version_major = 0;
	unsigned int version_minor = 0;
	const char *version_str = json_object_get_string(
		json_object_object_get(header_ir, "version"));
	if (version_str != NULL) {
		if (sscanf(version_str, "v%u.%u", &version_major,
			   &version_minor) != 2) {
			cper_print_log(
				"Warning: Could not parse MTIA version string '%s'\n",
				version_str);
		}
	}
	section_cper->Version = (UINT16)(((version_major & 0xFF) << 8) |
					 (version_minor & 0xFF));
	section_cper->RecordSize = (UINT16)json_object_get_uint64(
		json_object_object_get(header_ir, "recordSize"));
	get_value_hex_64(header_ir, "validationBits",
			 &section_cper->ValidationBits);
	mtia_get_bytes_hex(header_ir, "deviceId", section_cper->DeviceId,
			   sizeof(section_cper->DeviceId));
	mtia_get_bytes_hex(header_ir, "deviceSerial",
			   section_cper->DeviceSerial,
			   sizeof(section_cper->DeviceSerial));
	get_value_hex_8(header_ir, "reserved1", &section_cper->Reserved1);

	//Event record common.
	json_object *event_ir =
		json_object_object_get(section, "eventRecordCommon");
	section_cper->Timestamp = json_object_get_uint64(
		json_object_object_get(event_ir, "timestamp"));
	section_cper->EventId = (UINT16)json_object_get_uint64(
		json_object_object_get(event_ir, "eventId"));
	section_cper->Severity =
		(UINT8)json_object_get_uint64(json_object_object_get(
			json_object_object_get(event_ir, "severity"), "value"));
	section_cper->Scope = (UINT8)json_object_get_uint64(
		json_object_object_get(event_ir, "scope"));
	section_cper->ChipId = (UINT8)json_object_get_uint64(
		json_object_object_get(event_ir, "deviceId"));
	section_cper->PlatformId = (UINT8)json_object_get_uint64(
		json_object_object_get(event_ir, "platformId"));
	section_cper->SkuId = (UINT8)json_object_get_uint64(
		json_object_object_get(event_ir, "skuId"));
	section_cper->ChipletId = (UINT8)json_object_get_uint64(
		json_object_object_get(event_ir, "chipletId"));
	section_cper->ModuleId = (UINT8)json_object_get_uint64(
		json_object_object_get(event_ir, "moduleId"));
	get_value_hex_8(event_ir, "flags", &section_cper->Flags);
	section_cper->DetailFormatId = (UINT8)json_object_get_uint64(
		json_object_object_get(event_ir, "detailFormatId"));
	section_cper->DetailLength = (UINT8)json_object_get_uint64(
		json_object_object_get(event_ir, "detailLength"));
	mtia_get_bytes_hex(event_ir, "reserved2", section_cper->Reserved2,
			   sizeof(section_cper->Reserved2));

	//Event detail raw.
	mtia_get_bytes_hex(section, "eventDetailRaw",
			   section_cper->EventDetailRaw,
			   sizeof(section_cper->EventDetailRaw));

	fwrite(section_cper, sizeof(EFI_MTIA_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}
