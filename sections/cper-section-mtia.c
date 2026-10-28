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
#include <libcper/base64.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-mtia.h>
#include <libcper/log.h>

/**
 * MTIA CPER Section Binary Structure Layout:
 *
 * The MTIA CPER section is a fixed 120-byte record. All published fields
 * are keys of a single "mtia" JSON object; arrows show each field's key.
 * Fields without an arrow are not published.
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_MTIA_ERROR_DATA                                         (120 bytes) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │  Offset  Field                                                          │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │       0  UINT16  Version                      ← "version"               │
 * │       2  UINT16  RecordSize                   ← "recordSize"            │
 * │       4  UINT64  ValidationBits                                         │
 * │      12  EFI_MTIA_PCIE_DEVICE_ID PcieDeviceId ← "pcieDeviceId" (bit 0)  │
 * │      24  UINT8   DeviceSerial[15]             ← "deviceSerial" (bit 1)  │
 * │      39  UINT8   Reserved1                                              │
 * │      40  UINT64  Timestamp                    ← "bootTimer"             │
 * │      48  UINT16  EventId                      ← "eventId"               │
 * │      50  UINT8   Severity                     ← "severity"              │
 * │      51  UINT8   Scope                        ← "scope"                 │
 * │      52  UINT8   ChipId                       ← "chipId"                │
 * │      53  UINT8   PlatformId                   ← "platformId"            │
 * │      54  UINT8   SkuId                        ← "skuId"                 │
 * │      55  UINT8   ChipletId                    ← "chipletId"             │
 * │      56  UINT8   ModuleId                     ← "moduleId"              │
 * │      57  UINT8   Flags                                                  │
 * │      58  UINT8   DetailFormatId               ← "detailFormatId"        │
 * │      59  UINT8   DetailLength                 ← "detailLength"          │
 * │      60  UINT8   Reserved2[12]                                          │
 * │      72  UINT8   EventDetailRaw[48]           ← "eventDetailRaw"        │
 * └─────────────────────────────────────────────────────────────────────────┘
 **/

//Distinct from the CPER_SEVERITY_TYPES, so kept local to the MTIA section.
static const char *MTIA_SEVERITY_NAMES[] = { "Info", "Warning", "Recoverable",
					     "Fatal" };

static const char *mtia_severity_name(UINT8 severity)
{
	if (severity <
	    (sizeof(MTIA_SEVERITY_NAMES) / sizeof(MTIA_SEVERITY_NAMES[0]))) {
		return MTIA_SEVERITY_NAMES[severity];
	}
	return "Unknown";
}

//Converts a single MTIA CPER section into JSON IR.
json_object *cper_section_mtia_to_ir(const UINT8 *section, UINT32 size,
				     char **desc_string)
{
	*desc_string = malloc(SECTION_DESC_STRING_SIZE);

	EFI_MTIA_ERROR_DATA *record = (EFI_MTIA_ERROR_DATA *)section;
	if (size != sizeof(EFI_MTIA_ERROR_DATA)) {
		if (size > sizeof(EFI_MTIA_ERROR_DATA)) {
			cper_print_log(
				"Error: MTIA section has %u trailing bytes (HIVE extension), which is not yet supported\n",
				(unsigned int)(size -
					       sizeof(EFI_MTIA_ERROR_DATA)));
		} else {
			cper_print_log(
				"Error: MTIA section size (%u) is smaller than expected (%zu)\n",
				(unsigned int)size,
				sizeof(EFI_MTIA_ERROR_DATA));
		}
		free(*desc_string);
		*desc_string = NULL;
		return NULL;
	}
	if (record->RecordSize != sizeof(EFI_MTIA_ERROR_DATA)) {
		cper_print_log(
			"Error: MTIA recordSize (%u) does not match expected size (%zu)\n",
			(unsigned int)record->RecordSize,
			sizeof(EFI_MTIA_ERROR_DATA));
		free(*desc_string);
		*desc_string = NULL;
		return NULL;
	}
	if (record->DetailLength > sizeof(record->EventDetailRaw)) {
		cper_print_log(
			"Error: MTIA detailLength (%u) exceeds eventDetailRaw size (%zu)\n",
			(unsigned int)record->DetailLength,
			sizeof(record->EventDetailRaw));
		free(*desc_string);
		*desc_string = NULL;
		return NULL;
	}

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
	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = record->ValidationBits };

	json_object_object_add(section_ir, "version",
			       revision_to_ir(record->Version));
	add_int(section_ir, "recordSize", record->RecordSize);

	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *pcie_ir = json_object_new_object();
		add_int(pcie_ir, "vendorId", record->PcieDeviceId.VendorId);
		add_int(pcie_ir, "deviceId", record->PcieDeviceId.DeviceId);
		add_int(pcie_ir, "functionNumber",
			record->PcieDeviceId.Function);
		add_int(pcie_ir, "deviceNumber", record->PcieDeviceId.Device);
		add_int(pcie_ir, "busNumber", record->PcieDeviceId.Bus);
		add_int(pcie_ir, "segmentNumber", record->PcieDeviceId.Segment);
		add_int(pcie_ir, "slotNumber",
			record->PcieDeviceId.Slot.Number);
		json_object_object_add(section_ir, "pcieDeviceId", pcie_ir);
	}
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		add_bytes_hex(section_ir, "deviceSerial", record->DeviceSerial,
			      sizeof(record->DeviceSerial));
	}

	//Event time since boot, in nanoseconds.
	add_uint(section_ir, "bootTimer", record->Timestamp);
	add_int(section_ir, "eventId", record->EventId);
	add_dict(
		section_ir, "severity", record->Severity, MTIA_SEVERITY_NAMES,
		(sizeof(MTIA_SEVERITY_NAMES) / sizeof(MTIA_SEVERITY_NAMES[0])));
	add_int_hex_8(section_ir, "scope", record->Scope);
	add_int_hex_8(section_ir, "chipId", record->ChipId);
	add_int_hex_8(section_ir, "platformId", record->PlatformId);
	add_int_hex_8(section_ir, "skuId", record->SkuId);
	add_int_hex_8(section_ir, "chipletId", record->ChipletId);
	add_int_hex_8(section_ir, "moduleId", record->ModuleId);
	add_int(section_ir, "detailFormatId", record->DetailFormatId);
	add_int(section_ir, "detailLength", record->DetailLength);
	add_binary_base64(section_ir, "eventDetailRaw", record->EventDetailRaw,
			  sizeof(record->EventDetailRaw));

	return section_ir;
}

//Converts a single MTIA CPER-JSON section into CPER binary, outputting to the given stream.
void ir_section_mtia_to_cper(json_object *section, FILE *out)
{
	EFI_MTIA_ERROR_DATA *section_cper =
		(EFI_MTIA_ERROR_DATA *)calloc(1, sizeof(EFI_MTIA_ERROR_DATA));

	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	json_object *obj = NULL;

	json_object *version = json_object_object_get(section, "version");
	int minor =
		json_object_get_int(json_object_object_get(version, "minor"));
	int major =
		json_object_get_int(json_object_object_get(version, "major"));
	section_cper->Version =
		(UINT16)(((major & 0xFF) << 8) | (minor & 0xFF));
	section_cper->RecordSize = (UINT16)json_object_get_uint64(
		json_object_object_get(section, "recordSize"));

	if (json_object_object_get_ex(section, "pcieDeviceId", &obj)) {
		EFI_MTIA_PCIE_DEVICE_ID *pcie = &section_cper->PcieDeviceId;
		pcie->VendorId = (UINT16)json_object_get_uint64(
			json_object_object_get(obj, "vendorId"));
		pcie->DeviceId = (UINT16)json_object_get_uint64(
			json_object_object_get(obj, "deviceId"));
		pcie->Function = (UINT8)json_object_get_uint64(
			json_object_object_get(obj, "functionNumber"));
		pcie->Device = (UINT8)json_object_get_uint64(
			json_object_object_get(obj, "deviceNumber"));
		pcie->Bus = (UINT8)json_object_get_uint64(
			json_object_object_get(obj, "busNumber"));
		pcie->Segment = (UINT16)json_object_get_uint64(
			json_object_object_get(obj, "segmentNumber"));
		pcie->Slot.Number = (UINT16)json_object_get_uint64(
			json_object_object_get(obj, "slotNumber"));
		add_to_valid_bitfield(&ui64Type, 0);
	}
	if (json_object_object_get_ex(section, "deviceSerial", &obj)) {
		get_bytes_hex_checked(section, "deviceSerial",
				      section_cper->DeviceSerial,
				      sizeof(section_cper->DeviceSerial));
		add_to_valid_bitfield(&ui64Type, 1);
	}
	section_cper->ValidationBits = ui64Type.value.ui64;

	section_cper->Timestamp = json_object_get_uint64(
		json_object_object_get(section, "bootTimer"));
	section_cper->EventId = (UINT16)json_object_get_uint64(
		json_object_object_get(section, "eventId"));
	section_cper->Severity =
		(UINT8)json_object_get_uint64(json_object_object_get(
			json_object_object_get(section, "severity"), "raw"));
	get_value_hex_8(section, "scope", &section_cper->Scope);
	get_value_hex_8(section, "chipId", &section_cper->ChipId);
	get_value_hex_8(section, "platformId", &section_cper->PlatformId);
	get_value_hex_8(section, "skuId", &section_cper->SkuId);
	get_value_hex_8(section, "chipletId", &section_cper->ChipletId);
	get_value_hex_8(section, "moduleId", &section_cper->ModuleId);
	section_cper->DetailFormatId = (UINT8)json_object_get_uint64(
		json_object_object_get(section, "detailFormatId"));
	section_cper->DetailLength = (UINT8)json_object_get_uint64(
		json_object_object_get(section, "detailLength"));

	json_object *encoded =
		json_object_object_get(section, "eventDetailRaw");
	int32_t decoded_len = 0;
	UINT8 *decoded = base64_decode(json_object_get_string(encoded),
				       json_object_get_string_len(encoded),
				       &decoded_len);
	if (decoded == NULL) {
		cper_print_log("Error: Could not decode MTIA eventDetailRaw\n");
	} else {
		if (decoded_len == sizeof(section_cper->EventDetailRaw)) {
			memcpy(section_cper->EventDetailRaw, decoded,
			       decoded_len);
		} else {
			cper_print_log(
				"Error: MTIA eventDetailRaw has %d bytes, expected %zu\n",
				decoded_len,
				sizeof(section_cper->EventDetailRaw));
		}
		free(decoded);
	}

	fwrite(section_cper, sizeof(EFI_MTIA_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}
