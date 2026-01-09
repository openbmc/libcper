/**
 * Describes functions for converting CXL component error CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <json.h>
#include <libcper/base64.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-cxl-component.h>
#include <libcper/log.h>
#include <string.h>

//Converts a single CXL component error CPER section into JSON IR.
json_object *cper_section_cxl_component_to_ir(const UINT8 *section, UINT32 size,
					      char **desc_string)
{
	int outstr_len = 0;
	*desc_string = calloc(1, SECTION_DESC_STRING_SIZE);
	if (*desc_string == NULL ||
	    size < sizeof(EFI_CXL_COMPONENT_EVENT_HEADER)) {
		free(*desc_string);
		*desc_string = NULL;
		return NULL;
	}
	outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
			      "A CXL Component Error occurred");
	if (outstr_len < 0) {
		cper_print_log(
			"Error: Could not write to CXL Component description string\n");
	} else if (outstr_len > SECTION_DESC_STRING_SIZE) {
		cper_print_log(
			"Error: CXL Component description string truncated\n");
	}

	EFI_CXL_COMPONENT_EVENT_HEADER *cxl_error =
		(EFI_CXL_COMPONENT_EVENT_HEADER *)section;
	if (cxl_error->Length < sizeof(EFI_CXL_COMPONENT_EVENT_HEADER)) {
		free(*desc_string);
		*desc_string = NULL;
		return NULL;
	}
	if (size < cxl_error->Length) {
		free(*desc_string);
		*desc_string = NULL;
		return NULL;
	}
	json_object *section_ir = json_object_new_object();

	//Length (bytes) for the entire structure.
	json_object_object_add(section_ir, "length",
			       json_object_new_uint64(cxl_error->Length));

	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = cxl_error->ValidBits };

	//Device ID.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *device_id = json_object_new_object();
		json_object_object_add(
			device_id, "vendorID",
			json_object_new_int(cxl_error->DeviceId.VendorId));
		json_object_object_add(
			device_id, "deviceID",
			json_object_new_int(cxl_error->DeviceId.DeviceId));
		json_object_object_add(
			device_id, "functionNumber",
			json_object_new_int(
				cxl_error->DeviceId.FunctionNumber));
		json_object_object_add(
			device_id, "deviceNumber",
			json_object_new_int(cxl_error->DeviceId.DeviceNumber));
		json_object_object_add(
			device_id, "busNumber",
			json_object_new_int(cxl_error->DeviceId.BusNumber));
		json_object_object_add(
			device_id, "segmentNumber",
			json_object_new_int(cxl_error->DeviceId.SegmentNumber));
		json_object_object_add(
			device_id, "slotNumber",
			json_object_new_int(cxl_error->DeviceId.SlotNumber));
		json_object_object_add(section_ir, "deviceID", device_id);
	}

	//Device serial.
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		json_object_object_add(
			section_ir, "deviceSerial",
			json_object_new_uint64(cxl_error->DeviceSerial));
	}

	//The specification for this is defined within the CXL Specification Section 8.2.9.1.
	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		const UINT8 *cur_pos = (const UINT8 *)(cxl_error + 1);
		int remaining_len = cxl_error->Length -
				    sizeof(EFI_CXL_COMPONENT_EVENT_HEADER);
		if (remaining_len > 0) {
			int32_t encoded_len = 0;

			char *encoded = base64_encode(cur_pos, remaining_len,
						      &encoded_len);
			if (encoded == NULL) {
				cper_print_log(
					"Failed to allocate encode output buffer. \n");
				json_object_put(section_ir);
				free(*desc_string);
				*desc_string = NULL;
				return NULL;
			}
			json_object *event_log = json_object_new_object();

			json_object_object_add(event_log, "data",
					       json_object_new_string_len(
						       encoded, encoded_len));

			free(encoded);
			json_object_object_add(
				section_ir, "cxlComponentEventLog", event_log);
		}
	}

	return section_ir;
}

//Converts a single given CXL Component CPER-JSON section into CPER binary, outputting to the
//given stream.
void ir_section_cxl_component_to_cper(json_object *section, FILE *out)
{
	EFI_CXL_COMPONENT_EVENT_HEADER *section_cper =
		(EFI_CXL_COMPONENT_EVENT_HEADER *)calloc(
			1, sizeof(EFI_CXL_COMPONENT_EVENT_HEADER));

	//Length of the structure.
	section_cper->Length = json_object_get_uint64(
		json_object_object_get(section, "length"));

	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;

	//Device ID information.
	if (json_object_object_get_ex(section, "deviceID", &obj)) {
		json_object *device_id = obj;
		section_cper->DeviceId.VendorId = json_object_get_uint64(
			json_object_object_get(device_id, "vendorID"));
		section_cper->DeviceId.DeviceId = json_object_get_uint64(
			json_object_object_get(device_id, "deviceID"));
		section_cper->DeviceId.FunctionNumber = json_object_get_uint64(
			json_object_object_get(device_id, "functionNumber"));
		section_cper->DeviceId.DeviceNumber = json_object_get_uint64(
			json_object_object_get(device_id, "deviceNumber"));
		section_cper->DeviceId.BusNumber = json_object_get_uint64(
			json_object_object_get(device_id, "busNumber"));
		section_cper->DeviceId.SegmentNumber = json_object_get_uint64(
			json_object_object_get(device_id, "segmentNumber"));
		section_cper->DeviceId.SlotNumber = json_object_get_uint64(
			json_object_object_get(device_id, "slotNumber"));
		add_to_valid_bitfield(&ui64Type, 0);
	}

	//Device serial number.
	if (json_object_object_get_ex(section, "deviceSerial", &obj)) {
		section_cper->DeviceSerial = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 1);
	}

	//CXL component event log, decoded from base64.
	json_object *event_log = NULL;
	if (json_object_object_get_ex(section, "cxlComponentEventLog", &obj)) {
		event_log = obj;
		add_to_valid_bitfield(&ui64Type, 2);
	}
	section_cper->ValidBits = ui64Type.value.ui64;

	//Write header out to stream.
	fwrite(section_cper, sizeof(EFI_CXL_COMPONENT_EVENT_HEADER), 1, out);
	fflush(out);

	if (event_log != NULL) {
		json_object *encoded =
			json_object_object_get(event_log, "data");

		int32_t decoded_len = 0;

		UINT8 *decoded = base64_decode(
			json_object_get_string(encoded),
			json_object_get_string_len(encoded), &decoded_len);

		if (decoded == NULL) {
			cper_print_log(
				"Failed to allocate decode output buffer. \n");
		} else {
			fwrite(decoded, decoded_len, 1, out);
			fflush(out);
			free(decoded);
		}
	}

	free(section_cper);
}
