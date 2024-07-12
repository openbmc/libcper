/**
 * Describes functions for converting CXL component error CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <json.h>
#include "libbase64.h"
#include "../edk/Cper.h"
#include "../cper-utils.h"
#include "cper-section-cxl-component.h"

//Converts a single CXL component error CPER section into JSON IR.
json_object *cper_section_cxl_component_to_ir(void *section)
{
	EFI_CXL_COMPONENT_EVENT_HEADER *cxl_error =
		(EFI_CXL_COMPONENT_EVENT_HEADER *)section;
	json_object *section_ir = json_object_new_object();

	//Length (bytes) for the entire structure.
	json_object_object_add(section_ir, "length",
			       json_object_new_uint64(cxl_error->Length));

	//Validation bits.
	json_object *validation =
		bitfield_to_ir(cxl_error->ValidBits, 3,
			       CXL_COMPONENT_ERROR_VALID_BITFIELD_NAMES);
	json_object_object_add(section_ir, "validationBits", validation);

	//Device ID.
	json_object *device_id = json_object_new_object();
	json_object_object_add(
		device_id, "vendorID",
		json_object_new_int(cxl_error->DeviceId.VendorId));
	json_object_object_add(
		device_id, "deviceID",
		json_object_new_int(cxl_error->DeviceId.DeviceId));
	json_object_object_add(
		device_id, "functionNumber",
		json_object_new_int(cxl_error->DeviceId.FunctionNumber));
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

	//Device serial.
	json_object_object_add(section_ir, "deviceSerial",
			       json_object_new_uint64(cxl_error->DeviceSerial));

	//The specification for this is defined within the CXL Specification Section 8.2.9.1.
	const char *cur_pos = (const char *)(cxl_error + 1);
	int remaining_len =
		cxl_error->Length - sizeof(EFI_CXL_COMPONENT_EVENT_HEADER);
	if (remaining_len > 0) {
		json_object *event_log = json_object_new_object();
		char *encoded = malloc(2 * remaining_len);
		size_t encoded_len = 0;
		if (!encoded) {
			printf("Failed to allocate encode output buffer. \n");
		} else {
			base64_encode((const char *)cur_pos, remaining_len,
				      encoded, &encoded_len, 0);
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
	section_cper->ValidBits = ir_to_bitfield(
		json_object_object_get(section, "validationBits"), 3,
		CXL_COMPONENT_ERROR_VALID_BITFIELD_NAMES);

	//Device ID information.
	json_object *device_id = json_object_object_get(section, "deviceID");
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

	//Device serial number.
	section_cper->DeviceSerial = json_object_get_uint64(
		json_object_object_get(section, "deviceSerial"));

	//Write header out to stream.
	fwrite(section_cper, sizeof(EFI_CXL_COMPONENT_EVENT_HEADER), 1, out);
	fflush(out);

	//CXL component event log, decoded from base64.
	json_object *event_log =
		json_object_object_get(section, "cxlComponentEventLog");
	json_object *encoded = json_object_object_get(event_log, "data");
	char *decoded = malloc(json_object_get_string_len(encoded));
	size_t decoded_len = 0;
	if (!decoded) {
		printf("Failed to allocate decode output buffer. \n");
	} else {
		base64_decode(json_object_get_string(encoded),
			      json_object_get_string_len(encoded), decoded,
			      &decoded_len, 0);
		fwrite(decoded, decoded_len, 1, out);
		fflush(out);
		free(decoded);
	}

	free(section_cper);
}
