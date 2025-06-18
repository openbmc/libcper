/**
 * Describes functions for converting CXL protocol error CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <string.h>
#include <libcper/base64.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-cxl-protocol.h>
#include <libcper/log.h>
#include <string.h>

//Converts a single CXL protocol error CPER section into JSON IR.
json_object *cper_section_cxl_protocol_to_ir(const UINT8 *section, UINT32 size,
					     char **desc_string)
{
	*desc_string = malloc(SECTION_DESC_STRING_SIZE);
	strncpy(*desc_string, "A CXL Protocol Error occurred",
		SECTION_DESC_STRING_SIZE);

	if (size < sizeof(EFI_CXL_PROTOCOL_ERROR_DATA)) {
		return NULL;
	}

	EFI_CXL_PROTOCOL_ERROR_DATA *cxl_protocol_error =
		(EFI_CXL_PROTOCOL_ERROR_DATA *)section;

	if (size < sizeof(EFI_CXL_PROTOCOL_ERROR_DATA) +
			   cxl_protocol_error->CxlDvsecLength +
			   cxl_protocol_error->CxlErrorLogLength) {
		return NULL;
	}

	json_object *section_ir = json_object_new_object();
	ValidationTypes ui64Type = {
		UINT_64T, .value.ui64 = cxl_protocol_error->ValidBits
	};

	//Type of detecting agent.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *agent_type = integer_to_readable_pair(
			cxl_protocol_error->CxlAgentType, 2,
			CXL_PROTOCOL_ERROR_AGENT_TYPES_KEYS,
			CXL_PROTOCOL_ERROR_AGENT_TYPES_VALUES,
			"Unknown (Reserved)");
		json_object_object_add(section_ir, "agentType", agent_type);
	}
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		//CXL agent address, depending on the agent type.
		json_object *agent_address = NULL;
		if (cxl_protocol_error->CxlAgentType ==
		    CXL_PROTOCOL_ERROR_DEVICE_AGENT) {
			agent_address = json_object_new_object();
			//Address is a CXL1.1 device agent.
			json_object_object_add(
				agent_address, "functionNumber",
				json_object_new_uint64(
					cxl_protocol_error->CxlAgentAddress
						.DeviceAddress.FunctionNumber));
			json_object_object_add(
				agent_address, "deviceNumber",
				json_object_new_uint64(
					cxl_protocol_error->CxlAgentAddress
						.DeviceAddress.DeviceNumber));
			json_object_object_add(
				agent_address, "busNumber",
				json_object_new_uint64(
					cxl_protocol_error->CxlAgentAddress
						.DeviceAddress.BusNumber));
			json_object_object_add(
				agent_address, "segmentNumber",
				json_object_new_uint64(
					cxl_protocol_error->CxlAgentAddress
						.DeviceAddress.SegmentNumber));
		} else if (cxl_protocol_error->CxlAgentType ==
			   CXL_PROTOCOL_ERROR_HOST_DOWNSTREAM_PORT_AGENT) {
			agent_address = json_object_new_object();
			//Address is a CXL port RCRB base address.
			json_object_object_add(
				agent_address, "value",
				json_object_new_uint64(
					cxl_protocol_error->CxlAgentAddress
						.PortRcrbBaseAddress));
		}
		if (agent_address != NULL) {
			json_object_object_add(section_ir, "cxlAgentAddress",
					       agent_address);
		}
	}

	json_object *device_id = json_object_new_object();
	json_object_object_add(
		device_id, "vendorID",
		json_object_new_uint64(cxl_protocol_error->DeviceId.VendorId));

	//Device ID.
	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		json_object_object_add(
			device_id, "deviceID",
			json_object_new_uint64(
				cxl_protocol_error->DeviceId.DeviceId));
		json_object_object_add(
			device_id, "subsystemVendorID",
			json_object_new_uint64(
				cxl_protocol_error->DeviceId.SubsystemVendorId));
		json_object_object_add(
			device_id, "subsystemDeviceID",
			json_object_new_uint64(
				cxl_protocol_error->DeviceId.SubsystemDeviceId));
		json_object_object_add(
			device_id, "classCode",
			json_object_new_uint64(
				cxl_protocol_error->DeviceId.ClassCode));
		json_object_object_add(
			device_id, "slotNumber",
			json_object_new_uint64(
				cxl_protocol_error->DeviceId.SlotNumber));
	}
	json_object_object_add(section_ir, "deviceID", device_id);

	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		//Device serial & capability structure (if CXL 1.1 device).
		if (cxl_protocol_error->CxlAgentType ==
		    CXL_PROTOCOL_ERROR_DEVICE_AGENT) {
			json_object_object_add(
				section_ir, "deviceSerial",
				json_object_new_uint64(
					cxl_protocol_error->DeviceSerial));
		}
	}

	char *encoded;
	int32_t encoded_len = 0;

	//The PCIe capability structure provided here could either be PCIe 1.1 Capability Structure
	//(36-byte, padded to 60 bytes) or PCIe 2.0 Capability Structure (60-byte). There does not seem
	//to be a way to differentiate these, so this is left as a b64 dump.
	if (isvalid_prop_to_ir(&ui64Type, 4)) {
		encoded = base64_encode(
			(UINT8 *)cxl_protocol_error->CapabilityStructure.PcieCap,
			60, &encoded_len);
		if (encoded == NULL) {
			cper_print_log(
				"Failed to allocate encode output buffer. \n");
			json_object_put(section_ir);

			return NULL;
		}
		json_object_object_add(section_ir, "capabilityStructure",
				       json_object_new_string_len(encoded,
								  encoded_len));
		free(encoded);
	}

	const UINT8 *cur_pos = (const UINT8 *)(cxl_protocol_error + 1);

	if (isvalid_prop_to_ir(&ui64Type, 5)) {
		//CXL DVSEC & error log length.
		json_object_object_add(
			section_ir, "dvsecLength",
			json_object_new_int(
				cxl_protocol_error->CxlDvsecLength));
		//CXL DVSEC
		//For CXL 1.1 devices, this is the "CXL DVSEC For Flex Bus Device" structure as in CXL 1.1 spec.
		//For CXL 1.1 host downstream ports, this is the "CXL DVSEC For Flex Bus Port" structure as in CXL 1.1 spec.
		int32_t encoded_len = 0;

		encoded = base64_encode(cur_pos,
					cxl_protocol_error->CxlDvsecLength,
					&encoded_len);
		if (encoded == NULL) {
			json_object_put(section_ir);
			return NULL;
		}
		json_object_object_add(section_ir, "cxlDVSEC",
				       json_object_new_string_len(encoded,
								  encoded_len));

		free(encoded);
	}

	cur_pos += cxl_protocol_error->CxlDvsecLength;

	if (isvalid_prop_to_ir(&ui64Type, 6)) {
		json_object_object_add(
			section_ir, "errorLogLength",
			json_object_new_int(
				cxl_protocol_error->CxlErrorLogLength));

		//CXL Error Log
		//This is the "CXL RAS Capability Structure" as in CXL 1.1 spec.

		encoded_len = 0;
		encoded = base64_encode((UINT8 *)cur_pos,
					cxl_protocol_error->CxlErrorLogLength,
					&encoded_len);

		if (encoded == NULL) {
			cper_print_log(
				"Failed to allocate encode output buffer. \n");
			json_object_put(section_ir);
			return NULL;
		}
		json_object_object_add(section_ir, "cxlErrorLog",
				       json_object_new_string_len(encoded,
								  encoded_len));
		free(encoded);
	}

	return section_ir;
}

//Converts a single CXL protocol CPER-JSON section into CPER binary, outputting to the given stream.
void ir_section_cxl_protocol_to_cper(json_object *section, FILE *out)
{
	EFI_CXL_PROTOCOL_ERROR_DATA *section_cper =
		(EFI_CXL_PROTOCOL_ERROR_DATA *)calloc(
			1, sizeof(EFI_CXL_PROTOCOL_ERROR_DATA));
	struct json_object *obj = NULL;

	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };

	//Detecting agent type.
	if (json_object_object_get_ex(section, "agentType", &obj)) {
		section_cper->CxlAgentType = readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 0);
	}

	//Based on the agent type, set the address.
	if (json_object_object_get_ex(section, "cxlAgentAddress", &obj)) {
		json_object *address = obj;
		if (section_cper->CxlAgentType ==
		    CXL_PROTOCOL_ERROR_DEVICE_AGENT) {
			//Address is split by function, device, bus & segment.
			UINT64 function = json_object_get_uint64(
				json_object_object_get(address,
						       "functionNumber"));
			UINT64 device = json_object_get_uint64(
				json_object_object_get(address,
						       "deviceNumber"));
			UINT64 bus = json_object_get_uint64(
				json_object_object_get(address, "busNumber"));
			UINT64 segment = json_object_get_uint64(
				json_object_object_get(address,
						       "segmentNumber"));
			section_cper->CxlAgentAddress.DeviceAddress
				.FunctionNumber = function;
			section_cper->CxlAgentAddress.DeviceAddress
				.DeviceNumber = device;
			section_cper->CxlAgentAddress.DeviceAddress.BusNumber =
				bus;
			section_cper->CxlAgentAddress.DeviceAddress
				.SegmentNumber = segment;
		} else if (section_cper->CxlAgentType ==
			   CXL_PROTOCOL_ERROR_HOST_DOWNSTREAM_PORT_AGENT) {
			//Plain RCRB base address.
			section_cper->CxlAgentAddress.PortRcrbBaseAddress =
				json_object_get_uint64(json_object_object_get(
					address, "value"));
		}
		add_to_valid_bitfield(&ui64Type, 1);
	}

	//Device ID information.
	if (json_object_object_get_ex(section, "deviceID", &obj)) {
		json_object *device_id = obj;
		section_cper->DeviceId.VendorId = json_object_get_uint64(
			json_object_object_get(device_id, "vendorID"));
		section_cper->DeviceId.DeviceId = json_object_get_uint64(
			json_object_object_get(device_id, "deviceID"));
		section_cper->DeviceId.SubsystemVendorId =
			json_object_get_uint64(json_object_object_get(
				device_id, "subsystemVendorID"));
		section_cper->DeviceId.SubsystemDeviceId =
			json_object_get_uint64(json_object_object_get(
				device_id, "subsystemDeviceID"));
		section_cper->DeviceId.ClassCode = json_object_get_uint64(
			json_object_object_get(device_id, "classCode"));
		section_cper->DeviceId.SlotNumber = json_object_get_uint64(
			json_object_object_get(device_id, "slotNumber"));
		add_to_valid_bitfield(&ui64Type, 2);
	}

	//If CXL 1.1 device, the serial number & PCI capability structure.
	UINT8 *decoded;
	if (section_cper->CxlAgentType == CXL_PROTOCOL_ERROR_DEVICE_AGENT) {
		if (json_object_object_get_ex(section, "deviceSerial", &obj)) {
			section_cper->DeviceSerial =
				json_object_get_uint64(obj);
			add_to_valid_bitfield(&ui64Type, 3);
		}
		if (json_object_object_get_ex(section, "capabilityStructure",
					      &obj)) {
			json_object *encoded = obj;

			int32_t decoded_len = 0;

			decoded = base64_decode(
				json_object_get_string(encoded),
				json_object_get_string_len(encoded),
				&decoded_len);

			if (decoded == NULL) {
				cper_print_log(
					"Failed to allocate decode output buffer. \n");
			} else {
				memcpy(section_cper->CapabilityStructure.PcieCap,
				       decoded, decoded_len);
				free(decoded);
				add_to_valid_bitfield(&ui64Type, 4);
			}
		}
	}

	//DVSEC length & error log length.
	section_cper->CxlDvsecLength = (UINT16)json_object_get_int(
		json_object_object_get(section, "dvsecLength"));
	section_cper->CxlErrorLogLength = (UINT16)json_object_get_int(
		json_object_object_get(section, "errorLogLength"));

	json_object *encodedsrc = NULL;
	json_object *encodederr = NULL;

	//DVSEC out: write valid bits
	if (json_object_object_get_ex(section, "cxlDVSEC", &obj)) {
		add_to_valid_bitfield(&ui64Type, 5);
		encodedsrc = obj;
	}

	//Error log: write valid bits
	if (json_object_object_get_ex(section, "cxlErrorLog", &obj)) {
		add_to_valid_bitfield(&ui64Type, 6);
		encodederr = obj;
	}
	section_cper->ValidBits = ui64Type.value.ui64;

	//Write header to stream.
	fwrite(section_cper, sizeof(EFI_CXL_PROTOCOL_ERROR_DATA), 1, out);
	fflush(out);

	//DVSEC out to stream.
	int32_t decoded_len = 0;
	if (encodedsrc != NULL) {
		decoded = base64_decode(json_object_get_string(encodedsrc),
					json_object_get_string_len(encodedsrc),
					&decoded_len);
		if (decoded == NULL) {
			cper_print_log(
				"Failed to allocate decode output buffer. \n");
		} else {
			fwrite(decoded, decoded_len, 1, out);
			fflush(out);
			free(decoded);
		}
	}

	//Error log out to stream.
	decoded_len = 0;
	if (encodederr != NULL) {
		decoded = base64_decode(json_object_get_string(encodederr),
					json_object_get_string_len(encodederr),
					&decoded_len);
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
