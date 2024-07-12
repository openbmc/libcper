/**
 * Describes functions for converting CXL protocol error CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <string.h>
#include "libbase64.h"
#include "../edk/Cper.h"
#include "../cper-utils.h"
#include "cper-section-cxl-protocol.h"

//Converts a single CXL protocol error CPER section into JSON IR.
json_object *cper_section_cxl_protocol_to_ir(void *section)
{
	EFI_CXL_PROTOCOL_ERROR_DATA *cxl_protocol_error =
		(EFI_CXL_PROTOCOL_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Validation bits.
	json_object *validation =
		bitfield_to_ir(cxl_protocol_error->ValidBits, 7,
			       CXL_PROTOCOL_ERROR_VALID_BITFIELD_NAMES);
	json_object_object_add(section_ir, "validationBits", validation);

	//Type of detecting agent.
	json_object *agent_type = integer_to_readable_pair(
		cxl_protocol_error->CxlAgentType, 2,
		CXL_PROTOCOL_ERROR_AGENT_TYPES_KEYS,
		CXL_PROTOCOL_ERROR_AGENT_TYPES_VALUES, "Unknown (Reserved)");
	json_object_object_add(section_ir, "agentType", agent_type);

	//CXL agent address, depending on the agent type.
	json_object *agent_address = json_object_new_object();
	if (cxl_protocol_error->CxlAgentType ==
	    CXL_PROTOCOL_ERROR_DEVICE_AGENT) {
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
		//Address is a CXL port RCRB base address.
		json_object_object_add(
			agent_address, "value",
			json_object_new_uint64(
				cxl_protocol_error->CxlAgentAddress
					.PortRcrbBaseAddress));
	}
	json_object_object_add(section_ir, "cxlAgentAddress", agent_address);

	//Device ID.
	json_object *device_id = json_object_new_object();
	json_object_object_add(
		device_id, "vendorID",
		json_object_new_uint64(cxl_protocol_error->DeviceId.VendorId));
	json_object_object_add(
		device_id, "deviceID",
		json_object_new_uint64(cxl_protocol_error->DeviceId.DeviceId));
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
		json_object_new_uint64(cxl_protocol_error->DeviceId.ClassCode));
	json_object_object_add(
		device_id, "slotNumber",
		json_object_new_uint64(
			cxl_protocol_error->DeviceId.SlotNumber));
	json_object_object_add(section_ir, "deviceID", device_id);

	//Device serial & capability structure (if CXL 1.1 device).
	if (cxl_protocol_error->CxlAgentType ==
	    CXL_PROTOCOL_ERROR_DEVICE_AGENT) {
		json_object_object_add(
			section_ir, "deviceSerial",
			json_object_new_uint64(
				cxl_protocol_error->DeviceSerial));

		//The PCIe capability structure provided here could either be PCIe 1.1 Capability Structure
		//(36-byte, padded to 60 bytes) or PCIe 2.0 Capability Structure (60-byte). There does not seem
		//to be a way to differentiate these, so this is left as a b64 dump.
		char *encoded = malloc(2 * 60);
		size_t encoded_len = 0;
		if (!encoded) {
			printf("Failed to allocate encode output buffer. \n");
		} else {
			base64_encode((const char *)cxl_protocol_error
					      ->CapabilityStructure.PcieCap,
				      60, encoded, &encoded_len, 0);
			json_object_object_add(section_ir,
					       "capabilityStructure",
					       json_object_new_string_len(
						       encoded, encoded_len));
			free(encoded);
		}
	}

	//CXL DVSEC & error log length.
	json_object_object_add(
		section_ir, "dvsecLength",
		json_object_new_int(cxl_protocol_error->CxlDvsecLength));
	json_object_object_add(
		section_ir, "errorLogLength",
		json_object_new_int(cxl_protocol_error->CxlErrorLogLength));

	//CXL DVSEC
	//For CXL 1.1 devices, this is the "CXL DVSEC For Flex Bus Device" structure as in CXL 1.1 spec.
	//For CXL 1.1 host downstream ports, this is the "CXL DVSEC For Flex Bus Port" structure as in CXL 1.1 spec.
	const char *cur_pos = (const char *)(cxl_protocol_error + 1);
	char *encoded = malloc(2 * cxl_protocol_error->CxlDvsecLength);
	size_t encoded_len = 0;
	if (!encoded) {
		printf("Failed to allocate encode output buffer. \n");
	} else {
		base64_encode(cur_pos, cxl_protocol_error->CxlDvsecLength,
			      encoded, &encoded_len, 0);
		json_object_object_add(section_ir, "cxlDVSEC",
				       json_object_new_string_len(encoded,
								  encoded_len));

		free(encoded);
	}
	cur_pos += cxl_protocol_error->CxlDvsecLength;

	//CXL Error Log
	//This is the "CXL RAS Capability Structure" as in CXL 1.1 spec.
	encoded = malloc(2 * cxl_protocol_error->CxlErrorLogLength);
	encoded_len = 0;
	if (!encoded) {
		printf("Failed to allocate encode output buffer. \n");
	} else {
		base64_encode(cur_pos, cxl_protocol_error->CxlErrorLogLength,
			      encoded, &encoded_len, 0);
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

	//Validation bits.
	section_cper->ValidBits = ir_to_bitfield(
		json_object_object_get(section, "validationBits"), 7,
		CXL_PROTOCOL_ERROR_VALID_BITFIELD_NAMES);

	//Detecting agent type.
	section_cper->CxlAgentType = readable_pair_to_integer(
		json_object_object_get(section, "agentType"));

	//Based on the agent type, set the address.
	json_object *address =
		json_object_object_get(section, "cxlAgentAddress");
	if (section_cper->CxlAgentType == CXL_PROTOCOL_ERROR_DEVICE_AGENT) {
		//Address is split by function, device, bus & segment.
		UINT64 function = json_object_get_uint64(
			json_object_object_get(address, "functionNumber"));
		UINT64 device = json_object_get_uint64(
			json_object_object_get(address, "deviceNumber"));
		UINT64 bus = json_object_get_uint64(
			json_object_object_get(address, "busNumber"));
		UINT64 segment = json_object_get_uint64(
			json_object_object_get(address, "segmentNumber"));
		section_cper->CxlAgentAddress.DeviceAddress.FunctionNumber =
			function;
		section_cper->CxlAgentAddress.DeviceAddress.DeviceNumber =
			device;
		section_cper->CxlAgentAddress.DeviceAddress.BusNumber = bus;
		section_cper->CxlAgentAddress.DeviceAddress.SegmentNumber =
			segment;
	} else if (section_cper->CxlAgentType ==
		   CXL_PROTOCOL_ERROR_HOST_DOWNSTREAM_PORT_AGENT) {
		//Plain RCRB base address.
		section_cper->CxlAgentAddress.PortRcrbBaseAddress =
			json_object_get_uint64(
				json_object_object_get(address, "value"));
	}

	//Device ID information.
	json_object *device_id = json_object_object_get(section, "deviceID");
	section_cper->DeviceId.VendorId = json_object_get_uint64(
		json_object_object_get(device_id, "vendorID"));
	section_cper->DeviceId.DeviceId = json_object_get_uint64(
		json_object_object_get(device_id, "deviceID"));
	section_cper->DeviceId.SubsystemVendorId = json_object_get_uint64(
		json_object_object_get(device_id, "subsystemVendorID"));
	section_cper->DeviceId.SubsystemDeviceId = json_object_get_uint64(
		json_object_object_get(device_id, "subsystemDeviceID"));
	section_cper->DeviceId.ClassCode = json_object_get_uint64(
		json_object_object_get(device_id, "classCode"));
	section_cper->DeviceId.SlotNumber = json_object_get_uint64(
		json_object_object_get(device_id, "slotNumber"));

	//If CXL 1.1 device, the serial number & PCI capability structure.
	if (section_cper->CxlAgentType == CXL_PROTOCOL_ERROR_DEVICE_AGENT) {
		section_cper->DeviceSerial = json_object_get_uint64(
			json_object_object_get(section, "deviceSerial"));

		json_object *encoded =
			json_object_object_get(section, "capabilityStructure");
		char *decoded = malloc(json_object_get_string_len(encoded));
		size_t decoded_len = 0;
		if (!decoded) {
			printf("Failed to allocate decode output buffer. \n");
		} else {
			base64_decode(json_object_get_string(encoded),
				      json_object_get_string_len(encoded),
				      decoded, &decoded_len, 0);
			memcpy(section_cper->CapabilityStructure.PcieCap,
			       decoded, decoded_len);
			free(decoded);
		}
	}

	//DVSEC length & error log length.
	section_cper->CxlDvsecLength = (UINT16)json_object_get_int(
		json_object_object_get(section, "dvsecLength"));
	section_cper->CxlErrorLogLength = (UINT16)json_object_get_int(
		json_object_object_get(section, "errorLogLength"));

	//Write header to stream.
	fwrite(section_cper, sizeof(EFI_CXL_PROTOCOL_ERROR_DATA), 1, out);
	fflush(out);

	//DVSEC out to stream.
	json_object *encoded = json_object_object_get(section, "cxlDVSEC");
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

	//Error log out to stream.
	encoded = json_object_object_get(section, "cxlErrorLog");
	decoded = malloc(json_object_get_string_len(encoded));
	decoded_len = 0;
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
