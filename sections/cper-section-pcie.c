/**
 * Describes functions for converting PCIe CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <string.h>
#include <json.h>
#include <libcper/base64.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-pcie.h>
#include <libcper/log.h>

struct aer_info_registers {
	UINT32 pcie_capability_header;
	UINT32 uncorrectable_error_status;
	UINT32 uncorrectable_error_mask;
	UINT32 uncorrectable_error_severity;
	UINT32 correctable_error_status;
	UINT32 correctable_error_mask;
	UINT32 aer_capabilites_control;
	UINT32 tlp_header_log[4];
};

//Converts a single PCIe CPER section into JSON IR.
json_object *cper_section_pcie_to_ir(const UINT8 *section, UINT32 size)
{
	if (size < sizeof(EFI_PCIE_ERROR_DATA)) {
		return NULL;
	}

	EFI_PCIE_ERROR_DATA *pcie_error = (EFI_PCIE_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = pcie_error->ValidFields };

	//Port type.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *port_type = integer_to_readable_pair(
			pcie_error->PortType, 9, PCIE_ERROR_PORT_TYPES_KEYS,
			PCIE_ERROR_PORT_TYPES_VALUES, "Unknown");
		json_object_object_add(section_ir, "portType", port_type);
	}

	//Version, provided each half in BCD.
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		json_object *version = json_object_new_object();
		json_object_object_add(version, "minor",
				       json_object_new_int(bcd_to_int(
					       pcie_error->Version & 0xFF)));
		json_object_object_add(version, "major",
				       json_object_new_int(bcd_to_int(
					       pcie_error->Version >> 8)));
		json_object_object_add(section_ir, "version", version);
	}

	//Command & status.
	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		json_object *command_status = json_object_new_object();
		json_object_object_add(
			command_status, "commandRegister",
			json_object_new_uint64(pcie_error->CommandStatus &
					       0xFFFF));
		json_object_object_add(
			command_status, "statusRegister",
			json_object_new_uint64(pcie_error->CommandStatus >>
					       16));
		json_object_object_add(section_ir, "commandStatus",
				       command_status);
	}

	//PCIe Device ID.
	char hexstring_buf[EFI_UINT64_HEX_STRING_LEN];
	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		json_object *device_id = json_object_new_object();
		UINT64 class_id = (pcie_error->DevBridge.ClassCode[0] << 16) +
				  (pcie_error->DevBridge.ClassCode[1] << 8) +
				  pcie_error->DevBridge.ClassCode[2];
		json_object_object_add(
			device_id, "vendorID",
			json_object_new_uint64(pcie_error->DevBridge.VendorId));
		json_object_object_add(
			device_id, "deviceID",
			json_object_new_uint64(pcie_error->DevBridge.DeviceId));

		snprintf(hexstring_buf, EFI_UINT64_HEX_STRING_LEN, "0x%0X",
			 pcie_error->DevBridge.DeviceId);
		json_object_object_add(device_id, "deviceIDHex",
				       json_object_new_string(hexstring_buf));

		json_object_object_add(device_id, "classCode",
				       json_object_new_uint64(class_id));
		json_object_object_add(
			device_id, "functionNumber",
			json_object_new_uint64(pcie_error->DevBridge.Function));
		json_object_object_add(
			device_id, "deviceNumber",
			json_object_new_uint64(pcie_error->DevBridge.Device));
		json_object_object_add(
			device_id, "segmentNumber",
			json_object_new_uint64(pcie_error->DevBridge.Segment));
		json_object_object_add(
			device_id, "primaryOrDeviceBusNumber",
			json_object_new_uint64(
				pcie_error->DevBridge.PrimaryOrDeviceBus));
		json_object_object_add(
			device_id, "secondaryBusNumber",
			json_object_new_uint64(
				pcie_error->DevBridge.SecondaryBus));
		json_object_object_add(
			device_id, "slotNumber",
			json_object_new_uint64(
				pcie_error->DevBridge.Slot.Number));
		json_object_object_add(section_ir, "deviceID", device_id);
	}

	//Device serial number.
	if (isvalid_prop_to_ir(&ui64Type, 4)) {
		json_object_object_add(
			section_ir, "deviceSerialNumber",
			json_object_new_uint64(pcie_error->SerialNo));
	}

	//Bridge control status.
	if (isvalid_prop_to_ir(&ui64Type, 5)) {
		json_object *bridge_control_status = json_object_new_object();
		json_object_object_add(
			bridge_control_status, "secondaryStatusRegister",
			json_object_new_uint64(pcie_error->BridgeControlStatus &
					       0xFFFF));
		json_object_object_add(
			bridge_control_status, "controlRegister",
			json_object_new_uint64(
				pcie_error->BridgeControlStatus >> 16));
		json_object_object_add(section_ir, "bridgeControlStatus",
				       bridge_control_status);
	}

	//Capability structure.
	//The PCIe capability structure provided here could either be PCIe 1.1 Capability Structure
	//(36-byte, padded to 60 bytes) or PCIe 2.0 Capability Structure (60-byte). There does not seem
	//to be a way to differentiate these, so this is left as a b64 dump.
	int32_t encoded_len = 0;
	char *encoded = NULL;
	if (isvalid_prop_to_ir(&ui64Type, 6)) {
		char *encoded =
			base64_encode((UINT8 *)pcie_error->Capability.PcieCap,
				      60, &encoded_len);
		if (encoded == NULL) {
			cper_print_log(
				"Failed to allocate encode output buffer. \n");
		} else {
			json_object *capability = json_object_new_object();
			json_object_object_add(capability, "data",
					       json_object_new_string_len(
						       encoded, encoded_len));
			free(encoded);

			json_object_object_add(
				section_ir, "capabilityStructure", capability);
		}
	}

	//AER information.
	encoded_len = 0;
	encoded = NULL;
	if (isvalid_prop_to_ir(&ui64Type, 7)) {
		json_object *aer_capability_ir = json_object_new_object();

		encoded = base64_encode((UINT8 *)pcie_error->AerInfo.PcieAer,
					96, &encoded_len);
		if (encoded == NULL) {
			cper_print_log(
				"Failed to allocate encode output buffer. \n");
		} else {
			json_object_object_add(aer_capability_ir, "data",
					       json_object_new_string_len(
						       encoded, encoded_len));
			free(encoded);
		}

		struct aer_info_registers *aer_decode;
		aer_decode = (struct aer_info_registers *)&pcie_error->AerInfo
				     .PcieAer;
		json_object_object_add(
			aer_capability_ir, "capability_header",
			json_object_new_uint64(
				aer_decode->pcie_capability_header));
		json_object_object_add(
			aer_capability_ir, "uncorrectable_error_status",
			json_object_new_uint64(
				aer_decode->uncorrectable_error_status));

		snprintf(hexstring_buf, EFI_UINT64_HEX_STRING_LEN,
			 "0x%08" PRIX32,
			 aer_decode->uncorrectable_error_status);
		json_object_object_add(aer_capability_ir,
				       "uncorrectable_error_status_hex",
				       json_object_new_string(hexstring_buf));

		json_object_object_add(
			aer_capability_ir, "uncorrectable_error_mask",
			json_object_new_uint64(
				aer_decode->uncorrectable_error_mask));
		json_object_object_add(
			aer_capability_ir, "uncorrectable_error_severity",
			json_object_new_uint64(
				aer_decode->uncorrectable_error_severity));
		json_object_object_add(
			aer_capability_ir, "correctable_error_status",
			json_object_new_uint64(
				aer_decode->correctable_error_status));

		int len = snprintf(hexstring_buf, EFI_UINT64_HEX_STRING_LEN,
				   "0x%08" PRIX32,
				   aer_decode->correctable_error_status);
		json_object_object_add(
			aer_capability_ir, "correctable_error_status_hex",
			json_object_new_string_len(hexstring_buf, len));

		json_object_object_add(
			aer_capability_ir, "correctable_error_mask",
			json_object_new_uint64(
				aer_decode->correctable_error_mask));
		json_object_object_add(
			aer_capability_ir, "capabilites_control",
			json_object_new_uint64(
				aer_decode->aer_capabilites_control));
		json_object_object_add(
			aer_capability_ir, "tlp_header_0",
			json_object_new_uint64(aer_decode->tlp_header_log[0]));
		json_object_object_add(
			aer_capability_ir, "tlp_header_1",
			json_object_new_uint64(aer_decode->tlp_header_log[1]));
		json_object_object_add(
			aer_capability_ir, "tlp_header_2",
			json_object_new_uint64(aer_decode->tlp_header_log[2]));
		json_object_object_add(
			aer_capability_ir, "tlp_header_3",
			json_object_new_uint64(aer_decode->tlp_header_log[3]));
		json_object_object_add(section_ir, "aerInfo",
				       aer_capability_ir);
	}

	return section_ir;
}

//Converts a single CPER-JSON PCIe section into CPER binary, outputting to the given stream.
void ir_section_pcie_to_cper(json_object *section, FILE *out)
{
	EFI_PCIE_ERROR_DATA *section_cper =
		(EFI_PCIE_ERROR_DATA *)calloc(1, sizeof(EFI_PCIE_ERROR_DATA));

	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;

	//Version.
	if (json_object_object_get_ex(section, "version", &obj)) {
		json_object *version = obj;
		UINT32 minor = int_to_bcd(json_object_get_int(
			json_object_object_get(version, "minor")));
		UINT32 major = int_to_bcd(json_object_get_int(
			json_object_object_get(version, "major")));
		section_cper->Version = minor + (major << 8);
		add_to_valid_bitfield(&ui64Type, 1);
	}

	//Command/status registers.
	if (json_object_object_get_ex(section, "commandStatus", &obj)) {
		json_object *command_status = obj;
		UINT32 command = (UINT16)json_object_get_uint64(
			json_object_object_get(command_status,
					       "commandRegister"));
		UINT32 status = (UINT16)json_object_get_uint64(
			json_object_object_get(command_status,
					       "statusRegister"));
		section_cper->CommandStatus = command + (status << 16);
		add_to_valid_bitfield(&ui64Type, 2);
	}

	//Device ID.
	if (json_object_object_get_ex(section, "deviceID", &obj)) {
		json_object *device_id = obj;
		UINT64 class_id = json_object_get_uint64(
			json_object_object_get(device_id, "classCode"));
		section_cper->DevBridge.VendorId =
			(UINT16)json_object_get_uint64(
				json_object_object_get(device_id, "vendorID"));
		section_cper->DevBridge.DeviceId =
			(UINT16)json_object_get_uint64(
				json_object_object_get(device_id, "deviceID"));
		section_cper->DevBridge.ClassCode[0] = class_id >> 16;
		section_cper->DevBridge.ClassCode[1] = (class_id >> 8) & 0xFF;
		section_cper->DevBridge.ClassCode[2] = class_id & 0xFF;
		section_cper->DevBridge.Function =
			(UINT8)json_object_get_uint64(json_object_object_get(
				device_id, "functionNumber"));
		section_cper->DevBridge.Device = (UINT8)json_object_get_uint64(
			json_object_object_get(device_id, "deviceNumber"));
		section_cper->DevBridge.Segment =
			(UINT16)json_object_get_uint64(json_object_object_get(
				device_id, "segmentNumber"));
		section_cper->DevBridge.PrimaryOrDeviceBus =
			(UINT8)json_object_get_uint64(json_object_object_get(
				device_id, "primaryOrDeviceBusNumber"));
		section_cper->DevBridge.SecondaryBus =
			(UINT8)json_object_get_uint64(json_object_object_get(
				device_id, "secondaryBusNumber"));
		section_cper->DevBridge.Slot.Number =
			(UINT16)json_object_get_uint64(json_object_object_get(
				device_id, "slotNumber"));
		add_to_valid_bitfield(&ui64Type, 3);
	}

	//Bridge/control status.
	if (json_object_object_get_ex(section, "bridgeControlStatus", &obj)) {
		json_object *bridge_control = obj;
		UINT32 bridge_status = (UINT16)json_object_get_uint64(
			json_object_object_get(bridge_control,
					       "secondaryStatusRegister"));
		UINT32 control_status = (UINT16)json_object_get_uint64(
			json_object_object_get(bridge_control,
					       "controlRegister"));
		section_cper->BridgeControlStatus =
			bridge_status + (control_status << 16);
		add_to_valid_bitfield(&ui64Type, 5);
	}

	//Capability structure.
	int32_t decoded_len = 0;
	UINT8 *decoded = NULL;
	json_object *encoded = NULL;
	if (json_object_object_get_ex(section, "capabilityStructure", &obj)) {
		json_object *capability = obj;
		json_object *encoded =
			json_object_object_get(capability, "data");

		UINT8 *decoded = base64_decode(
			json_object_get_string(encoded),
			json_object_get_string_len(encoded), &decoded_len);
		if (decoded == NULL) {
			cper_print_log(
				"Failed to allocate decode output buffer. \n");
		} else {
			memcpy(section_cper->Capability.PcieCap, decoded,
			       decoded_len);
			free(decoded);
		}
		add_to_valid_bitfield(&ui64Type, 6);
	}

	decoded = NULL;
	encoded = NULL;
	//AER capability structure.
	if (json_object_object_get_ex(section, "aerInfo", &obj)) {
		json_object *aer_info = obj;
		encoded = json_object_object_get(aer_info, "data");
		decoded_len = 0;

		decoded = base64_decode(json_object_get_string(encoded),
					json_object_get_string_len(encoded),
					&decoded_len);

		if (decoded == NULL) {
			cper_print_log(
				"Failed to allocate decode output buffer. \n");
		} else {
			memcpy(section_cper->AerInfo.PcieAer, decoded,
			       decoded_len);
			free(decoded);
		}
		add_to_valid_bitfield(&ui64Type, 7);
	}

	//Miscellaneous value fields.
	if (json_object_object_get_ex(section, "portType", &obj)) {
		section_cper->PortType = (UINT32)readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 0);
	}
	if (json_object_object_get_ex(section, "deviceSerialNumber", &obj)) {
		section_cper->SerialNo = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 4);
	}

	section_cper->ValidFields = ui64Type.value.ui64;

	//Write out to stream, free resources.
	fwrite(section_cper, sizeof(EFI_PCIE_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}
