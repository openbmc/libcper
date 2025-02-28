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

// Convenience MACROs to parse and decode PCIe Capability and AER fields
#define JSON_FIELD(field, ir, decode)                                          \
	json_object_object_add(ir, #field,                                     \
			       json_object_new_uint64(decode->field));
#define JSON_FIELD_HEX(field, ir, decode)                                      \
	snprintf(hexstring_buf, EFI_UINT64_HEX_STRING_LEN, "0x%08" PRIX32,     \
		 decode->field);                                               \
	json_object_object_add(ir, #field "_hex",                              \
			       json_object_new_string(hexstring_buf));

#define CAP_FIELD(field) JSON_FIELD(field, pcie_capability_ir, cap_decode)
#define CAP_FIELD_HEX(field)                                                   \
	JSON_FIELD_HEX(field, pcie_capability_ir, cap_decode)
#define AER_FIELD(field) JSON_FIELD(field, aer_capability_ir, aer_decode)
#define AER_FIELD_HEX(field)                                                   \
	JSON_FIELD_HEX(field, aer_capability_ir, aer_decode)

struct pcie_capabilities {
	UINT32 cap_version : 4;		// bits [3:0]
	UINT32 device_type : 4;		// bits [7:4]
	UINT32 slot_implemented : 1;	// bit [8]
	UINT32 int_msg_num : 5;		// bits [13:9]
	UINT32 r : 1;			// bit [14]
	UINT32 flit_mode_supported : 1; // bit [15]
} __attribute__((packed));

struct capabilities_control {
	UINT32 first_error_pointer : 5;		      // bit [4:0]
	UINT32 ecrc_generation_capable : 1;	      // bit [5]
	UINT32 ecrc_generation_enable : 1;	      // bit [6]
	UINT32 ecrc_check_capable : 1;		      // bit [7]
	UINT32 ecrc_check_enable : 1;		      // bit [8]
	UINT32 multiple_header_recording_capable : 1; // bit [9]
	UINT32 multiple_header_recording_enable : 1;  // bit [10]
	UINT32 tlp_prefix_log_present : 1;	      // bit [11]
	UINT32 cto_prefix_header_log_capable : 1;     // bit [12]
	UINT32 header_log_size : 5;		      // bits [17:13]
	UINT32 logged_tlp_was_flit_mode : 1;	      // bit [18]
	UINT32 logged_tlp_size : 5;		      // bits [23:19]
} __attribute__((packed));

struct capability_registers {
	UINT8 pcie_cap_id;
	UINT8 next_ptr;
	union {
		struct pcie_capabilities pcie_capabilities_fields;
		UINT16 pcie_capabilities;
	} __attribute__((packed));
	UINT32 device_capabilities;
	UINT16 device_control;
	UINT16 device_status;
	UINT32 link_capabilities;
	UINT16 link_control;
	UINT16 link_status;
	UINT32 slot_capabilities;
	UINT16 slot_control;
	UINT16 slot_status;
	UINT16 root_control;
	UINT16 root_capabilities;
	UINT32 root_status;
	// "_2" postfixed only valid when pcie_capabilities_fields.cap_version >= 2
	UINT32 device_capabilities_2;
	UINT16 device_control_2;
	UINT16 device_status_2;
	UINT32 link_capabilities_2;
	UINT16 link_control_2;
	UINT16 link_status_2;
	UINT32 slot_capabilities_2;
	UINT16 slot_control_2;
	UINT16 slot_status_2;
} __attribute__((packed));

struct aer_info_registers {
	UINT32 capability_header;
	UINT32 uncorrectable_error_status;
	UINT32 uncorrectable_error_mask;
	UINT32 uncorrectable_error_severity;
	UINT32 correctable_error_status;
	UINT32 correctable_error_mask;
	union {
		struct capabilities_control capabilities_control_fields;
		UINT16 capabilities_control;
	} __attribute__((packed));
	UINT32 tlp_header_0;
	UINT32 tlp_header_1;
	UINT32 tlp_header_2;
	UINT32 tlp_header_3;
	UINT32 root_error_command;
	UINT32 root_error_status;
	UINT32 error_source_id;
	union {
		struct { // Non-flit mode TLP prefix logs
			UINT32 tlp_prefix_log_0;
			UINT32 tlp_prefix_log_1;
			UINT32 tlp_prefix_log_2;
			UINT32 tlp_prefix_log_3;
		} __attribute__((packed));
		struct { // Flit mode TLP header logs
			UINT32 tlp_header_4;
			UINT32 tlp_header_5;
			UINT32 tlp_header_6;
			UINT32 tlp_header_7;
			UINT32 tlp_header_8;
			UINT32 tlp_header_9;
			UINT32 tlp_header_10;
			UINT32 tlp_header_11;
			UINT32 tlp_header_12;
			UINT32 tlp_header_13;
		} __attribute__((packed));
	} __attribute__((packed));
} __attribute__((packed));

// TLP Header Log MACROS and structs
#define FMT_3DWND 0	   // 3DW header, no data
#define FMT_4DWND 1	   // 4DW header, no data
#define FMT_3DWD  2	   // 3DW header, with data
#define FMT_4DWD  3	   // 4DW header, with data

#define TYPE_MR	      0x00 // 0b00000
#define TYPE_IO	      0x02 // 0b00010
#define TYPE_CFG0     0x04 // 0b00100
#define TYPE_CFG1     0x05 // 0b00101
#define TYPE_DMRW     0x13 // 0b11011
#define TYPE_CPL      0x0A // 0b01010
#define TYPE_CPLLK    0x0B // 0b01011
#define TYPE_FETCHADD 0x0C // 0b01100
#define TYPE_SWAP     0x0D // 0b01101
#define TYPE_CAS      0x0E // 0b01110
#define TYPE_MSG0     0x10 // 0b10000
#define TYPE_MSG1     0x11 // 0b10001
#define TYPE_MSG2     0x12 // 0b10010
#define TYPE_MSG3     0x13 // 0b10011
#define TYPE_MSG4     0x14 // 0b10100
#define TYPE_MSG5     0x15 // 0b10101

// Define a struct for TLP header fields using bit fields
// For Memory, I/O, and Cfg Request Rules
struct req_tlp_header {
	// First DWORD (DW0)
	UINT32 length : 10;  // [9:0]   - Length
	UINT32 at : 2;	     // [11:10] - Address Type
	UINT32 attr_lo : 2;  // [13:12] - Attribute (lower 2 bits)
	UINT32 ep : 1;	     // [14]    - Poisoned
	UINT32 td : 1;	     // [15]    - TLP Digest
	UINT32 th : 1;	     // [16]    - TLP Hints
	UINT32 reserved : 1; // [17] - Reserved
	UINT32 attr_hi : 1;  // [18]    - Attribute (upper bit)
	UINT32 t8 : 1;	     // [19]    - TLP Priority
	UINT32 tc : 3;	     // [22:20] - Traffic Class
	UINT32 t9 : 1;	     // [23]    - Reserved
	UINT32 type : 5;     // [28:24] - Type
	UINT32 fmt : 3;	     // [31:29] - Format
} __attribute__((packed));

struct mem_tlp_3dw {
	struct req_tlp_header header;
	UINT32 first_dw : 4;
	UINT32 last_dw : 4;
	UINT32 tag : 8;
	UINT32 requester_id : 16;
	UINT32 ph : 2;
	UINT32 address : 30;
} __attribute__((packed));

struct mem_tlp_4dw {
	struct req_tlp_header header;
	UINT32 first_dw : 4;
	UINT32 last_dw : 4;
	UINT32 tag : 8;
	UINT32 requester_id : 16;
	UINT32 address_hi : 32;
	UINT32 ph : 2;
	UINT32 address_lo : 30;
} __attribute__((packed));

#define io_tlp mem_tlp_3dw // IO TLP is the same as mem_tlp_3dw

struct cfg_tlp {
	struct req_tlp_header header;
	UINT32 first_dw : 4;
	UINT32 last_dw : 4;
	UINT32 tag : 8;
	UINT32 requester_id : 16;
	UINT32 r1 : 2;
	UINT32 reg_num : 10;
	UINT32 r2 : 4;
	UINT32 destination_id : 16;
} __attribute__((packed));

struct cpl_tlp {
	struct req_tlp_header header;
	UINT32 byte_count : 12;
	UINT32 bcm : 1;
	UINT32 cpl_status : 3;
	UINT32 completer_id : 16;
	UINT32 lower_address : 7;
	UINT32 reserved : 1;
	UINT32 tag : 8;
	UINT32 requester_id : 16;
} __attribute__((packed));

// Parses the PCIe TLP Header Log
json_object *parse_tlp_header_log(UINT32 *tlp_header_log)
{
	// Allocate a json object to store the parsed TLP header fields
	json_object *tlp_obj = json_object_new_object();

	// Add fields to json object
	struct req_tlp_header *req_tlp_header;
	req_tlp_header = (struct req_tlp_header *)tlp_header_log;
	JSON_FIELD(fmt, tlp_obj, req_tlp_header);
	JSON_FIELD(type, tlp_obj, req_tlp_header);
	JSON_FIELD(tc, tlp_obj, req_tlp_header);
	JSON_FIELD(attr_hi, tlp_obj, req_tlp_header);
	JSON_FIELD(th, tlp_obj, req_tlp_header);
	JSON_FIELD(td, tlp_obj, req_tlp_header);
	JSON_FIELD(ep, tlp_obj, req_tlp_header);
	JSON_FIELD(attr_lo, tlp_obj, req_tlp_header);
	JSON_FIELD(at, tlp_obj, req_tlp_header);
	JSON_FIELD(length, tlp_obj, req_tlp_header);

	// Build description string
	char desc[1024];
	const char *fmt_str = "Unknown";
	const char *type_str = "Unknown";

	// Decode fmt field
	switch (req_tlp_header->fmt) {
	case FMT_3DWND:
		fmt_str = "3DW (no data)";
		break;
	case FMT_4DWND:
		fmt_str = "4DW (no data)";
		break;
	case FMT_3DWD:
		fmt_str = "3DW (with data)";
		break;
	case FMT_4DWD:
		fmt_str = "4DW (with data)";
		break;
	default:
		fmt_str = "Reserved";
		break;
	}

	// Decode type field
#define TYPE_MSG0_STR "Routed to Root Complex"
#define TYPE_MSG1_STR "Routed by Address + AT"
#define TYPE_MSG2_STR "Routed by ID"
#define TYPE_MSG3_STR "Broadcast from Root Complex"
#define TYPE_MSG4_STR "Local - Terminate at Receiver"
#define TYPE_MSG5_STR "Gathered and routed to Root Complex"

#define TYPE_RESERVED "TLP Prefix", "Reserved", "Reserved", "Reserved"
	struct type_decode_entry {
		int type;
		// 000 = 3DW (no data)
		// 001 = 4DW (no data)
		// 010 = 3DW (with data)
		// 011 = 4DW (with data)
		// 100 = TLP Prefix Log
		// 101 = Reserved
		// 110 = Reserved
		// 111 = Reserved
		const char *type_str[8];
	} type_decode[] = {
		{ TYPE_MR, { "MRd", "MRd", "MWr", "MWr", TYPE_RESERVED } },
		{ TYPE_IO,
		  { "IORd", "Reserved", "IOWr", "Reserved", TYPE_RESERVED } },
		{ TYPE_CFG0,
		  { "CfgRd", "Reserved", "CfgWr", "Reserved", TYPE_RESERVED } },
		{ TYPE_CFG1,
		  { "CfgRd", "Reserved", "CfgWr", "Reserved", TYPE_RESERVED } },
		{ TYPE_DMRW,
		  { "Reserved", "Reserved", "DMWr", "DMWr", TYPE_RESERVED } },
		{ TYPE_CPL,
		  { "Cpl", "Reserved", "CplD", "Reserved", TYPE_RESERVED } },
		{ TYPE_CPLLK,
		  { "CplLk", "Reserved", "CplDLk", "Reserved",
		    TYPE_RESERVED } },
		{ TYPE_FETCHADD,
		  { "Reserved", "Reserved", "FetchAdd", "FetchAdd",
		    TYPE_RESERVED } },
		{ TYPE_SWAP,
		  { "Reserved", "Reserved", "Swap", "Swap", TYPE_RESERVED } },
		{ TYPE_CAS,
		  { "Reserved", "Reserved", "CAS", "CAS", TYPE_RESERVED } },
		{ TYPE_MSG0,
		  { "Reserved", "Msg " TYPE_MSG0_STR, "Reserved",
		    "MsgD " TYPE_MSG0_STR, TYPE_RESERVED } },
		{ TYPE_MSG1,
		  { "Reserved", "Msg " TYPE_MSG1_STR, "Reserved",
		    "MsgD " TYPE_MSG1_STR, TYPE_RESERVED } },
		{ TYPE_MSG2,
		  { "Reserved", "Msg " TYPE_MSG2_STR, "Reserved",
		    "MsgD " TYPE_MSG2_STR, TYPE_RESERVED } },
		{ TYPE_MSG3,
		  { "Reserved", "Msg " TYPE_MSG3_STR, "Reserved",
		    "MsgD " TYPE_MSG3_STR, TYPE_RESERVED } },
		{ TYPE_MSG4,
		  { "Reserved", "Msg " TYPE_MSG4_STR, "Reserved",
		    "MsgD " TYPE_MSG4_STR, TYPE_RESERVED } },
		{ TYPE_MSG5,
		  { "Reserved", "Msg " TYPE_MSG5_STR, "Reserved",
		    "MsgD " TYPE_MSG5_STR, TYPE_RESERVED } },
	};

	for (int i = 0; i < (int)(sizeof(type_decode) / sizeof(type_decode[0]));
	     i++) {
		if (type_decode[i].type == req_tlp_header->type) {
			type_str = type_decode[i].type_str[req_tlp_header->fmt];
			break;
		}
	}

#define TLP_ADDRESS_32(tlp) (tlp->address & 0xFFFC)
#define TLP_ADDRESS_64(tlp)                                                    \
	(UINT64)(((UINT64)tlp->address_hi << 32) | (tlp->address_lo & 0xFFFC))
	char completer_id[128] = "";
	char requester_id[128] = "";
	char destination_id[128] = "";
	char completion_status[128] = "";
	char address[128] = "";

	switch (req_tlp_header->type) {
	case TYPE_MR: // Memory
	case TYPE_IO: // IO
		struct mem_tlp_3dw *tlp_3dw =
			(struct mem_tlp_3dw *)tlp_header_log;
		struct mem_tlp_4dw *tlp_4dw =
			(struct mem_tlp_4dw *)tlp_header_log;
		snprintf(requester_id, sizeof(requester_id),
			 ", Requester ID: 0x%04X", tlp_3dw->requester_id);
		if (req_tlp_header->fmt == FMT_3DWND ||
		    req_tlp_header->fmt == FMT_3DWD) {
			snprintf(address, sizeof(address), ", Address: 0x%08X",
				 TLP_ADDRESS_32(tlp_3dw));
		} else {
			snprintf(address, sizeof(address), ", Address: 0x%llX",
				 TLP_ADDRESS_64(tlp_4dw));
		}
		break;
	case TYPE_CFG0: // Config
	case TYPE_CFG1: // Config
		struct cfg_tlp *tlp_cfg = (struct cfg_tlp *)tlp_header_log;
		snprintf(requester_id, sizeof(requester_id),
			 ", Requester ID: 0x%04X", tlp_cfg->requester_id);
		snprintf(destination_id, sizeof(destination_id),
			 ", Destination ID: 0x%04X", tlp_cfg->destination_id);
		snprintf(address, sizeof(address), ", Address: %d",
			 tlp_cfg->reg_num);
		break;
	case TYPE_CPL:	 // Completion
	case TYPE_CPLLK: // Completion with Locked TLP
		struct cpl_tlp *tlp_cpl = (struct cpl_tlp *)tlp_header_log;
		snprintf(completer_id, sizeof(completer_id),
			 ", Completer ID: 0x%04X", tlp_cpl->completer_id);
		snprintf(completion_status, sizeof(completion_status),
			 ", Completion Status: ");
		switch (tlp_cpl->cpl_status) {
		case 0:
			strcat(completion_status, "Success");
			break;
		case 1:
			strcat(completion_status, "Unsupported Request");
			break;
		case 2:
			strcat(completion_status, "Request Retry Status");
			break;
		case 3:
			strcat(completion_status, "Completer Abort");
			break;
		default:
			strcat(completion_status, "Reserved");
			break;
		}
		snprintf(requester_id, sizeof(requester_id),
			 ", Requester ID: 0x%04X", tlp_cpl->requester_id);
		break;
	}

	snprintf(desc, sizeof(desc),
		 "TLP Header: %s, %s, TC=%d%s%s, Length=%d%s%s%s%s%s", fmt_str,
		 type_str, req_tlp_header->tc,
		 req_tlp_header->ep ? ", Poisoned" : "",
		 req_tlp_header->td ? ", TLP Digest" : "",
		 req_tlp_header->length, completer_id, requester_id,
		 destination_id, completion_status, address);
	json_object_object_add(tlp_obj, "description",
			       json_object_new_string(desc));

	return tlp_obj;
}

//Converts a single PCIe CPER section into JSON IR.
json_object *cper_section_pcie_to_ir(void *section)
{
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
	//(36-byte, padded to 60 bytes) or PCIe 2.0 Capability Structure (60-byte).
	//Check the PCIe Capabilities Registers (offset 0x2) to determine the capability version.
	int32_t encoded_len = 0;
	char *encoded = NULL;
	if (isvalid_prop_to_ir(&ui64Type, 6)) {
		json_object *pcie_capability_ir = json_object_new_object();

		encoded = base64_encode((UINT8 *)pcie_error->Capability.PcieCap,
					60, &encoded_len);
		if (encoded == NULL) {
			printf("Failed to allocate encode output buffer. \n");
		} else {
			json_object_object_add(pcie_capability_ir, "data",
					       json_object_new_string_len(
						       encoded, encoded_len));
			free(encoded);
		}

		struct capability_registers *cap_decode;
		cap_decode = (struct capability_registers *)&pcie_error
				     ->Capability.PcieCap;
		CAP_FIELD(pcie_cap_id);
		CAP_FIELD_HEX(pcie_cap_id);
		CAP_FIELD(next_ptr);
		CAP_FIELD_HEX(next_ptr);
		CAP_FIELD(pcie_capabilities);
		CAP_FIELD_HEX(pcie_capabilities);
		CAP_FIELD(device_capabilities);
		CAP_FIELD_HEX(device_capabilities);
		CAP_FIELD(device_control);
		CAP_FIELD_HEX(device_control);
		CAP_FIELD(device_status);
		CAP_FIELD_HEX(device_status);
		CAP_FIELD(link_capabilities);
		CAP_FIELD_HEX(link_capabilities);
		CAP_FIELD(link_control);
		CAP_FIELD_HEX(link_control);
		CAP_FIELD(link_status);
		CAP_FIELD_HEX(link_status);
		CAP_FIELD(slot_capabilities);
		CAP_FIELD_HEX(slot_capabilities);
		CAP_FIELD(slot_control);
		CAP_FIELD_HEX(slot_control);
		CAP_FIELD(slot_status);
		CAP_FIELD_HEX(slot_status);
		CAP_FIELD(root_control);
		CAP_FIELD_HEX(root_control);
		CAP_FIELD(root_capabilities);
		CAP_FIELD_HEX(root_capabilities);
		CAP_FIELD(root_status);
		CAP_FIELD_HEX(root_status);
		if (cap_decode->pcie_capabilities_fields.cap_version >= 2) {
			CAP_FIELD(device_capabilities_2);
			CAP_FIELD_HEX(device_capabilities_2);
			CAP_FIELD(device_control_2);
			CAP_FIELD_HEX(device_control_2);
			CAP_FIELD(device_status_2);
			CAP_FIELD_HEX(device_status_2);
			CAP_FIELD(link_capabilities_2);
			CAP_FIELD_HEX(link_capabilities_2);
			CAP_FIELD(link_control_2);
			CAP_FIELD_HEX(link_control_2);
			CAP_FIELD(link_status_2);
			CAP_FIELD_HEX(link_status_2);
			CAP_FIELD(slot_capabilities_2);
			CAP_FIELD_HEX(slot_capabilities_2);
			CAP_FIELD(slot_control_2);
			CAP_FIELD_HEX(slot_control_2);
			CAP_FIELD(slot_status_2);
			CAP_FIELD_HEX(slot_status_2);
		}

		json_object_object_add(section_ir, "capabilityStructure",
				       pcie_capability_ir);
	}

	//AER information.
	encoded_len = 0;
	encoded = NULL;
	if (isvalid_prop_to_ir(&ui64Type, 7)) {
		json_object *aer_capability_ir = json_object_new_object();

		encoded = base64_encode((UINT8 *)pcie_error->AerInfo.PcieAer,
					96, &encoded_len);
		if (encoded == NULL) {
			printf("Failed to allocate encode output buffer. \n");
		} else {
			json_object_object_add(aer_capability_ir, "data",
					       json_object_new_string_len(
						       encoded, encoded_len));
			free(encoded);
		}

		struct aer_info_registers *aer_decode;
		aer_decode = (struct aer_info_registers *)&pcie_error->AerInfo
				     .PcieAer;
		AER_FIELD(capability_header);
		AER_FIELD_HEX(capability_header);
		AER_FIELD(uncorrectable_error_status);
		AER_FIELD_HEX(uncorrectable_error_status);
		AER_FIELD(uncorrectable_error_mask);
		AER_FIELD_HEX(uncorrectable_error_mask);
		AER_FIELD(uncorrectable_error_severity);
		AER_FIELD_HEX(uncorrectable_error_severity);
		AER_FIELD(correctable_error_status);
		AER_FIELD_HEX(correctable_error_status);
		AER_FIELD(correctable_error_mask);
		AER_FIELD_HEX(correctable_error_mask);
		AER_FIELD(capabilities_control);
		AER_FIELD_HEX(capabilities_control);
		AER_FIELD(root_error_command);
		AER_FIELD_HEX(root_error_command);
		AER_FIELD(root_error_status);
		AER_FIELD_HEX(root_error_status);
		AER_FIELD(error_source_id);
		AER_FIELD_HEX(error_source_id);
		AER_FIELD(tlp_header_0);
		AER_FIELD_HEX(tlp_header_0);
		AER_FIELD(tlp_header_1);
		AER_FIELD_HEX(tlp_header_1);
		AER_FIELD(tlp_header_2);
		AER_FIELD_HEX(tlp_header_2);
		AER_FIELD(tlp_header_3);
		AER_FIELD_HEX(tlp_header_3);
		if (aer_decode->capabilities_control_fields.
			    .logged_tlp_was_flit_mode == 1) {
			// For Flit mode the rest of the payload is tlp header logs
			AER_FIELD(tlp_header_4);
			AER_FIELD_HEX(tlp_header_4);
			AER_FIELD(tlp_header_5);
			AER_FIELD_HEX(tlp_header_5);
			AER_FIELD(tlp_header_6);
			AER_FIELD_HEX(tlp_header_6);
			AER_FIELD(tlp_header_7);
			AER_FIELD_HEX(tlp_header_7);
			AER_FIELD(tlp_header_8);
			AER_FIELD_HEX(tlp_header_8);
			AER_FIELD(tlp_header_9);
			AER_FIELD_HEX(tlp_header_9);
			AER_FIELD(tlp_header_10);
			AER_FIELD_HEX(tlp_header_10);
			AER_FIELD(tlp_header_11);
			AER_FIELD_HEX(tlp_header_11);
			AER_FIELD(tlp_header_12);
			AER_FIELD_HEX(tlp_header_12);
			AER_FIELD(tlp_header_13);
			AER_FIELD_HEX(tlp_header_13);
		} else {
			// For Non-Flit mode
			// Add Non-Flit mode TLP description
			// The next 4 DWORDs are TLP prefix logs
			json_object_object_add(
				aer_capability_ir, "tlp_description",
				parse_tlp_header_log(
					&aer_decode->tlp_header_0));

			AER_FIELD(tlp_prefix_log_0);
			AER_FIELD_HEX(tlp_prefix_log_0);
			AER_FIELD(tlp_prefix_log_1);
			AER_FIELD_HEX(tlp_prefix_log_1);
			AER_FIELD(tlp_prefix_log_2);
			AER_FIELD_HEX(tlp_prefix_log_2);
			AER_FIELD(tlp_prefix_log_3);
			AER_FIELD_HEX(tlp_prefix_log_3);
		}

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
			printf("Failed to allocate decode output buffer. \n");
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
			printf("Failed to allocate decode output buffer. \n");
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
