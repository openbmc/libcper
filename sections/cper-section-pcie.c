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
			       json_object_new_uint64((decode)->field));
#define JSON_FIELD_HEX(field, ir, decode)                                      \
	snprintf(hexstring_buf, EFI_UINT64_HEX_STRING_LEN, "0x%08" PRIX32,     \
		 (decode)->field);                                             \
	json_object_object_add(ir, #field "_hex",                              \
			       json_object_new_string(hexstring_buf));

#define AER_FIELD(field) JSON_FIELD(field, aer_capability_ir, aer_decode)
#define AER_FIELD_HEX(field)                                                   \
	JSON_FIELD_HEX(field, aer_capability_ir, aer_decode)

#define JSON_FIELD_INT(ir, field, decode)                                      \
	add_json_field_int(ir, #field, (decode).field)                        
#define JSON_FIELD_BOOL(ir, field, decode)                                     \
	add_json_field_bool(ir, #field, (decode).field);
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define JSON_FIELD_DICT(ir, field, decode)                                     \
	add_json_field_dict(ir, #field, (decode).field, field ## _dict,        \
	(sizeof(field ## _dict) / sizeof((field ## _dict)[0])))

void add_json_field_int(json_object *register_ir, const char *field_name, UINT64 value) {
	json_object *field_ir = json_object_new_object();
	json_object_object_add(register_ir, field_name, field_ir);
	json_object_object_add(field_ir, "value", json_object_new_uint64(value));
}

void add_json_field_bool(json_object *register_ir, const char *field_name, UINT64 value) {
	json_object *field_ir = json_object_new_object();
	json_object_object_add(register_ir, field_name, field_ir);
	json_object_object_add(field_ir, "value", json_object_new_boolean(value));
}

void add_json_field_dict(json_object *register_ir, const char *field_name, UINT64 value, const char *dict[], size_t dict_size) {
	json_object *field_ir = json_object_new_object();
	json_object_object_add(register_ir, field_name, field_ir);
	json_object_object_add(field_ir, "value", json_object_new_uint64(value));

	//size_t dict_size = sizeof(dict) / sizeof(dict[0]);
	const char *value_name = "UNKNOWN";
	if (value < dict_size && dict[value] != NULL) {
		value_name = dict[value];
	}
	
	json_object_object_add(field_ir, "name", json_object_new_string(value_name));
}

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
	pcie_capability_header_t pcie_capability_header;
	pcie_capabilities_t pcie_capabilities;
	device_capabilities_t device_capabilities;
	device_control_t device_control;
	device_status_t device_status;
	link_capabilities_t link_capabilities;
	link_control_t link_control;
	link_status_t link_status;
	slot_capabilities_t slot_capabilities;
	slot_control_t slot_control;
	slot_status_t slot_status;
	root_control_t root_control;
	root_capabilities_t root_capabilities;
	root_status_t root_status;
	// "_2" postfixed only valid when pcie_capabilities_fields.cap_version >= 2
	device_capabilities2_t device_capabilities2;
	device_control2_t device_control2;
	device_status2_t device_status2;
	link_capabilities2_t link_capabilities2;
	link_control2_t link_control2;
	link_status2_t link_status2;
	slot_capabilities2_t slot_capabilities2;
	slot_control2_t slot_control2;
	slot_status2_t slot_status2;
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
		UINT32 capabilities_control;
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
// Valid for All Non-Flit Mode TLPs
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

// Memory PIO TLPs in 3DW format
struct mem_tlp_3dw {
	struct req_tlp_header header;
	UINT32 first_dw : 4;
	UINT32 last_dw : 4;
	UINT32 tag : 8;
	UINT32 requester_id : 16;
	UINT32 ph : 2;
	UINT32 address : 30;
} __attribute__((packed));

// Memory PIO TLPs in 3DW format
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

#define io_tlp mem_tlp_3dw // IO PIO TLP is the same as mem_tlp_3dw

// Configuration PIO TLPs
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

// Completion TLPs
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
// Step 1: Parse the first DWORD (DW0) of the TLP header log
// Step 2: Find the string representation of the TLP FMT/Type
// Step 3: Decode DW1-DW3 based on FMT/Type and create a description string
json_object *parse_tlp_header_log(UINT32 *tlp_header_log)
{
	// Allocate a json object to store the parsed TLP header fields
	json_object *tlp_obj = json_object_new_object();

	// Parse the first DWORD (DW0) of the TLP header log
	// These fields are valid for all non-flit mode TLPs
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
	const char *fmt_str;
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

	// Decode the format type field
	// Create a table for all possible FMT/Type combinations with their
	// string representations.
#define TYPE_MSG0_STR "Routed to Root Complex"
#define TYPE_MSG1_STR "Routed by Address + AT"
#define TYPE_MSG2_STR "Routed by ID"
#define TYPE_MSG3_STR "Broadcast from Root Complex"
#define TYPE_MSG4_STR "Local - Terminate at Receiver"
#define TYPE_MSG5_STR "Gathered and routed to Root Complex"
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
		{ TYPE_MR,
		  { "MRd", "MRd", "MWr", "MWr", "TLP Prefix", "Reserved",
		    "Reserved", "Reserved" } },
		{ TYPE_IO,
		  { "IORd", "Reserved", "IOWr", "Reserved", "TLP Prefix",
		    "Reserved", "Reserved", "Reserved" } },
		{ TYPE_CFG0,
		  { "CfgRd", "Reserved", "CfgWr", "Reserved", "TLP Prefix",
		    "Reserved", "Reserved", "Reserved" } },
		{ TYPE_CFG1,
		  { "CfgRd", "Reserved", "CfgWr", "Reserved", "TLP Prefix",
		    "Reserved", "Reserved", "Reserved" } },
		{ TYPE_DMRW,
		  { "Reserved", "Reserved", "DMWr", "DMWr", "TLP Prefix",
		    "Reserved", "Reserved", "Reserved" } },
		{ TYPE_CPL,
		  { "Cpl", "Reserved", "CplD", "Reserved", "TLP Prefix",
		    "Reserved", "Reserved", "Reserved" } },
		{ TYPE_CPLLK,
		  { "CplLk", "Reserved", "CplDLk", "Reserved", "TLP Prefix",
		    "Reserved", "Reserved", "Reserved" } },
		{ TYPE_FETCHADD,
		  { "Reserved", "Reserved", "FetchAdd", "FetchAdd",
		    "TLP Prefix", "Reserved", "Reserved", "Reserved" } },
		{ TYPE_SWAP,
		  { "Reserved", "Reserved", "Swap", "Swap", "TLP Prefix",
		    "Reserved", "Reserved", "Reserved" } },
		{ TYPE_CAS,
		  { "Reserved", "Reserved", "CAS", "CAS", "TLP Prefix",
		    "Reserved", "Reserved", "Reserved" } },
		{ TYPE_MSG0,
		  { "Reserved", "Msg " TYPE_MSG0_STR, "Reserved",
		    "MsgD " TYPE_MSG0_STR, "TLP Prefix", "Reserved", "Reserved",
		    "Reserved" } },
		{ TYPE_MSG1,
		  { "Reserved", "Msg " TYPE_MSG1_STR, "Reserved",
		    "MsgD " TYPE_MSG1_STR, "TLP Prefix", "Reserved", "Reserved",
		    "Reserved" } },
		{ TYPE_MSG2,
		  { "Reserved", "Msg " TYPE_MSG2_STR, "Reserved",
		    "MsgD " TYPE_MSG2_STR, "TLP Prefix", "Reserved", "Reserved",
		    "Reserved" } },
		{ TYPE_MSG3,
		  { "Reserved", "Msg " TYPE_MSG3_STR, "Reserved",
		    "MsgD " TYPE_MSG3_STR, "TLP Prefix", "Reserved", "Reserved",
		    "Reserved" } },
		{ TYPE_MSG4,
		  { "Reserved", "Msg " TYPE_MSG4_STR, "Reserved",
		    "MsgD " TYPE_MSG4_STR, "TLP Prefix", "Reserved", "Reserved",
		    "Reserved" } },
		{ TYPE_MSG5,
		  { "Reserved", "Msg " TYPE_MSG5_STR, "Reserved",
		    "MsgD " TYPE_MSG5_STR, "TLP Prefix", "Reserved", "Reserved",
		    "Reserved" } },
	};

	for (int i = 0; i < (int)(sizeof(type_decode) / sizeof(type_decode[0]));
	     i++) {
		if (type_decode[i].type == req_tlp_header->type) {
			type_str = type_decode[i].type_str[req_tlp_header->fmt];
			break;
		}
	}

	// Decode DW1-DW3 based on FMT/Type and create a description string
	char completer_id[128] = "";
	char requester_id[128] = "";
	char destination_id[128] = "";
	char completion_status[128] = "";
	char address[128] = "";
	UINT8 hdr_type = req_tlp_header->type;

	if (hdr_type == TYPE_MR || hdr_type == TYPE_IO) {
		// Memory or IO Requests
		const struct mem_tlp_3dw *tlp_3dw =
			(const struct mem_tlp_3dw *)tlp_header_log;
		const struct mem_tlp_4dw *tlp_4dw =
			(struct mem_tlp_4dw *)tlp_header_log;
		snprintf(requester_id, sizeof(requester_id),
			 ", Requester ID: 0x%04X", tlp_3dw->requester_id);
		if (req_tlp_header->fmt == FMT_3DWND ||
		    req_tlp_header->fmt == FMT_3DWD) {
			snprintf(address, sizeof(address), ", Address: 0x%08X",
				 (tlp_3dw->address) & 0xFFFC);
		} else {
			snprintf(address, sizeof(address),
				 ", Address: 0x%X%08X", (tlp_4dw->address_hi),
				 (tlp_4dw->address_lo & 0xFFFC));
		}
	} else if (hdr_type == TYPE_CFG0 || hdr_type == TYPE_CFG1) {
		// Configuration Requests
		const struct cfg_tlp *tlp_cfg =
			(const struct cfg_tlp *)tlp_header_log;
		snprintf(requester_id, sizeof(requester_id),
			 ", Requester ID: 0x%04X", tlp_cfg->requester_id);
		snprintf(destination_id, sizeof(destination_id),
			 ", Destination ID: 0x%04X", tlp_cfg->destination_id);
		snprintf(address, sizeof(address), ", Address: %u",
			 tlp_cfg->reg_num);
	} else if (hdr_type == TYPE_CPL || hdr_type == TYPE_CPLLK) {
		// Completions and Locked Completions
		const struct cpl_tlp *tlp_cpl =
			(const struct cpl_tlp *)tlp_header_log;
		snprintf(requester_id, sizeof(requester_id),
			 ", Requester ID: 0x%04X", tlp_cpl->requester_id);
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
	}

	snprintf(desc, sizeof(desc),
		 "TLP Header: %s, %s, TC=%u%s%s, Length=%u%s%s%s%s%s", fmt_str,
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

		json_object *register_fields_ir;

		struct capability_registers *cap_decode;
		cap_decode = (struct capability_registers *)&pcie_error
				     ->Capability.PcieCap;


		/*
		 * PCI Express Capability Structure Header
		 * Offset: 0x0
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_INT(register_fields_ir, capability_id,
			       cap_decode->pcie_capability_header);
		JSON_FIELD_INT(register_fields_ir, next_capability_pointer,
			       cap_decode->pcie_capability_header);
		json_object_object_add(pcie_capability_ir,
				       "pcie_capability_header", register_fields_ir);

		/*
		 * PCI Express Capabilities Register
		 * Offset: 0x2
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_INT(register_fields_ir, capability_version,
			       cap_decode->pcie_capabilities);
		JSON_FIELD_DICT(register_fields_ir, device_port_type,
			        cap_decode->pcie_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, slot_implemented,
			        cap_decode->pcie_capabilities);
		JSON_FIELD_INT(register_fields_ir, interrupt_message_number,
			       cap_decode->pcie_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, undefined,
			        cap_decode->pcie_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, flit_mode_supported,
			        cap_decode->pcie_capabilities);
		json_object_object_add(pcie_capability_ir, "pcie_capabilities",
				       register_fields_ir);

		/*
		 * Device Capabilities Register
		 * Offset: 0x4
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_INT(register_fields_ir, max_payload_size_supported,
			       cap_decode->device_capabilities);
		JSON_FIELD_INT(register_fields_ir, phantom_functions_supported,
			       cap_decode->device_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, extended_tag_field_supported,
			        cap_decode->device_capabilities);
		JSON_FIELD_INT(register_fields_ir,
			       endpoint_l0s_acceptable_latency,
			       cap_decode->device_capabilities);
		JSON_FIELD_INT(register_fields_ir,
			       endpoint_l1_acceptable_latency,
			       cap_decode->device_capabilities);
		JSON_FIELD_INT(register_fields_ir, undefined,
			       cap_decode->device_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, role_based_error_reporting,
			        cap_decode->device_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, err_cor_subclass_capable,
			        cap_decode->device_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, rx_mps_fixed,
			        cap_decode->device_capabilities);
		JSON_FIELD_INT(register_fields_ir,
			       captured_slot_power_limit_value,
			       cap_decode->device_capabilities);
		JSON_FIELD_INT(register_fields_ir,
			       captured_slot_power_limit_scale,
			       cap_decode->device_capabilities);
		JSON_FIELD_BOOL(register_fields_ir,
			        function_level_reset_capability,
			        cap_decode->device_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, mixed_mps_supported,
			        cap_decode->device_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, tee_io_supported,
			        cap_decode->device_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, rsvdp,
			        cap_decode->device_capabilities);
		json_object_object_add(pcie_capability_ir,
				       "device_capabilities",
				       register_fields_ir);

		/*
		 * Device Control Register
		 * Offset: 0x8
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_BOOL(register_fields_ir,
			        correctable_error_reporting_enable,
			        cap_decode->device_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        non_fatal_error_reporting_enable,
			        cap_decode->device_control);
		JSON_FIELD_BOOL(register_fields_ir, fatal_error_reporting_enable,
			        cap_decode->device_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        unsupported_request_reporting_enable,
			        cap_decode->device_control);
		JSON_FIELD_BOOL(register_fields_ir, enable_relaxed_ordering,
			        cap_decode->device_control);
		JSON_FIELD_INT(register_fields_ir, max_payload_size,
			       cap_decode->device_control);
		JSON_FIELD_BOOL(register_fields_ir, extended_tag_field_enable,
			        cap_decode->device_control);
		JSON_FIELD_BOOL(register_fields_ir, phantom_functions_enable,
			        cap_decode->device_control);
		JSON_FIELD_BOOL(register_fields_ir, aux_power_pm_enable,
			        cap_decode->device_control);
		JSON_FIELD_BOOL(register_fields_ir, enable_no_snoop,
			        cap_decode->device_control);
		JSON_FIELD_INT(register_fields_ir, max_read_request_size,
			       cap_decode->device_control);
		JSON_FIELD_BOOL(register_fields_ir, function_level_reset,
			        cap_decode->device_control);
		json_object_object_add(pcie_capability_ir, "device_control",
				       register_fields_ir);

		/*
		 * Device Status Register
		 * Offset: 0xA
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_BOOL(register_fields_ir, correctable_error_detected,
			        cap_decode->device_status);
		JSON_FIELD_BOOL(register_fields_ir, non_fatal_error_detected,
			        cap_decode->device_status);
		JSON_FIELD_BOOL(register_fields_ir, fatal_error_detected,
			        cap_decode->device_status);
		JSON_FIELD_BOOL(register_fields_ir, unsupported_request_detected,
			        cap_decode->device_status);
		JSON_FIELD_BOOL(register_fields_ir, aux_power_detected,
			        cap_decode->device_status);
		JSON_FIELD_BOOL(register_fields_ir, transactions_pending,
			        cap_decode->device_status);
		JSON_FIELD_INT(register_fields_ir, emergency_power_reduction,
			       cap_decode->device_status);
		JSON_FIELD_INT(register_fields_ir, rsvdz,
			       cap_decode->device_status);
		json_object_object_add(pcie_capability_ir, "device_status",
				       register_fields_ir);

		/*
		 * Link Capabilities Register
		 * Offset: 0xC
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_INT(register_fields_ir, max_link_speed,
			       cap_decode->link_capabilities);
		JSON_FIELD_INT(register_fields_ir, maximum_link_width,
			       cap_decode->link_capabilities);
		JSON_FIELD_INT(register_fields_ir, aspm_support,
			       cap_decode->link_capabilities);
		JSON_FIELD_INT(register_fields_ir, l0s_exit_latency,
			       cap_decode->link_capabilities);
		JSON_FIELD_INT(register_fields_ir, l1_exit_latency,
			       cap_decode->link_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, clock_power_management,
			        cap_decode->link_capabilities);
		JSON_FIELD_BOOL(register_fields_ir,
			        surprise_down_error_reporting_capable,
			        cap_decode->link_capabilities);
		JSON_FIELD_BOOL(register_fields_ir,
			        data_link_layer_link_active_reporting_capable,
			        cap_decode->link_capabilities);
		JSON_FIELD_BOOL(register_fields_ir,
			        link_bandwidth_notification_capability,
			        cap_decode->link_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, aspm_optionality_compliance,
			        cap_decode->link_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, rsvdp,
			        cap_decode->link_capabilities);
		JSON_FIELD_INT(register_fields_ir, port_number,
			       cap_decode->link_capabilities);
		json_object_object_add(pcie_capability_ir, "link_capabilities", register_fields_ir);

		/*
		 * Link Control Register
		 * Offset: 0x10
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_INT(register_fields_ir, aspm_control,
			       cap_decode->link_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        ptm_prop_delay_adaptation_interpretation_bit,
			        cap_decode->link_control);
		JSON_FIELD_BOOL(register_fields_ir, read_completion_boundary,
			        cap_decode->link_control);
		JSON_FIELD_BOOL(register_fields_ir, link_disable,
			        cap_decode->link_control);
		JSON_FIELD_BOOL(register_fields_ir, retrain_link,
			        cap_decode->link_control);
		JSON_FIELD_BOOL(register_fields_ir, common_clock_configuration,
			        cap_decode->link_control);
		JSON_FIELD_BOOL(register_fields_ir, extended_synch,
			        cap_decode->link_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        enable_clock_power_management,
			        cap_decode->link_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        hardware_autonomous_width_disable,
			        cap_decode->link_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        link_bandwidth_management_interrupt_enable,
			        cap_decode->link_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        link_autonomous_bandwidth_interrupt_enable,
			        cap_decode->link_control);
		JSON_FIELD_BOOL(register_fields_ir, sris_clocking,
			        cap_decode->link_control);
		JSON_FIELD_BOOL(register_fields_ir, flit_mode_disable,
			        cap_decode->link_control);
		JSON_FIELD_BOOL(register_fields_ir, drs_signaling_control,
			        cap_decode->link_control);
		json_object_object_add(pcie_capability_ir, "link_control", register_fields_ir);

		/*
		 * Link Status Register
		 * Offset: 0x12
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_INT(register_fields_ir, current_link_speed,
			       cap_decode->link_status);
		JSON_FIELD_INT(register_fields_ir, negotiated_link_width,
			       cap_decode->link_status);
		JSON_FIELD_BOOL(register_fields_ir, undefined,
			        cap_decode->link_status);
		JSON_FIELD_BOOL(register_fields_ir, link_training,
			        cap_decode->link_status);
		JSON_FIELD_BOOL(register_fields_ir, slot_clock_configuration,
			        cap_decode->link_status);
		JSON_FIELD_BOOL(register_fields_ir, data_link_layer_link_active,
			        cap_decode->link_status);
		JSON_FIELD_BOOL(register_fields_ir,
			        link_bandwidth_management_status,
			        cap_decode->link_status);
		JSON_FIELD_BOOL(register_fields_ir,
			        link_autonomous_bandwidth_status,
			        cap_decode->link_status);
		json_object_object_add(pcie_capability_ir, "link_status", register_fields_ir);

		/*
		 * Slot Capabilities Register
		 * Offset: 0x14
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_BOOL(register_fields_ir, attention_button_present,
			        cap_decode->slot_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, power_controller_present,
			        cap_decode->slot_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, mrl_sensor_present,
			        cap_decode->slot_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, attention_indicator_present,
			        cap_decode->slot_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, power_indicator_present,
			        cap_decode->slot_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, hot_plug_surprise,
			        cap_decode->slot_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, hot_plug_capable,
			        cap_decode->slot_capabilities);
		JSON_FIELD_INT(register_fields_ir, slot_power_limit_value,
			       cap_decode->slot_capabilities);
		JSON_FIELD_INT(register_fields_ir, slot_power_limit_scale,
			       cap_decode->slot_capabilities);
		JSON_FIELD_BOOL(register_fields_ir,
			        electromechanical_interlock_present,
			        cap_decode->slot_capabilities);
		JSON_FIELD_BOOL(register_fields_ir, no_command_completed_support,
			        cap_decode->slot_capabilities);
		JSON_FIELD_INT(register_fields_ir, physical_slot_number,
			       cap_decode->slot_capabilities);
		json_object_object_add(pcie_capability_ir, "slot_capabilities", register_fields_ir);

		/*
		 * Slot Control Register
		 * Offset: 0x18
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_BOOL(register_fields_ir,
			        attention_button_pressed_enable,
			        cap_decode->slot_control);
		JSON_FIELD_BOOL(register_fields_ir, power_fault_detected_enable,
			        cap_decode->slot_control);
		JSON_FIELD_BOOL(register_fields_ir, mrl_sensor_changed_enable,
			        cap_decode->slot_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        presence_detect_changed_enable,
			        cap_decode->slot_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        command_completed_interrupt_enable,
			        cap_decode->slot_control);
		JSON_FIELD_BOOL(register_fields_ir, hot_plug_interrupt_enable,
			        cap_decode->slot_control);
		JSON_FIELD_INT(register_fields_ir, attention_indicator_control,
			       cap_decode->slot_control);
		JSON_FIELD_INT(register_fields_ir, power_indicator_control,
			       cap_decode->slot_control);
		JSON_FIELD_BOOL(register_fields_ir, power_controller_control,
			        cap_decode->slot_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        electromechanical_interlock_control,
			        cap_decode->slot_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        data_link_layer_state_changed_enable,
			        cap_decode->slot_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        auto_slot_power_limit_disable,
			        cap_decode->slot_control);
		JSON_FIELD_BOOL(register_fields_ir, in_band_pd_disable,
			        cap_decode->slot_control);
		JSON_FIELD_BOOL(register_fields_ir, rsvdp,
			        cap_decode->slot_control);
		json_object_object_add(pcie_capability_ir, "slot_control", register_fields_ir);

		/*
		 * Slot Status Register
		 * Offset: 0x1A
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_BOOL(register_fields_ir, attention_button_pressed,
			        cap_decode->slot_status);
		JSON_FIELD_BOOL(register_fields_ir, power_fault_detected,
			        cap_decode->slot_status);
		JSON_FIELD_BOOL(register_fields_ir, mrl_sensor_changed,
			        cap_decode->slot_status);
		JSON_FIELD_BOOL(register_fields_ir, presence_detect_changed,
			        cap_decode->slot_status);
		JSON_FIELD_BOOL(register_fields_ir, command_completed,
			        cap_decode->slot_status);
		JSON_FIELD_BOOL(register_fields_ir, mrl_sensor_state,
			        cap_decode->slot_status);
		JSON_FIELD_BOOL(register_fields_ir, presence_detect_state,
			        cap_decode->slot_status);
		JSON_FIELD_BOOL(register_fields_ir,
			        electromechanical_interlock_status,
			        cap_decode->slot_status);
		JSON_FIELD_BOOL(register_fields_ir,
			        data_link_layer_state_changed,
			        cap_decode->slot_status);
		JSON_FIELD_INT(register_fields_ir, rsvdz,
			       cap_decode->slot_status);
		json_object_object_add(pcie_capability_ir, "slot_status", register_fields_ir);

		/*
		 * Root Control Register
		 * Offset: 0x1C
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_BOOL(register_fields_ir,
			        system_error_on_correctable_error_enable,
			        cap_decode->root_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        system_error_on_non_fatal_error_enable,
			        cap_decode->root_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        system_error_on_fatal_error_enable,
			        cap_decode->root_control);
		JSON_FIELD_BOOL(register_fields_ir, pme_interrupt_enable,
			        cap_decode->root_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        configuration_rrs_software_visibility_enable,
			        cap_decode->root_control);
		JSON_FIELD_BOOL(register_fields_ir,
			        no_nfm_subtree_below_this_root_port,
			        cap_decode->root_control);
		JSON_FIELD_INT(register_fields_ir, rsvdp,
			       cap_decode->root_control);
		json_object_object_add(pcie_capability_ir, "root_control", register_fields_ir);

		/*
		 * Root Capabilities Register
		 * Offset: 0x1E
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_BOOL(register_fields_ir,
			        configuraton_rrs_software_visibility,
			        cap_decode->root_capabilities);
		JSON_FIELD_INT(register_fields_ir, rsvdp,
			       cap_decode->root_capabilities);
		json_object_object_add(pcie_capability_ir, "root_capabilities", register_fields_ir);

		/*
		 * Root Status Register
		 * Offset: 0x20
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_INT(register_fields_ir, pme_requester_id,
			       cap_decode->root_status);
		JSON_FIELD_BOOL(register_fields_ir, pme_status,
			        cap_decode->root_status);
		JSON_FIELD_BOOL(register_fields_ir, pme_pending,
			        cap_decode->root_status);
		JSON_FIELD_INT(register_fields_ir, rsvdp,
			       cap_decode->root_status);
		json_object_object_add(pcie_capability_ir, "root_status", register_fields_ir);

		/*
		 * Device Capabilities 2 Register
		 * Offset: 0x24
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_INT(register_fields_ir,
			       completion_timeout_ranges_supported,
			       cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir,
			        completion_timeout_disable_supported,
			        cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir, ari_forwarding_supported,
			        cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir, atomic_op_routing_supported,
			        cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir,
			        _32_bit_atomicop_completer_supported,
			        cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir,
			        _64_bit_atomicop_completer_supported,
			        cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir,
			        _128_bit_cas_completer_supported,
			        cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir, no_ro_enabled_pr_pr_passing,
			        cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir, ltr_mechanism_supported,
			        cap_decode->device_capabilities2);
		JSON_FIELD_INT(register_fields_ir, tph_completer_supported,
			       cap_decode->device_capabilities2);
		JSON_FIELD_INT(register_fields_ir, undefined,
			       cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir,
			        _10_bit_tag_completer_supported,
			        cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir,
			        _10_bit_tag_requester_supported,
			        cap_decode->device_capabilities2);
		JSON_FIELD_INT(register_fields_ir, obff_supported,
			       cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir, extended_fmt_field_supported,
			        cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir, end_end_tlp_prefix_supported,
			        cap_decode->device_capabilities2);
		JSON_FIELD_INT(register_fields_ir, max_end_end_tlp_prefixes,
			       cap_decode->device_capabilities2);
		JSON_FIELD_INT(register_fields_ir,
			       emergency_power_reduction_supported,
			       cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir,
			        emergency_power_reduction_init_required,
			        cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir, rsvdp,
			        cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir, dmwr_completer_supported,
			        cap_decode->device_capabilities2);
		JSON_FIELD_INT(register_fields_ir, dmwr_lengths_supported,
			       cap_decode->device_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir, frs_supported,
			        cap_decode->device_capabilities2);
		json_object_object_add(pcie_capability_ir, "device_capabilities2", register_fields_ir);

		/*
		 * Device Control 2 Register
		 * Offset: 0x28
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_INT(register_fields_ir, completion_timeout_value,
			       cap_decode->device_control2);
		JSON_FIELD_BOOL(register_fields_ir, completion_timeout_disable,
			        cap_decode->device_control2);
		JSON_FIELD_BOOL(register_fields_ir, ari_forwarding_enable,
			        cap_decode->device_control2);
		JSON_FIELD_BOOL(register_fields_ir, atomicop_requester_enable,
			        cap_decode->device_control2);
		JSON_FIELD_BOOL(register_fields_ir, atomicop_egress_blocking,
			        cap_decode->device_control2);
		JSON_FIELD_BOOL(register_fields_ir, ido_request_enable,
			        cap_decode->device_control2);
		JSON_FIELD_BOOL(register_fields_ir, ido_completion_enable,
			        cap_decode->device_control2);
		JSON_FIELD_BOOL(register_fields_ir, ltr_mechanism_enable,
			        cap_decode->device_control2);
		JSON_FIELD_BOOL(register_fields_ir,
			        emergency_power_reduction_request,
			        cap_decode->device_control2);
		JSON_FIELD_BOOL(register_fields_ir, _10_bit_tag_requester_enable,
			        cap_decode->device_control2);
		JSON_FIELD_INT(register_fields_ir, obff_enable,
			       cap_decode->device_control2);
		JSON_FIELD_BOOL(register_fields_ir, end_end_tlp_prefix_blocking,
			        cap_decode->device_control2);
		json_object_object_add(pcie_capability_ir, "device_control2", register_fields_ir);

		/*
		 * Device Status 2 Register
		 * Offset: 0x2A
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_INT(register_fields_ir, rsvdz,
			       cap_decode->device_status2);
		json_object_object_add(pcie_capability_ir, "device_status2", register_fields_ir);

		/*
		 * Link Capabilities 2 Register
		 * Offset: 0x2C
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_BOOL(register_fields_ir, rsvdp,
			        cap_decode->link_capabilities2);
		JSON_FIELD_INT(register_fields_ir, supported_link_speeds,
			       cap_decode->link_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir, crosslink_supported,
			        cap_decode->link_capabilities2);
		JSON_FIELD_INT(register_fields_ir,
			       lower_skp_os_generation_supported,
			       cap_decode->link_capabilities2);
		JSON_FIELD_INT(register_fields_ir,
			       lower_skp_os_reception_supported,
			       cap_decode->link_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir,
			        retimer_presence_detect_supported,
			        cap_decode->link_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir,
			        two_retimers_presence_detect_supported,
			        cap_decode->link_capabilities2);
		JSON_FIELD_INT(register_fields_ir, reserved,
			       cap_decode->link_capabilities2);
		JSON_FIELD_BOOL(register_fields_ir, drs_supported,
			        cap_decode->link_capabilities2);
		json_object_object_add(pcie_capability_ir, "link_capabilities2", register_fields_ir);

		/*
		 * Link Control 2 Register
		 * Offset: 0x30
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_INT(register_fields_ir, target_link_speed,
			       cap_decode->link_control2);
		JSON_FIELD_BOOL(register_fields_ir, enter_compliance,
			        cap_decode->link_control2);
		JSON_FIELD_BOOL(register_fields_ir,
			        hardware_autonomous_speed_disable,
			        cap_decode->link_control2);
		JSON_FIELD_BOOL(register_fields_ir, selectable_de_emphasis,
			        cap_decode->link_control2);
		JSON_FIELD_INT(register_fields_ir, transmit_margin,
			       cap_decode->link_control2);
		JSON_FIELD_BOOL(register_fields_ir, enter_modified_compliance,
			        cap_decode->link_control2);
		JSON_FIELD_BOOL(register_fields_ir, compliance_sos,
			        cap_decode->link_control2);
		JSON_FIELD_INT(register_fields_ir, compliance_preset_de_emphasis,
			       cap_decode->link_control2);
		json_object_object_add(pcie_capability_ir, "link_control2", register_fields_ir);

		/*
		 * Link Status 2 Register
		 * Offset: 0x32
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_BOOL(register_fields_ir, current_de_emphasis_level,
			        cap_decode->link_status2);
		JSON_FIELD_BOOL(register_fields_ir, equalization_8gts_complete,
			        cap_decode->link_status2);
		JSON_FIELD_BOOL(register_fields_ir,
			        equalization_8gts_phase1_successful,
			        cap_decode->link_status2);
		JSON_FIELD_BOOL(register_fields_ir,
			        equalization_8gts_phase2_successful,
			        cap_decode->link_status2);
		JSON_FIELD_BOOL(register_fields_ir,
			        equalization_8gts_phase3_successful,
			        cap_decode->link_status2);
		JSON_FIELD_BOOL(register_fields_ir,
			        link_equalization_request_8gts,
			        cap_decode->link_status2);
		JSON_FIELD_BOOL(register_fields_ir, retimer_presence_detected,
			        cap_decode->link_status2);
		JSON_FIELD_BOOL(register_fields_ir,
			        two_retimers_presence_detected,
			        cap_decode->link_status2);
		JSON_FIELD_INT(register_fields_ir, crosslink_resolution,
			       cap_decode->link_status2);
		JSON_FIELD_BOOL(register_fields_ir, flit_mode_status,
			        cap_decode->link_status2);
		JSON_FIELD_BOOL(register_fields_ir, rsvdz,
			        cap_decode->link_status2);
		JSON_FIELD_INT(register_fields_ir, downstream_component_presence,
			       cap_decode->link_status2);
		JSON_FIELD_BOOL(register_fields_ir, drs_message_received,
			        cap_decode->link_status2);
		json_object_object_add(pcie_capability_ir, "link_status2", register_fields_ir);

		/*
		 * Slot Capabilities 2 Register
		 * Offset: 0x34
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_INT(register_fields_ir, rsvdp,
			       cap_decode->slot_capabilities2);
		json_object_object_add(pcie_capability_ir, "slot_capabilities2", register_fields_ir);

		/*
		 * Slot Control 2 Register
		 * Offset: 0x38
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_INT(register_fields_ir, rsvdp,
			       cap_decode->slot_control2);
		json_object_object_add(pcie_capability_ir, "slot_control2", register_fields_ir);

		/*
		 * Slot Status 2 Register
		 * Offset: 0x3A
		 */
		register_fields_ir = json_object_new_object();
		JSON_FIELD_INT(register_fields_ir, rsvdp,
			       cap_decode->slot_status2);
		json_object_object_add(pcie_capability_ir, "slot_status2", register_fields_ir);

		/*
		* STOP STOP STOP
		*/


//		if (cap_decode->pcie_capabilities.capability_version >= 2) {

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
		if (aer_decode->capabilities_control_fields
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
		const json_object *version = obj;
		UINT32 minor = int_to_bcd(json_object_get_int(
			json_object_object_get(version, "minor")));
		UINT32 major = int_to_bcd(json_object_get_int(
			json_object_object_get(version, "major")));
		section_cper->Version = minor + (major << 8);
		add_to_valid_bitfield(&ui64Type, 1);
	}

	//Command/status registers.
	if (json_object_object_get_ex(section, "commandStatus", &obj)) {
		const json_object *command_status = obj;
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
		const json_object *device_id = obj;
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
		const json_object *bridge_control = obj;
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
		const json_object *capability = obj;
		encoded = json_object_object_get(capability, "data");

		decoded = base64_decode(json_object_get_string(encoded),
					json_object_get_string_len(encoded),
					&decoded_len);
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
		const json_object *aer_info = obj;
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
