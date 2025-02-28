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


#define JSON_FIELD_INT(ir, field, decode)                                      \
	add_json_field_int(ir, #field, (decode).field)
#define JSON_FIELD_BOOL(ir, field, decode)                                     \
	add_json_field_bool(ir, #field, (decode).field)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define JSON_FIELD_DICT(ir, field, decode)                                     \
	add_json_field_dict(                                                   \
		ir, #field, (decode).field, field##_dict,                    \
		(sizeof(field##_dict) / sizeof((field##_dict)[0])))

void add_json_field_int(json_object *register_ir, const char *field_name,
			UINT64 value)
{
	json_object *field_ir = json_object_new_object();
	json_object_object_add(register_ir, field_name, field_ir);
	json_object_object_add(field_ir, "value",
			       json_object_new_uint64(value));
}

void add_json_field_bool(json_object *register_ir, const char *field_name,
			 UINT64 value)
{
	json_object_object_add(register_ir, field_name,
			       json_object_new_boolean(value));
}

void add_json_field_dict(json_object *register_ir, const char *field_name,
			 UINT64 value, const char *dict[], size_t dict_size)
{
	json_object *field_ir = json_object_new_object();
	json_object_object_add(register_ir, field_name, field_ir);
	json_object_object_add(field_ir, "value",
			       json_object_new_uint64(value));

	const char *value_name = "UNKNOWN";
	if (value < dict_size && dict[value] != NULL) {
		value_name = dict[value];
	}

	json_object_object_add(field_ir, "name",
			       json_object_new_string(value_name));
}

json_object *pcie_capability_to_ir(EFI_PCIE_ERROR_DATA *pcie_error);
json_object *pcie_aer_to_ir(EFI_PCIE_ERROR_DATA *pcie_error);

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
	// "2" postfixed only valid when pcie_capabilities_fields.cap_version >= 2
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
	capability_header_t capability_header;
	uncorrectable_error_status_t uncorrectable_error_status;
	uncorrectable_error_mask_t uncorrectable_error_mask;
	uncorrectable_error_severity_t uncorrectable_error_severity;
	correctable_error_status_t correctable_error_status;
	correctable_error_mask_t correctable_error_mask;
	advanced_error_capabilities_and_control_t
		advanced_error_capabilities_and_control;
	UINT32 tlp_header0;
	UINT32 tlp_header1;
	UINT32 tlp_header2;
	UINT32 tlp_header3;
	root_error_command_t root_error_command;
	root_error_status_t root_error_status;
	error_source_id_t error_source_id;
	union {
		struct { // Non-flit mode TLP prefix logs
			UINT32 tlp_prefix_log0;
			UINT32 tlp_prefix_log1;
			UINT32 tlp_prefix_log2;
			UINT32 tlp_prefix_log3;
		} __attribute__((packed));
		struct { // Flit mode TLP header logs
			UINT32 tlp_header4;
			UINT32 tlp_header5;
			UINT32 tlp_header6;
			UINT32 tlp_header7;
			UINT32 tlp_header8;
			UINT32 tlp_header9;
			UINT32 tlp_header10;
			UINT32 tlp_header11;
			UINT32 tlp_header12;
			UINT32 tlp_header13;
		} __attribute__((packed));
	} __attribute__((packed));
} __attribute__((packed));

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
	if (isvalid_prop_to_ir(&ui64Type, 6)) {
		json_object_object_add(section_ir, "capabilityStructure",
				       pcie_capability_to_ir(pcie_error));
	}

	//AER information.
	if (isvalid_prop_to_ir(&ui64Type, 7)) {
		json_object_object_add(section_ir, "aerInfo",
				       pcie_aer_to_ir(pcie_error));
	}

	return section_ir;
}

//Converts PCIe Capability Structure section into JSON IR.
json_object *pcie_capability_to_ir(EFI_PCIE_ERROR_DATA *pcie_error)
{
	int32_t encoded_len = 0;
	char *encoded = NULL;
	json_object *pcie_capability_ir = json_object_new_object();

	encoded = base64_encode((UINT8 *)pcie_error->Capability.PcieCap, 60,
				&encoded_len);
	if (encoded == NULL) {
		printf("Failed to allocate encode output buffer. \n");
	} else {
		json_object_object_add(pcie_capability_ir, "data",
				       json_object_new_string_len(encoded,
								  encoded_len));
		free(encoded);
	}

	json_object *fields_ir;
	struct capability_registers *cap_decode;
	cap_decode =
		(struct capability_registers *)&pcie_error->Capability.PcieCap;

	/*
	 * PCI Express Capability Structure Header
	 * Offset: 0x0
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, capability_id,
		       cap_decode->pcie_capability_header);
	JSON_FIELD_INT(fields_ir, next_capability_pointer,
		       cap_decode->pcie_capability_header);
	json_object_object_add(pcie_capability_ir, "pcie_capability_header",
			       fields_ir);

	/*
	 * PCI Express Capabilities Register
	 * Offset: 0x2
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, capability_version,
		       cap_decode->pcie_capabilities);
	JSON_FIELD_DICT(fields_ir, device_port_type,
			cap_decode->pcie_capabilities);
	JSON_FIELD_BOOL(fields_ir, slot_implemented,
			cap_decode->pcie_capabilities);
	JSON_FIELD_INT(fields_ir, interrupt_message_number,
		       cap_decode->pcie_capabilities);
	JSON_FIELD_BOOL(fields_ir, undefined, cap_decode->pcie_capabilities);
	JSON_FIELD_BOOL(fields_ir, flit_mode_supported,
			cap_decode->pcie_capabilities);
	json_object_object_add(pcie_capability_ir, "pcie_capabilities",
			       fields_ir);

	/*
	 * Device Capabilities Register
	 * Offset: 0x4
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, max_payload_size_supported,
		       cap_decode->device_capabilities);
	JSON_FIELD_INT(fields_ir, phantom_functions_supported,
		       cap_decode->device_capabilities);
	JSON_FIELD_BOOL(fields_ir, extended_tag_field_supported,
			cap_decode->device_capabilities);
	JSON_FIELD_INT(fields_ir, endpoint_l0s_acceptable_latency,
		       cap_decode->device_capabilities);
	JSON_FIELD_INT(fields_ir, endpoint_l1_acceptable_latency,
		       cap_decode->device_capabilities);
	JSON_FIELD_INT(fields_ir, undefined, cap_decode->device_capabilities);
	JSON_FIELD_BOOL(fields_ir, role_based_error_reporting,
			cap_decode->device_capabilities);
	JSON_FIELD_BOOL(fields_ir, err_cor_subclass_capable,
			cap_decode->device_capabilities);
	JSON_FIELD_BOOL(fields_ir, rx_mps_fixed,
			cap_decode->device_capabilities);
	JSON_FIELD_INT(fields_ir, captured_slot_power_limit_value,
		       cap_decode->device_capabilities);
	JSON_FIELD_INT(fields_ir, captured_slot_power_limit_scale,
		       cap_decode->device_capabilities);
	JSON_FIELD_BOOL(fields_ir, function_level_reset_capability,
			cap_decode->device_capabilities);
	JSON_FIELD_BOOL(fields_ir, mixed_mps_supported,
			cap_decode->device_capabilities);
	JSON_FIELD_BOOL(fields_ir, tee_io_supported,
			cap_decode->device_capabilities);
	JSON_FIELD_BOOL(fields_ir, rsvdp, cap_decode->device_capabilities);
	json_object_object_add(pcie_capability_ir, "device_capabilities",
			       fields_ir);

	/*
	 * Device Control Register
	 * Offset: 0x8
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, correctable_error_reporting_enable,
			cap_decode->device_control);
	JSON_FIELD_BOOL(fields_ir, non_fatal_error_reporting_enable,
			cap_decode->device_control);
	JSON_FIELD_BOOL(fields_ir, fatal_error_reporting_enable,
			cap_decode->device_control);
	JSON_FIELD_BOOL(fields_ir, unsupported_request_reporting_enable,
			cap_decode->device_control);
	JSON_FIELD_BOOL(fields_ir, enable_relaxed_ordering,
			cap_decode->device_control);
	JSON_FIELD_INT(fields_ir, max_payload_size, cap_decode->device_control);
	JSON_FIELD_BOOL(fields_ir, extended_tag_field_enable,
			cap_decode->device_control);
	JSON_FIELD_BOOL(fields_ir, phantom_functions_enable,
			cap_decode->device_control);
	JSON_FIELD_BOOL(fields_ir, aux_power_pm_enable,
			cap_decode->device_control);
	JSON_FIELD_BOOL(fields_ir, enable_no_snoop, cap_decode->device_control);
	JSON_FIELD_INT(fields_ir, max_read_request_size,
		       cap_decode->device_control);
	JSON_FIELD_BOOL(fields_ir, function_level_reset,
			cap_decode->device_control);
	json_object_object_add(pcie_capability_ir, "device_control", fields_ir);

	/*
	 * Device Status Register
	 * Offset: 0xA
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, correctable_error_detected,
			cap_decode->device_status);
	JSON_FIELD_BOOL(fields_ir, non_fatal_error_detected,
			cap_decode->device_status);
	JSON_FIELD_BOOL(fields_ir, fatal_error_detected,
			cap_decode->device_status);
	JSON_FIELD_BOOL(fields_ir, unsupported_request_detected,
			cap_decode->device_status);
	JSON_FIELD_BOOL(fields_ir, aux_power_detected,
			cap_decode->device_status);
	JSON_FIELD_BOOL(fields_ir, transactions_pending,
			cap_decode->device_status);
	JSON_FIELD_INT(fields_ir, emergency_power_reduction,
		       cap_decode->device_status);
	JSON_FIELD_INT(fields_ir, rsvdz, cap_decode->device_status);
	json_object_object_add(pcie_capability_ir, "device_status", fields_ir);

	/*
	 * Link Capabilities Register
	 * Offset: 0xC
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, max_link_speed,
		       cap_decode->link_capabilities);
	JSON_FIELD_INT(fields_ir, maximum_link_width,
		       cap_decode->link_capabilities);
	JSON_FIELD_INT(fields_ir, aspm_support, cap_decode->link_capabilities);
	JSON_FIELD_INT(fields_ir, l0s_exit_latency,
		       cap_decode->link_capabilities);
	JSON_FIELD_INT(fields_ir, l1_exit_latency,
		       cap_decode->link_capabilities);
	JSON_FIELD_BOOL(fields_ir, clock_power_management,
			cap_decode->link_capabilities);
	JSON_FIELD_BOOL(fields_ir, surprise_down_error_reporting_capable,
			cap_decode->link_capabilities);
	JSON_FIELD_BOOL(fields_ir,
			data_link_layer_link_active_reporting_capable,
			cap_decode->link_capabilities);
	JSON_FIELD_BOOL(fields_ir, link_bandwidth_notification_capability,
			cap_decode->link_capabilities);
	JSON_FIELD_BOOL(fields_ir, aspm_optionality_compliance,
			cap_decode->link_capabilities);
	JSON_FIELD_BOOL(fields_ir, rsvdp, cap_decode->link_capabilities);
	JSON_FIELD_INT(fields_ir, port_number, cap_decode->link_capabilities);
	json_object_object_add(pcie_capability_ir, "link_capabilities",
			       fields_ir);

	/*
	 * Link Control Register
	 * Offset: 0x10
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, aspm_control, cap_decode->link_control);
	JSON_FIELD_BOOL(fields_ir, ptm_prop_delay_adaptation_interpretation_bit,
			cap_decode->link_control);
	JSON_FIELD_BOOL(fields_ir, read_completion_boundary,
			cap_decode->link_control);
	JSON_FIELD_BOOL(fields_ir, link_disable, cap_decode->link_control);
	JSON_FIELD_BOOL(fields_ir, retrain_link, cap_decode->link_control);
	JSON_FIELD_BOOL(fields_ir, common_clock_configuration,
			cap_decode->link_control);
	JSON_FIELD_BOOL(fields_ir, extended_synch, cap_decode->link_control);
	JSON_FIELD_BOOL(fields_ir, enable_clock_power_management,
			cap_decode->link_control);
	JSON_FIELD_BOOL(fields_ir, hardware_autonomous_width_disable,
			cap_decode->link_control);
	JSON_FIELD_BOOL(fields_ir, link_bandwidth_management_interrupt_enable,
			cap_decode->link_control);
	JSON_FIELD_BOOL(fields_ir, link_autonomous_bandwidth_interrupt_enable,
			cap_decode->link_control);
	JSON_FIELD_BOOL(fields_ir, sris_clocking, cap_decode->link_control);
	JSON_FIELD_BOOL(fields_ir, flit_mode_disable, cap_decode->link_control);
	JSON_FIELD_BOOL(fields_ir, drs_signaling_control,
			cap_decode->link_control);
	json_object_object_add(pcie_capability_ir, "link_control", fields_ir);

	/*
	 * Link Status Register
	 * Offset: 0x12
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, current_link_speed, cap_decode->link_status);
	JSON_FIELD_INT(fields_ir, negotiated_link_width,
		       cap_decode->link_status);
	JSON_FIELD_BOOL(fields_ir, undefined, cap_decode->link_status);
	JSON_FIELD_BOOL(fields_ir, link_training, cap_decode->link_status);
	JSON_FIELD_BOOL(fields_ir, slot_clock_configuration,
			cap_decode->link_status);
	JSON_FIELD_BOOL(fields_ir, data_link_layer_link_active,
			cap_decode->link_status);
	JSON_FIELD_BOOL(fields_ir, link_bandwidth_management_status,
			cap_decode->link_status);
	JSON_FIELD_BOOL(fields_ir, link_autonomous_bandwidth_status,
			cap_decode->link_status);
	json_object_object_add(pcie_capability_ir, "link_status", fields_ir);

	/*
	 * Slot Capabilities Register
	 * Offset: 0x14
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, attention_button_present,
			cap_decode->slot_capabilities);
	JSON_FIELD_BOOL(fields_ir, power_controller_present,
			cap_decode->slot_capabilities);
	JSON_FIELD_BOOL(fields_ir, mrl_sensor_present,
			cap_decode->slot_capabilities);
	JSON_FIELD_BOOL(fields_ir, attention_indicator_present,
			cap_decode->slot_capabilities);
	JSON_FIELD_BOOL(fields_ir, power_indicator_present,
			cap_decode->slot_capabilities);
	JSON_FIELD_BOOL(fields_ir, hot_plug_surprise,
			cap_decode->slot_capabilities);
	JSON_FIELD_BOOL(fields_ir, hot_plug_capable,
			cap_decode->slot_capabilities);
	JSON_FIELD_INT(fields_ir, slot_power_limit_value,
		       cap_decode->slot_capabilities);
	JSON_FIELD_INT(fields_ir, slot_power_limit_scale,
		       cap_decode->slot_capabilities);
	JSON_FIELD_BOOL(fields_ir, electromechanical_interlock_present,
			cap_decode->slot_capabilities);
	JSON_FIELD_BOOL(fields_ir, no_command_completed_support,
			cap_decode->slot_capabilities);
	JSON_FIELD_INT(fields_ir, physical_slot_number,
		       cap_decode->slot_capabilities);
	json_object_object_add(pcie_capability_ir, "slot_capabilities",
			       fields_ir);

	/*
	 * Slot Control Register
	 * Offset: 0x18
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, attention_button_pressed_enable,
			cap_decode->slot_control);
	JSON_FIELD_BOOL(fields_ir, power_fault_detected_enable,
			cap_decode->slot_control);
	JSON_FIELD_BOOL(fields_ir, mrl_sensor_changed_enable,
			cap_decode->slot_control);
	JSON_FIELD_BOOL(fields_ir, presence_detect_changed_enable,
			cap_decode->slot_control);
	JSON_FIELD_BOOL(fields_ir, command_completed_interrupt_enable,
			cap_decode->slot_control);
	JSON_FIELD_BOOL(fields_ir, hot_plug_interrupt_enable,
			cap_decode->slot_control);
	JSON_FIELD_INT(fields_ir, attention_indicator_control,
		       cap_decode->slot_control);
	JSON_FIELD_INT(fields_ir, power_indicator_control,
		       cap_decode->slot_control);
	JSON_FIELD_BOOL(fields_ir, power_controller_control,
			cap_decode->slot_control);
	JSON_FIELD_BOOL(fields_ir, electromechanical_interlock_control,
			cap_decode->slot_control);
	JSON_FIELD_BOOL(fields_ir, data_link_layer_state_changed_enable,
			cap_decode->slot_control);
	JSON_FIELD_BOOL(fields_ir, auto_slot_power_limit_disable,
			cap_decode->slot_control);
	JSON_FIELD_BOOL(fields_ir, in_band_pd_disable,
			cap_decode->slot_control);
	JSON_FIELD_BOOL(fields_ir, rsvdp, cap_decode->slot_control);
	json_object_object_add(pcie_capability_ir, "slot_control", fields_ir);

	/*
	 * Slot Status Register
	 * Offset: 0x1A
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, attention_button_pressed,
			cap_decode->slot_status);
	JSON_FIELD_BOOL(fields_ir, power_fault_detected,
			cap_decode->slot_status);
	JSON_FIELD_BOOL(fields_ir, mrl_sensor_changed, cap_decode->slot_status);
	JSON_FIELD_BOOL(fields_ir, presence_detect_changed,
			cap_decode->slot_status);
	JSON_FIELD_BOOL(fields_ir, command_completed, cap_decode->slot_status);
	JSON_FIELD_BOOL(fields_ir, mrl_sensor_state, cap_decode->slot_status);
	JSON_FIELD_BOOL(fields_ir, presence_detect_state,
			cap_decode->slot_status);
	JSON_FIELD_BOOL(fields_ir, electromechanical_interlock_status,
			cap_decode->slot_status);
	JSON_FIELD_BOOL(fields_ir, data_link_layer_state_changed,
			cap_decode->slot_status);
	JSON_FIELD_INT(fields_ir, rsvdz, cap_decode->slot_status);
	json_object_object_add(pcie_capability_ir, "slot_status", fields_ir);

	/*
	 * Root Control Register
	 * Offset: 0x1C
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, system_error_on_correctable_error_enable,
			cap_decode->root_control);
	JSON_FIELD_BOOL(fields_ir, system_error_on_non_fatal_error_enable,
			cap_decode->root_control);
	JSON_FIELD_BOOL(fields_ir, system_error_on_fatal_error_enable,
			cap_decode->root_control);
	JSON_FIELD_BOOL(fields_ir, pme_interrupt_enable,
			cap_decode->root_control);
	JSON_FIELD_BOOL(fields_ir, configuration_rrs_software_visibility_enable,
			cap_decode->root_control);
	JSON_FIELD_BOOL(fields_ir, no_nfm_subtree_below_this_root_port,
			cap_decode->root_control);
	JSON_FIELD_INT(fields_ir, rsvdp, cap_decode->root_control);
	json_object_object_add(pcie_capability_ir, "root_control", fields_ir);

	/*
	 * Root Capabilities Register
	 * Offset: 0x1E
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, configuraton_rrs_software_visibility,
			cap_decode->root_capabilities);
	JSON_FIELD_INT(fields_ir, rsvdp, cap_decode->root_capabilities);
	json_object_object_add(pcie_capability_ir, "root_capabilities",
			       fields_ir);

	/*
	 * Root Status Register
	 * Offset: 0x20
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, pme_requester_id, cap_decode->root_status);
	JSON_FIELD_BOOL(fields_ir, pme_status, cap_decode->root_status);
	JSON_FIELD_BOOL(fields_ir, pme_pending, cap_decode->root_status);
	JSON_FIELD_INT(fields_ir, rsvdp, cap_decode->root_status);
	json_object_object_add(pcie_capability_ir, "root_status", fields_ir);

	if (cap_decode->pcie_capabilities.capability_version < 2) {
		return pcie_capability_ir;
	}

	/*
	 * Device Capabilities 2 Register
	 * Offset: 0x24
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, completion_timeout_ranges_supported,
		       cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, completion_timeout_disable_supported,
			cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, ari_forwarding_supported,
			cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, atomic_op_routing_supported,
			cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, _32_bit_atomicop_completer_supported,
			cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, _64_bit_atomicop_completer_supported,
			cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, _128_bit_cas_completer_supported,
			cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, no_ro_enabled_pr_pr_passing,
			cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, ltr_mechanism_supported,
			cap_decode->device_capabilities2);
	JSON_FIELD_INT(fields_ir, tph_completer_supported,
		       cap_decode->device_capabilities2);
	JSON_FIELD_INT(fields_ir, undefined, cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, _10_bit_tag_completer_supported,
			cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, _10_bit_tag_requester_supported,
			cap_decode->device_capabilities2);
	JSON_FIELD_INT(fields_ir, obff_supported,
		       cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, extended_fmt_field_supported,
			cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, end_end_tlp_prefix_supported,
			cap_decode->device_capabilities2);
	JSON_FIELD_INT(fields_ir, max_end_end_tlp_prefixes,
		       cap_decode->device_capabilities2);
	JSON_FIELD_INT(fields_ir, emergency_power_reduction_supported,
		       cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, emergency_power_reduction_init_required,
			cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, rsvdp, cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, dmwr_completer_supported,
			cap_decode->device_capabilities2);
	JSON_FIELD_INT(fields_ir, dmwr_lengths_supported,
		       cap_decode->device_capabilities2);
	JSON_FIELD_BOOL(fields_ir, frs_supported,
			cap_decode->device_capabilities2);
	json_object_object_add(pcie_capability_ir, "device_capabilities2",
			       fields_ir);

	/*
	 * Device Control 2 Register
	 * Offset: 0x28
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, completion_timeout_value,
		       cap_decode->device_control2);
	JSON_FIELD_BOOL(fields_ir, completion_timeout_disable,
			cap_decode->device_control2);
	JSON_FIELD_BOOL(fields_ir, ari_forwarding_enable,
			cap_decode->device_control2);
	JSON_FIELD_BOOL(fields_ir, atomicop_requester_enable,
			cap_decode->device_control2);
	JSON_FIELD_BOOL(fields_ir, atomicop_egress_blocking,
			cap_decode->device_control2);
	JSON_FIELD_BOOL(fields_ir, ido_request_enable,
			cap_decode->device_control2);
	JSON_FIELD_BOOL(fields_ir, ido_completion_enable,
			cap_decode->device_control2);
	JSON_FIELD_BOOL(fields_ir, ltr_mechanism_enable,
			cap_decode->device_control2);
	JSON_FIELD_BOOL(fields_ir, emergency_power_reduction_request,
			cap_decode->device_control2);
	JSON_FIELD_BOOL(fields_ir, _10_bit_tag_requester_enable,
			cap_decode->device_control2);
	JSON_FIELD_INT(fields_ir, obff_enable, cap_decode->device_control2);
	JSON_FIELD_BOOL(fields_ir, end_end_tlp_prefix_blocking,
			cap_decode->device_control2);
	json_object_object_add(pcie_capability_ir, "device_control2",
			       fields_ir);

	/*
	 * Device Status 2 Register
	 * Offset: 0x2A
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, rsvdz, cap_decode->device_status2);
	json_object_object_add(pcie_capability_ir, "device_status2", fields_ir);

	/*
	 * Link Capabilities 2 Register
	 * Offset: 0x2C
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, rsvdp, cap_decode->link_capabilities2);
	JSON_FIELD_INT(fields_ir, supported_link_speeds,
		       cap_decode->link_capabilities2);
	JSON_FIELD_BOOL(fields_ir, crosslink_supported,
			cap_decode->link_capabilities2);
	JSON_FIELD_INT(fields_ir, lower_skp_os_generation_supported,
		       cap_decode->link_capabilities2);
	JSON_FIELD_INT(fields_ir, lower_skp_os_reception_supported,
		       cap_decode->link_capabilities2);
	JSON_FIELD_BOOL(fields_ir, retimer_presence_detect_supported,
			cap_decode->link_capabilities2);
	JSON_FIELD_BOOL(fields_ir, two_retimers_presence_detect_supported,
			cap_decode->link_capabilities2);
	JSON_FIELD_INT(fields_ir, reserved, cap_decode->link_capabilities2);
	JSON_FIELD_BOOL(fields_ir, drs_supported,
			cap_decode->link_capabilities2);
	json_object_object_add(pcie_capability_ir, "link_capabilities2",
			       fields_ir);

	/*
	 * Link Control 2 Register
	 * Offset: 0x30
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, target_link_speed, cap_decode->link_control2);
	JSON_FIELD_BOOL(fields_ir, enter_compliance, cap_decode->link_control2);
	JSON_FIELD_BOOL(fields_ir, hardware_autonomous_speed_disable,
			cap_decode->link_control2);
	JSON_FIELD_BOOL(fields_ir, selectable_de_emphasis,
			cap_decode->link_control2);
	JSON_FIELD_INT(fields_ir, transmit_margin, cap_decode->link_control2);
	JSON_FIELD_BOOL(fields_ir, enter_modified_compliance,
			cap_decode->link_control2);
	JSON_FIELD_BOOL(fields_ir, compliance_sos, cap_decode->link_control2);
	JSON_FIELD_INT(fields_ir, compliance_preset_de_emphasis,
		       cap_decode->link_control2);
	json_object_object_add(pcie_capability_ir, "link_control2", fields_ir);

	/*
	 * Link Status 2 Register
	 * Offset: 0x32
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, current_de_emphasis_level,
		       cap_decode->link_status2);
	JSON_FIELD_BOOL(fields_ir, equalization_8gts_complete,
			cap_decode->link_status2);
	JSON_FIELD_BOOL(fields_ir, equalization_8gts_phase1_successful,
			cap_decode->link_status2);
	JSON_FIELD_BOOL(fields_ir, equalization_8gts_phase2_successful,
			cap_decode->link_status2);
	JSON_FIELD_BOOL(fields_ir, equalization_8gts_phase3_successful,
			cap_decode->link_status2);
	JSON_FIELD_BOOL(fields_ir, link_equalization_request_8gts,
			cap_decode->link_status2);
	JSON_FIELD_BOOL(fields_ir, retimer_presence_detected,
			cap_decode->link_status2);
	JSON_FIELD_BOOL(fields_ir, two_retimers_presence_detected,
			cap_decode->link_status2);
	JSON_FIELD_INT(fields_ir, crosslink_resolution,
		       cap_decode->link_status2);
	JSON_FIELD_BOOL(fields_ir, flit_mode_status, cap_decode->link_status2);
	JSON_FIELD_BOOL(fields_ir, rsvdz, cap_decode->link_status2);
	JSON_FIELD_INT(fields_ir, downstream_component_presence,
		       cap_decode->link_status2);
	JSON_FIELD_BOOL(fields_ir, drs_message_received,
			cap_decode->link_status2);
	json_object_object_add(pcie_capability_ir, "link_status2", fields_ir);

	/*
	 * Slot Capabilities 2 Register
	 * Offset: 0x34
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, rsvdp, cap_decode->slot_capabilities2);
	json_object_object_add(pcie_capability_ir, "slot_capabilities2",
			       fields_ir);

	/*
	 * Slot Control 2 Register
	 * Offset: 0x38
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, rsvdp, cap_decode->slot_control2);
	json_object_object_add(pcie_capability_ir, "slot_control2", fields_ir);

	/*
	 * Slot Status 2 Register
	 * Offset: 0x3A
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, rsvdp, cap_decode->slot_status2);
	json_object_object_add(pcie_capability_ir, "slot_status2", fields_ir);

	return pcie_capability_ir;
}

//Converts PCIe Capability Structure section into JSON IR.
json_object *pcie_aer_to_ir(EFI_PCIE_ERROR_DATA *pcie_error)
{
	int32_t encoded_len = 0;
	char *encoded = NULL;
	json_object *aer_capability_ir = json_object_new_object();

	encoded = base64_encode((UINT8 *)pcie_error->AerInfo.PcieAer, 96,
				&encoded_len);
	if (encoded == NULL) {
		printf("Failed to allocate encode output buffer. \n");
	} else {
		json_object_object_add(aer_capability_ir, "data",
				       json_object_new_string_len(encoded,
								  encoded_len));
		free(encoded);
	}

	json_object *fields_ir;

	struct aer_info_registers *aer_decode;
	aer_decode = (struct aer_info_registers *)&pcie_error->AerInfo.PcieAer;

	/*
	 * AER Capability Header
	 * Offset: 0x0
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, capability_id, aer_decode->capability_header);
	JSON_FIELD_INT(fields_ir, capability_version,
		       aer_decode->capability_header);
	JSON_FIELD_INT(fields_ir, next_capability_offset,
		       aer_decode->capability_header);
	json_object_object_add(aer_capability_ir, "capability_header",
			       fields_ir);

	/*
	 * Uncorrectable Error Status Register
	 * Offset: 0x4
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, undefined,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_INT(fields_ir, rsvdz1,
		       aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, data_link_protocol_error_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, surprise_down_error_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_INT(fields_ir, rsvdz2,
		       aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, poisoned_tlp_received,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, flow_control_protocol_error_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, completion_timeout_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, completer_abort_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, unexpected_completion_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, receiver_overflow_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, malformed_tlp_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, ecrc_error_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, unsupported_request_error_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, acs_violation_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, uncorrectable_internal_error_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, mc_blocked_tlp_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, atomicop_egress_blocked_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, tlp_prefix_blocked_error_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, poisoned_tlp_egress_blocked_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, dmwr_request_egress_blocked_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, ide_check_failed_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, misrouted_ide_tlp_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, pcrc_check_failed_status,
			aer_decode->uncorrectable_error_status);
	JSON_FIELD_BOOL(fields_ir, tlp_translation_egress_blocked_status,
			aer_decode->uncorrectable_error_status);
	json_object_object_add(aer_capability_ir, "uncorrectable_error_status",
			       fields_ir);

	/*
	 * Uncorrectable Error Mask Register
	 * Offset: 0x8
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, undefined,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_INT(fields_ir, rsvdz1, aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, data_link_protocol_error_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, surprise_down_error_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_INT(fields_ir, rsvdz2, aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, poisoned_tlp_received_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, flow_control_protocol_error_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, completion_timeout_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, completer_abort_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, unexpected_completion_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, receiver_overflow_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, malformed_tlp_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, ecrc_error_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, unsupported_request_error_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, acs_violation_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, uncorrectable_internal_error_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, mc_blocked_tlp_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, atomicop_egress_blocked_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, tlp_prefix_blocked_error_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, poisoned_tlp_egress_blocked_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, dmwr_request_egress_blocked_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, ide_check_failed_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, misrouted_ide_tlp_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, pcrc_check_failed_mask,
			aer_decode->uncorrectable_error_mask);
	JSON_FIELD_BOOL(fields_ir, tlp_translation_egress_blocked_mask,
			aer_decode->uncorrectable_error_mask);
	json_object_object_add(aer_capability_ir, "uncorrectable_error_mask",
			       fields_ir);

	/*
	 * Uncorrectable Error Severity Register
	 * Offset: 0xC
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, undefined,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_INT(fields_ir, rsvdz1,
		       aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, data_link_protocol_error_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, surprise_down_error_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_INT(fields_ir, rsvdz2,
		       aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, poisoned_tlp_received_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, flow_control_protocol_error_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, completion_timeout_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, completer_abort_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, unexpected_completion_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, receiver_overflow_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, malformed_tlp_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, ecrc_error_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, unsupported_request_error_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, acs_violation_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, uncorrectable_internal_error_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, mc_blocked_tlp_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, atomicop_egress_blocked_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, tlp_prefix_blocked_error_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, poisoned_tlp_egress_blocked_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, dmwr_request_egress_blocked_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, ide_check_failed_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, misrouted_ide_tlp_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, pcrc_check_failed_severity,
			aer_decode->uncorrectable_error_severity);
	JSON_FIELD_BOOL(fields_ir, tlp_translation_egress_blocked_severity,
			aer_decode->uncorrectable_error_severity);
	json_object_object_add(aer_capability_ir,
			       "uncorrectable_error_severity", fields_ir);

	/*
	 * Correctable Error Status Register
	 * Offset: 0x10
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, receiver_error_status,
			aer_decode->correctable_error_status);
	JSON_FIELD_INT(fields_ir, rsvdz1, aer_decode->correctable_error_status);
	JSON_FIELD_BOOL(fields_ir, bad_tlp_status,
			aer_decode->correctable_error_status);
	JSON_FIELD_BOOL(fields_ir, bad_dllp_status,
			aer_decode->correctable_error_status);
	JSON_FIELD_BOOL(fields_ir, replay_num_rollover_status,
			aer_decode->correctable_error_status);
	JSON_FIELD_INT(fields_ir, rsvdz2, aer_decode->correctable_error_status);
	JSON_FIELD_BOOL(fields_ir, replay_timer_timeout_status,
			aer_decode->correctable_error_status);
	JSON_FIELD_BOOL(fields_ir, advisory_non_fatal_error_status,
			aer_decode->correctable_error_status);
	JSON_FIELD_BOOL(fields_ir, corrected_internal_error_status,
			aer_decode->correctable_error_status);
	JSON_FIELD_BOOL(fields_ir, header_log_overflow_status,
			aer_decode->correctable_error_status);
	JSON_FIELD_INT(fields_ir, rsvdz3, aer_decode->correctable_error_status);
	json_object_object_add(aer_capability_ir, "correctable_error_status",
			       fields_ir);

	/*
	 * Correctable Error Mask Register
	 * Offset: 0x14
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, receiver_error_mask,
			aer_decode->correctable_error_mask);
	JSON_FIELD_INT(fields_ir, rsvdz1, aer_decode->correctable_error_mask);
	JSON_FIELD_BOOL(fields_ir, bad_tlp_mask,
			aer_decode->correctable_error_mask);
	JSON_FIELD_BOOL(fields_ir, bad_dllp_mask,
			aer_decode->correctable_error_mask);
	JSON_FIELD_BOOL(fields_ir, replay_num_rollover_mask,
			aer_decode->correctable_error_mask);
	JSON_FIELD_INT(fields_ir, rsvdz2, aer_decode->correctable_error_mask);
	JSON_FIELD_BOOL(fields_ir, replay_timer_timeout_mask,
			aer_decode->correctable_error_mask);
	JSON_FIELD_BOOL(fields_ir, advisory_non_fatal_error_mask,
			aer_decode->correctable_error_mask);
	JSON_FIELD_BOOL(fields_ir, corrected_internal_error_mask,
			aer_decode->correctable_error_mask);
	JSON_FIELD_BOOL(fields_ir, header_log_overflow_mask,
			aer_decode->correctable_error_mask);
	JSON_FIELD_INT(fields_ir, rsvdz3, aer_decode->correctable_error_mask);
	json_object_object_add(aer_capability_ir, "correctable_error_mask",
			       fields_ir);

	/*
	 * Advanced Error Capabilities and Control Register
	 * Offset: 0x18
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, first_error_pointer,
		       aer_decode->advanced_error_capabilities_and_control);
	JSON_FIELD_BOOL(fields_ir, ecrc_generation_capable,
			aer_decode->advanced_error_capabilities_and_control);
	JSON_FIELD_BOOL(fields_ir, ecrc_generation_enable,
			aer_decode->advanced_error_capabilities_and_control);
	JSON_FIELD_BOOL(fields_ir, ecrc_check_capable,
			aer_decode->advanced_error_capabilities_and_control);
	JSON_FIELD_BOOL(fields_ir, ecrc_check_enable,
			aer_decode->advanced_error_capabilities_and_control);
	JSON_FIELD_BOOL(fields_ir, multiple_header_recording_capable,
			aer_decode->advanced_error_capabilities_and_control);
	JSON_FIELD_BOOL(fields_ir, multiple_header_recording_enable,
			aer_decode->advanced_error_capabilities_and_control);
	JSON_FIELD_BOOL(fields_ir, tlp_prefix_log_present,
			aer_decode->advanced_error_capabilities_and_control);
	JSON_FIELD_BOOL(fields_ir, completion_timeout_prefix_header_log_capable,
			aer_decode->advanced_error_capabilities_and_control);
	JSON_FIELD_INT(fields_ir, header_log_size,
		       aer_decode->advanced_error_capabilities_and_control);
	JSON_FIELD_BOOL(fields_ir, logged_tlp_was_flit_mode,
			aer_decode->advanced_error_capabilities_and_control);
	JSON_FIELD_INT(fields_ir, logged_tlp_size,
		       aer_decode->advanced_error_capabilities_and_control);
	JSON_FIELD_INT(fields_ir, rsvdp,
		       aer_decode->advanced_error_capabilities_and_control);
	json_object_object_add(aer_capability_ir,
			       "advanced_error_capabilities_and_control",
			       fields_ir);

	/*
	 * Root Error Command Register
	 * Offset: 0x2C
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, correctable_error_reporting_enable,
			aer_decode->root_error_command);
	JSON_FIELD_BOOL(fields_ir, non_fatal_error_reporting_enable,
			aer_decode->root_error_command);
	JSON_FIELD_BOOL(fields_ir, fatal_error_reporting_enable,
			aer_decode->root_error_command);
	JSON_FIELD_INT(fields_ir, rsvdp, aer_decode->root_error_command);
	json_object_object_add(aer_capability_ir, "root_error_command",
			       fields_ir);

	/*
	 * Root Error Status Register
	 * Offset: 0x30
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_BOOL(fields_ir, err_cor_received,
			aer_decode->root_error_status);
	JSON_FIELD_BOOL(fields_ir, multiple_err_cor_received,
			aer_decode->root_error_status);
	JSON_FIELD_BOOL(fields_ir, err_fatal_nonfatal_received,
			aer_decode->root_error_status);
	JSON_FIELD_BOOL(fields_ir, multiple_err_fatal_nonfatal_received,
			aer_decode->root_error_status);
	JSON_FIELD_BOOL(fields_ir, first_uncorrectable_fatal,
			aer_decode->root_error_status);
	JSON_FIELD_BOOL(fields_ir, non_fatal_error_messages_received,
			aer_decode->root_error_status);
	JSON_FIELD_BOOL(fields_ir, fatal_error_messages_received,
			aer_decode->root_error_status);
	JSON_FIELD_INT(fields_ir, err_cor_subclass,
		       aer_decode->root_error_status);
	JSON_FIELD_INT(fields_ir, rsvdz, aer_decode->root_error_status);
	JSON_FIELD_INT(fields_ir, advanced_error_interrupt_message_number,
		       aer_decode->root_error_status);
	json_object_object_add(aer_capability_ir, "root_error_status",
			       fields_ir);

	/*
	 * Error Source Identification Register
	 * Offset: 0x34
	 */
	fields_ir = json_object_new_object();
	JSON_FIELD_INT(fields_ir, err_cor_source_identification,
		       aer_decode->error_source_id);
	JSON_FIELD_INT(fields_ir, err_fatal_nonfatal_source_indentification,
		       aer_decode->error_source_id);
	json_object_object_add(aer_capability_ir, "error_source_id", fields_ir);

	return aer_capability_ir;
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
