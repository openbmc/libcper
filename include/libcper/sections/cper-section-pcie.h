#ifndef CPER_SECTION_PCIE_H
#define CPER_SECTION_PCIE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <json.h>
#include <libcper/Cper.h>

#define PCIE_ERROR_VALID_BITFIELD_NAMES                                        \
	(const char *[]){ "portTypeValid",                                     \
			  "versionValid",                                      \
			  "commandStatusValid",                                \
			  "deviceIDValid",                                     \
			  "deviceSerialNumberValid",                           \
			  "bridgeControlStatusValid",                          \
			  "capabilityStructureStatusValid",                    \
			  "aerInfoValid" }
#define PCIE_ERROR_PORT_TYPES_KEYS (int[]){ 0, 1, 4, 5, 6, 7, 8, 9, 10 }
#define PCIE_ERROR_PORT_TYPES_VALUES                                           \
	(const char *[]){ "PCI Express End Point",                             \
			  "Legacy PCI End Point Device",                       \
			  "Root Port",                                         \
			  "Upstream Switch Port",                              \
			  "Downstream Switch Port",                            \
			  "PCI Express to PCI/PCI-X Bridge",                   \
			  "PCI/PCI-X Bridge to PCI Express Bridge",            \
			  "Root Complex Integrated Endpoint Device",           \
			  "Root Complex Event Collector" }

struct class_code {
	UINT8 base;
	UINT8 sub;
	UINT8 programming;
	const char *name;
};

json_object *cper_section_pcie_to_ir(const UINT8 *section, UINT32 size);
void ir_section_pcie_to_cper(json_object *section, FILE *out);

/*
 * This file is designed as a standard c header file and as a script friendly
 * source fo the PCIe PCIe Capability and Advanced Error Registers structures.
 * The template of each register is:
 *
 * 
 *  * <Name of Capabaility Structure>
 *  * CAPABILITY_ID = <id of capability structure>
 *  * <Register Name>
 *  * Offset: <offset of the register in the capability structure>
 * struct {
 * 	<register width> <field name> : <field width>;
 * 	<register width> <field name> : <field width>;
 * 	<register width> <field name> : <field width>;
 * }
 */

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * PCI Express Capability Structure Header
 * Offset: 0x0
 */
typedef struct {
	UINT16 capability_id : 8; // bits [7:0] - Capability ID (should be 0x10)
	UINT16 next_capability_pointer : 8; // bits [7:0] - Next capability pointer
} __attribute__((packed)) pcie_capability_header_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * PCI Express Capabilities Register
 * Offset: 0x2
 */
typedef struct {
	UINT16 capability_version : 4;	     // bits [3:0]
	UINT16 device_port_type : 4;	     // bits [7:4]
	UINT16 slot_implemented : 1;	     // bit [8]
	UINT16 interrupt_message_number : 5; // bits [13:9]
	UINT16 undefined : 1;		     // bit [14]
	UINT16 flit_mode_supported : 1;	     // bit [15]
} __attribute__((packed)) pcie_capabilities_t;

static const char *device_port_type_dict[] = {
	"PCIE",		   // 0x0
	"PCI",		   // 0x1
	"ROOT_PORT",	   // 0x4
	"UPSTREAM",	   // 0x5
	"DOWNSTREAM",	   // 0x6
	"PCIE_PCI_BRIDGE", // 0x7
	"PCI_PCIE_BRIDGE", // 0x8
	"RCiEP",	   // 0x9
	"RCEC",		   // 0xa
};

static const size_t device_port_type_dict_size =
	sizeof(device_port_type_dict) / sizeof(device_port_type_dict[0]);

/*
 * Begin Of PCIe Capability Registers
 */

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Device Capabilities Register
 * Offset: 0x4
 */
typedef struct {
	UINT32 max_payload_size_supported : 3;	    // bits [2:0]
	UINT32 phantom_functions_supported : 2;	    // bits [4:3]
	UINT32 extended_tag_field_supported : 1;    // bit [5]
	UINT32 endpoint_l0s_acceptable_latency : 3; // bits [8:6]
	UINT32 endpoint_l1_acceptable_latency : 3;  // bits [11:9]
	UINT32 undefined : 3;			    // bits [14:12]
	UINT32 role_based_error_reporting : 1;	    // bit [15]
	UINT32 err_cor_subclass_capable : 1;	    // bit [16]
	UINT32 rx_mps_fixed : 1;		    // bits [17]
	UINT32 captured_slot_power_limit_value : 8; // bits [25:18]
	UINT32 captured_slot_power_limit_scale : 2; // bits [27:26]
	UINT32 function_level_reset_capability : 1; // bit [28]
	UINT32 mixed_mps_supported : 1;		    // bit [29]
	UINT32 tee_io_supported : 1;		    // bit [30]
	UINT32 rsvdp : 1;			    // bit [31]
} __attribute__((packed)) device_capabilities_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Device Control Register
 * Offset: 0x8
 */
typedef struct {
	UINT16 correctable_error_reporting_enable : 1;	 // bit [0]
	UINT16 non_fatal_error_reporting_enable : 1;	 // bit [1]
	UINT16 fatal_error_reporting_enable : 1;	 // bit [2]
	UINT16 unsupported_request_reporting_enable : 1; // bit [3]
	UINT16 enable_relaxed_ordering : 1;		 // bit [4]
	UINT16 max_payload_size : 3;			 // bits [7:5]
	UINT16 extended_tag_field_enable : 1;		 // bit [8]
	UINT16 phantom_functions_enable : 1;		 // bit [9]
	UINT16 aux_power_pm_enable : 1;			 // bit [10]
	UINT16 enable_no_snoop : 1;			 // bit [11]
	UINT16 max_read_request_size : 3;		 // bits [14:12]
	UINT16 function_level_reset : 1;		 // bit [15]
} __attribute__((packed)) device_control_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Device Status Register
 * Offset: 0xA
 */
typedef struct {
	UINT16 correctable_error_detected : 1;	 // bit [0]
	UINT16 non_fatal_error_detected : 1;	 // bit [1]
	UINT16 fatal_error_detected : 1;	 // bit [2]
	UINT16 unsupported_request_detected : 1; // bit [3]
	UINT16 aux_power_detected : 1;		 // bit [4]
	UINT16 transactions_pending : 1;	 // bit [5]
	UINT16 emergency_power_reduction : 2;	 // bits [7:6] (PCIe 4.0+)
	UINT16 rsvdz : 8;			 // bits [15:8]
} __attribute__((packed)) device_status_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Link Capabilities Register
 * Offset: 0xC
 */
typedef struct {
	UINT32 max_link_speed : 4;			  // bits [3:0]
	UINT32 maximum_link_width : 6;			  // bits [9:4]
	UINT32 aspm_support : 2;			  // bits [11:10]
	UINT32 l0s_exit_latency : 3;			  // bits [14:12]
	UINT32 l1_exit_latency : 3;			  // bits [17:15]
	UINT32 clock_power_management : 1;		  // bit [18]
	UINT32 surprise_down_error_reporting_capable : 1; // bit [19]
	UINT32 data_link_layer_link_active_reporting_capable : 1; // bit [20]
	UINT32 link_bandwidth_notification_capability : 1;	  // bit [21]
	UINT32 aspm_optionality_compliance : 1;			  // bit [22]
	UINT32 rsvdp : 1;					  // bit [23]
	UINT32 port_number : 8; // bits [31:24]
} __attribute__((packed)) link_capabilities_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Link Control Register
 * Offset: 0x10
 */
typedef struct {
	UINT16 aspm_control : 2; // bits [1:0]
	// ptm_propagation_delay_adaptation_interpretation_bit
	UINT16 ptm_prop_delay_adaptation_interpretation : 1;   // bit [2]
	UINT16 read_completion_boundary : 1;		       // bit [3]
	UINT16 link_disable : 1;			       // bit [4]
	UINT16 retrain_link : 1;			       // bit [5]
	UINT16 common_clock_configuration : 1;		       // bit [6]
	UINT16 extended_synch : 1;			       // bit [7]
	UINT16 enable_clock_power_management : 1;	       // bit [8]
	UINT16 hardware_autonomous_width_disable : 1;	       // bit [9]
	UINT16 link_bandwidth_management_interrupt_enable : 1; // bit [10]
	UINT16 link_autonomous_bandwidth_interrupt_enable : 1; // bit [11]
	UINT16 sris_clocking : 1;			       // bit [12]
	UINT16 flit_mode_disable : 1;			       // bit [13]
	UINT16 drs_signaling_control : 1;		       // bits [15:14]
} __attribute__((packed)) link_control_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Link Status Register
 * Offset: 0x12
 */
typedef struct {
	UINT16 current_link_speed : 4;		     // bits [3:0]
	UINT16 negotiated_link_width : 6;	     // bits [9:4]
	UINT16 undefined : 1;			     // bit [10]
	UINT16 link_training : 1;		     // bit [11]
	UINT16 slot_clock_configuration : 1;	     // bit [12]
	UINT16 data_link_layer_link_active : 1;	     // bit [13]
	UINT16 link_bandwidth_management_status : 1; // bit [14]
	UINT16 link_autonomous_bandwidth_status : 1; // bit [15]
} __attribute__((packed)) link_status_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Slot Capabilities Register
 * Offset: 0x14
 */
typedef struct {
	UINT32 attention_button_present : 1;		// bit [0]
	UINT32 power_controller_present : 1;		// bit [1]
	UINT32 mrl_sensor_present : 1;			// bit [2]
	UINT32 attention_indicator_present : 1;		// bit [3]
	UINT32 power_indicator_present : 1;		// bit [4]
	UINT32 hot_plug_surprise : 1;			// bit [5]
	UINT32 hot_plug_capable : 1;			// bit [6]
	UINT32 slot_power_limit_value : 8;		// bits [14:7]
	UINT32 slot_power_limit_scale : 2;		// bits [16:15]
	UINT32 electromechanical_interlock_present : 1; // bit [17]
	UINT32 no_command_completed_support : 1;	// bit [18]
	UINT32 physical_slot_number : 13;		// bits [31:19]
} __attribute__((packed)) slot_capabilities_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Slot Control Register
 * Offset: 0x18
 */
typedef struct {
	UINT16 attention_button_pressed_enable : 1;	 // bit [0]
	UINT16 power_fault_detected_enable : 1;		 // bit [1]
	UINT16 mrl_sensor_changed_enable : 1;		 // bit [2]
	UINT16 presence_detect_changed_enable : 1;	 // bit [3]
	UINT16 command_completed_interrupt_enable : 1;	 // bit [4]
	UINT16 hot_plug_interrupt_enable : 1;		 // bit [5]
	UINT16 attention_indicator_control : 2;		 // bits [7:6]
	UINT16 power_indicator_control : 2;		 // bits [9:8]
	UINT16 power_controller_control : 1;		 // bit [10]
	UINT16 electromechanical_interlock_control : 1;	 // bit [11]
	UINT16 data_link_layer_state_changed_enable : 1; // bit [12]
	UINT16 auto_slot_power_limit_disable : 1;	 // bit [13]
	UINT16 in_band_pd_disable : 1;			 // bit [14]
	UINT16 rsvdp : 1;				 // bit [15]
} __attribute__((packed)) slot_control_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Slot Status Register
 * Offset: 0x1A
 */
typedef struct {
	UINT16 attention_button_pressed : 1;	       // bit [0]
	UINT16 power_fault_detected : 1;	       // bit [1]
	UINT16 mrl_sensor_changed : 1;		       // bit [2]
	UINT16 presence_detect_changed : 1;	       // bit [3]
	UINT16 command_completed : 1;		       // bit [4]
	UINT16 mrl_sensor_state : 1;		       // bit [5]
	UINT16 presence_detect_state : 1;	       // bit [6]
	UINT16 electromechanical_interlock_status : 1; // bit [7]
	UINT16 data_link_layer_state_changed : 1;      // bit [8]
	UINT16 rsvdz : 7;			       // bits [15:9]
} __attribute__((packed)) slot_status_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Root Control Register
 * Offset: 0x1C
 */
typedef struct {
	UINT16 system_error_on_correctable_error_enable : 1;	 // bit [0]
	UINT16 system_error_on_non_fatal_error_enable : 1;	 // bit [1]
	UINT16 system_error_on_fatal_error_enable : 1;		 // bit [2]
	UINT16 pme_interrupt_enable : 1;			 // bit [3]
	UINT16 configuration_rrs_software_visibility_enable : 1; // bit [4]
	UINT16 no_nfm_subtree_below_this_root_port : 1;		 // bit [5]
	UINT16 rsvdp : 10;					 // bits [15:6]
} __attribute__((packed)) root_control_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Root Capabilities Register
 * Offset: 0x1E
 */
typedef struct {
	UINT16 configuraton_rrs_software_visibility : 1; // bit [0]
	UINT16 rsvdp : 15;				 // bits [15:1]
} __attribute__((packed)) root_capabilities_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Root Status Register
 * Offset: 0x20
 */
typedef struct {
	UINT32 pme_requester_id : 16; // bits [15:0]
	UINT32 pme_status : 1;	      // bit [16]
	UINT32 pme_pending : 1;	      // bit [17]
	UINT32 rsvdp : 14;	      // bits [31:18]
} __attribute__((packed)) root_status_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Device Capabilities 2 Register
 * Offset: 0x24
 */
typedef struct {
	UINT32 completion_timeout_ranges_supported : 4;	 // bits [3:0]
	UINT32 completion_timeout_disable_supported : 1; // bit [4]
	UINT32 ari_forwarding_supported : 1;		 // bit [5]
	UINT32 atomic_op_routing_supported : 1;		 // bit [6]
	UINT32 _32_bit_atomicop_completer_supported : 1; // bit [7]
	UINT32 _64_bit_atomicop_completer_supported : 1; // bit [8]
	UINT32 _128_bit_cas_completer_supported : 1;	 // bit [9]
	UINT32 no_ro_enabled_pr_pr_passing : 1;		 // bit [10]
	UINT32 ltr_mechanism_supported : 1;		 // bit [11]
	UINT32 tph_completer_supported : 2;		 // bits [13:12]
	UINT32 undefined : 2;				 // bit [15:14]
	UINT32 _10_bit_tag_completer_supported : 1;	 // bit [16]
	UINT32 _10_bit_tag_requester_supported : 1;	 // bit [17]
	UINT32 obff_supported : 2;			 // bits [19:18]
	UINT32 extended_fmt_field_supported : 1;	 // bit [20]
	UINT32 end_end_tlp_prefix_supported : 1;	 // bit [21]
	UINT32 max_end_end_tlp_prefixes : 2;		 // bits [23:22]
	UINT32 emergency_power_reduction_supported : 2;	 // bits [25:24]
	// emergency_power_reduction_initialization_required
	UINT32 emergency_power_reduction_init_required : 1; // bit [26]
	UINT32 rsvdp : 1;				    // bit [27]
	UINT32 dmwr_completer_supported : 1;		    // bit [28]
	UINT32 dmwr_lengths_supported : 2;		    // bits [30:29]
	UINT32 frs_supported : 1;			    // bit [31]
} __attribute__((packed)) device_capabilities2_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Device Control 2 Register
 * Offset: 0x28
 */
typedef struct {
	UINT16 completion_timeout_value : 4;	      // bits [3:0]
	UINT16 completion_timeout_disable : 1;	      // bit [4]
	UINT16 ari_forwarding_enable : 1;	      // bit [5]
	UINT16 atomicop_requester_enable : 1;	      // bit [6]
	UINT16 atomicop_egress_blocking : 1;	      // bit [7]
	UINT16 ido_request_enable : 1;		      // bit [8]
	UINT16 ido_completion_enable : 1;	      // bit [9]
	UINT16 ltr_mechanism_enable : 1;	      // bit [10]
	UINT16 emergency_power_reduction_request : 1; // bit [11]
	UINT16 bit_tag_requester_10_enable : 1;      // bit [12]
	UINT16 obff_enable : 2;			      // bits [14:13]
	UINT16 end_end_tlp_prefix_blocking : 1;	      // bit [15]
} __attribute__((packed)) device_control2_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Device Status 2 Register
 * Offset: 0x2A
 */
typedef struct {
	UINT16 rsvdz : 16; // bits [15:0]
} __attribute__((packed)) device_status2_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Link Capabilities 2 Register
 * Offset: 0x2C
 */
typedef struct {
	UINT32 rsvdp : 1; // bit [0]
	union {
		struct {
			UINT32 l_2_5g_supported : 1;
			UINT32 l_5g_supported : 1;
			UINT32 l_8g_supported : 1;
			UINT32 l_16g_supported : 1;
			UINT32 l_32g_supported : 1;
			UINT32 reserved1 : 1;
			UINT32 reserved2 : 1;
		} __attribute__((packed)) supported_link_speeds;
		UINT32 supported_link_speeds_register : 7; // bits [7:1]
	};

	UINT32 crosslink_supported : 1;			   // bit [8]
	UINT32 lower_skp_os_generation_supported : 7;	   // bit [15:9]
	UINT32 lower_skp_os_reception_supported : 7;	   // bit [22:16]
	UINT32 retimer_presence_detect_supported : 1;	   // bit [23]
	UINT32 two_retimers_presence_detect_supported : 1; // bit [24]
	UINT32 reserved : 6;				   // bits [30:25]
	UINT32 drs_supported : 1;			   // bit [31]
} __attribute__((packed)) link_capabilities2_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Link Control 2 Register
 * Offset: 0x30
 */
typedef struct {
	UINT16 target_link_speed : 4;		      // bits [3:0]
	UINT16 enter_compliance : 1;		      // bit [4]
	UINT16 hardware_autonomous_speed_disable : 1; // bit [5]
	UINT16 selectable_de_emphasis : 1;	      // bit [6]
	UINT16 transmit_margin : 3;		      // bits [9:7]
	UINT16 enter_modified_compliance : 1;	      // bit [10]
	UINT16 compliance_sos : 1;		      // bit [11]
	UINT16 compliance_preset_de_emphasis : 4;     // bits [15:12]
} __attribute__((packed)) link_control2_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Link Status 2 Register
 * Offset: 0x32
 */
typedef struct {
	UINT16 current_de_emphasis_level : 1;		// bit [0]
	UINT16 equalization_8gts_complete : 1;		// bit [1]
	UINT16 equalization_8gts_phase1_successful : 1; // bit [2]
	UINT16 equalization_8gts_phase2_successful : 1; // bit [3]
	UINT16 equalization_8gts_phase3_successful : 1; // bit [4]
	UINT16 link_equalization_request_8gts : 1;	// bit [5]
	UINT16 retimer_presence_detected : 1;		// bit [6]
	UINT16 two_retimers_presence_detected : 1;	// bit [7]
	UINT16 crosslink_resolution : 2;		// bits [9:8]
	UINT16 flit_mode_status : 1;			// bit [10]
	UINT16 rsvdz : 1;				// bit [11]
	UINT16 downstream_component_presence : 3;	// bits [14:12]
	UINT16 drs_message_received : 1;		// bit [15]
} __attribute__((packed)) link_status2_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Slot Capabilities 2 Register
 * Offset: 0x34
 */
typedef struct {
	UINT32 rsvdp : 32; // bits [31:0]
} __attribute__((packed)) slot_capabilities2_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Slot Control 2 Register
 * Offset: 0x38
 */
typedef struct {
	UINT16 rsvdp : 16; // bits [15:0]
} __attribute__((packed)) slot_control2_t;

/*
 * PCI Express Capability Structure
 * CAPABILITY_ID = 0x10
 * Slot Status 2 Register
 * Offset: 0x3A
 */
typedef struct {
	UINT16 rsvdp : 16; // bits [15:0]
} __attribute__((packed)) slot_status2_t;

/*
 * End Of PCIe Capability Registers
 */

/*
 * Begin Of AER Registers
 */

/*
 * PCI Express Advanced Error Reporting Capability Structure
 * CAPABILITY_ID = 0x01
 * AER Capability Header
 * Offset: 0x0
 */
typedef struct {
	UINT16 capability_id : 16;	    // bits [15:0]
	UINT16 capability_version : 4;	    // bits [19:16]
	UINT16 next_capability_offset : 12; // bits [31:20]
} __attribute__((packed)) capability_header_t;

/*
 * PCI Express Advanced Error Reporting Capability Structure
 * CAPABILITY_ID = 0x01
 * Uncorrectable Error Status Register
 * Offset: 0x4
 */
typedef struct {
	UINT32 undefined : 1;				  // bits [0]
	UINT32 rsvdz1 : 3;				  // bits [3:1]
	UINT32 data_link_protocol_error_status : 1;	  // bit [4]
	UINT32 surprise_down_error_status : 1;		  // bit [5]
	UINT32 rsvdz2 : 6;				  // bits [11:6]
	UINT32 poisoned_tlp_received : 1;		  // bit [12]
	UINT32 flow_control_protocol_error_status : 1;	  // bit [13]
	UINT32 completion_timeout_status : 1;		  // bit [14]
	UINT32 completer_abort_status : 1;		  // bit [15]
	UINT32 unexpected_completion_status : 1;	  // bit [16]
	UINT32 receiver_overflow_status : 1;		  // bit [17]
	UINT32 malformed_tlp_status : 1;		  // bit [18]
	UINT32 ecrc_error_status : 1;			  // bit [19]
	UINT32 unsupported_request_error_status : 1;	  // bit [20]
	UINT32 acs_violation_status : 1;		  // bit [21]
	UINT32 uncorrectable_internal_error_status : 1;	  // bit [22]
	UINT32 mc_blocked_tlp_status : 1;		  // bit [23]
	UINT32 atomicop_egress_blocked_status : 1;	  // bit [24]
	UINT32 tlp_prefix_blocked_error_status : 1;	  // bit [25]
	UINT32 poisoned_tlp_egress_blocked_status : 1;	  // bit [26]
	UINT32 dmwr_request_egress_blocked_status : 1;	  // bit [27]
	UINT32 ide_check_failed_status : 1;		  // bit [28]
	UINT32 misrouted_ide_tlp_status : 1;		  // bit [29]
	UINT32 pcrc_check_failed_status : 1;		  // bit [30]
	UINT32 tlp_translation_egress_blocked_status : 1; // bit [31]
} __attribute__((packed)) uncorrectable_error_status_t;

/*
 * PCI Express Advanced Error Reporting Capability Structure
 * CAPABILITY_ID = 0x01
 * Uncorrectable Error Mask Register
 * Offset: 0x8
 */
typedef struct {
	UINT32 undefined : 1;				// bits [0]
	UINT32 rsvdz1 : 3;				// bits [3:1]
	UINT32 data_link_protocol_error_mask : 1;	// bit [4]
	UINT32 surprise_down_error_mask : 1;		// bit [5]
	UINT32 rsvdz2 : 6;				// bits [11:6]
	UINT32 poisoned_tlp_received_mask : 1;		// bit [12]
	UINT32 flow_control_protocol_error_mask : 1;	// bit [13]
	UINT32 completion_timeout_mask : 1;		// bit [14]
	UINT32 completer_abort_mask : 1;		// bit [15]
	UINT32 unexpected_completion_mask : 1;		// bit [16]
	UINT32 receiver_overflow_mask : 1;		// bit [17]
	UINT32 malformed_tlp_mask : 1;			// bit [18]
	UINT32 ecrc_error_mask : 1;			// bit [19]
	UINT32 unsupported_request_error_mask : 1;	// bit [20]
	UINT32 acs_violation_mask : 1;			// bit [21]
	UINT32 uncorrectable_internal_error_mask : 1;	// bit [22]
	UINT32 mc_blocked_tlp_mask : 1;			// bit [23]
	UINT32 atomicop_egress_blocked_mask : 1;	// bit [24]
	UINT32 tlp_prefix_blocked_error_mask : 1;	// bit [25]
	UINT32 poisoned_tlp_egress_blocked_mask : 1;	// bit [26]
	UINT32 dmwr_request_egress_blocked_mask : 1;	// bit [27]
	UINT32 ide_check_failed_mask : 1;		// bit [28]
	UINT32 misrouted_ide_tlp_mask : 1;		// bit [29]
	UINT32 pcrc_check_failed_mask : 1;		// bit [30]
	UINT32 tlp_translation_egress_blocked_mask : 1; // bit [31]
} __attribute__((packed)) uncorrectable_error_mask_t;

static const char *severity_dict[] = {
	"NonFatal", // 0x0
	"Fatal",    // 0x1
};

static const size_t severity_dict_size =
	sizeof(severity_dict) / sizeof(severity_dict[0]);

static const char *supported_dict[] = {
	"NotSupported", // 0x0
	"Supported",	// 0x1
};

static const size_t supported_dict_size =
	sizeof(severity_dict) / sizeof(severity_dict[0]);

static const char *enabled_dict[] = {
	"Disabled", // 0x0
	"Enabled",  // 0x1
};

static const size_t enabled_dict_size =
	sizeof(enabled_dict) / sizeof(enabled_dict[0]);

static const char *passing_dict[] = {
	"Failed",  // 0x0
	"Passing", // 0x1
};

static const size_t passing_dict_size =
	sizeof(passing_dict) / sizeof(passing_dict[0]);

/*
 * PCI Express Advanced Error Reporting Capability Structure
 * CAPABILITY_ID = 0x01
 * Uncorrectable Error Severity Register
 * Offset: 0xC
 */
typedef struct {
	UINT32 undefined : 1;				    // bits [0]
	UINT32 rsvdz1 : 3;				    // bits [3:1]
	UINT32 data_link_protocol_error_severity : 1;	    // bit [4]
	UINT32 surprise_down_error_severity : 1;	    // bit [5]
	UINT32 rsvdz2 : 6;				    // bits [11:6]
	UINT32 poisoned_tlp_received_severity : 1;	    // bit [12]
	UINT32 flow_control_protocol_error_severity : 1;    // bit [13]
	UINT32 completion_timeout_severity : 1;		    // bit [14]
	UINT32 completer_abort_severity : 1;		    // bit [15]
	UINT32 unexpected_completion_severity : 1;	    // bit [16]
	UINT32 receiver_overflow_severity : 1;		    // bit [17]
	UINT32 malformed_tlp_severity : 1;		    // bit [18]
	UINT32 ecrc_error_severity : 1;			    // bit [19]
	UINT32 unsupported_request_error_severity : 1;	    // bit [20]
	UINT32 acs_violation_severity : 1;		    // bit [21]
	UINT32 uncorrectable_internal_error_severity : 1;   // bit [22]
	UINT32 mc_blocked_tlp_severity : 1;		    // bit [23]
	UINT32 atomicop_egress_blocked_severity : 1;	    // bit [24]
	UINT32 tlp_prefix_blocked_error_severity : 1;	    // bit [25]
	UINT32 poisoned_tlp_egress_blocked_severity : 1;    // bit [26]
	UINT32 dmwr_request_egress_blocked_severity : 1;    // bit [27]
	UINT32 ide_check_failed_severity : 1;		    // bit [28]
	UINT32 misrouted_ide_tlp_severity : 1;		    // bit [29]
	UINT32 pcrc_check_failed_severity : 1;		    // bit [30]
	UINT32 tlp_translation_egress_blocked_severity : 1; // bit [31]
} __attribute__((packed)) uncorrectable_error_severity_t;

/*
 * PCI Express Advanced Error Reporting Capability Structure
 * CAPABILITY_ID = 0x01
 * Correctable Error Status Register
 * Offset: 0x10
 */
typedef struct {
	UINT32 receiver_error_status : 1;	    // bit [0]
	UINT32 rsvdz1 : 5;			    // bits [5:1]
	UINT32 bad_tlp_status : 1;		    // bit [6]
	UINT32 bad_dllp_status : 1;		    // bit [7]
	UINT32 replay_num_rollover_status : 1;	    // bit [8]
	UINT32 rsvdz2 : 3;			    // bits [11:9]
	UINT32 replay_timer_timeout_status : 1;	    // bit [12]
	UINT32 advisory_non_fatal_error_status : 1; // bit [13]
	UINT32 corrected_internal_error_status : 1; // bit [14]
	UINT32 header_log_overflow_status : 1;	    // bit [15]
	UINT32 rsvdz3 : 16;			    // bits [31:16]
} __attribute__((packed)) correctable_error_status_t;

/*
 * PCI Express Advanced Error Reporting Capability Structure
 * CAPABILITY_ID = 0x01
 * Correctable Error Mask Register
 * Offset: 0x14
 */
typedef struct {
	UINT32 receiver_error_mask : 1;		  // bit [0]
	UINT32 rsvdz1 : 5;			  // bits [5:1]
	UINT32 bad_tlp_mask : 1;		  // bit [6]
	UINT32 bad_dllp_mask : 1;		  // bit [7]
	UINT32 replay_num_rollover_mask : 1;	  // bit [8]
	UINT32 rsvdz2 : 3;			  // bits [11:9]
	UINT32 replay_timer_timeout_mask : 1;	  // bit [12]
	UINT32 advisory_non_fatal_error_mask : 1; // bit [13]
	UINT32 corrected_internal_error_mask : 1; // bit [14]
	UINT32 header_log_overflow_mask : 1;	  // bit [15]
	UINT32 rsvdz3 : 16;			  // bits [31:16]
} __attribute__((packed)) correctable_error_mask_t;

/*
 * PCI Express Advanced Error Reporting Capability Structure
 * CAPABILITY_ID = 0x01
 * Advanced Error Capabilities and Control Register
 * Offset: 0x18
 */
typedef struct {
	UINT32 first_error_pointer : 5;				 // bits [4:0]
	UINT32 ecrc_generation_capable : 1;			 // bit [5]
	UINT32 ecrc_generation_enable : 1;			 // bit [6]
	UINT32 ecrc_check_capable : 1;				 // bit [7]
	UINT32 ecrc_check_enable : 1;				 // bit [8]
	UINT32 multiple_header_recording_capable : 1;		 // bit [9]
	UINT32 multiple_header_recording_enable : 1;		 // bit [10]
	UINT32 tlp_prefix_log_present : 1;			 // bit [11]
	UINT32 completion_timeout_prefix_header_log_capable : 1; // bit [12]
	UINT32 header_log_size : 5;				 // bits [17:13]
	UINT32 logged_tlp_was_flit_mode : 1;			 // bit [18]
	UINT32 logged_tlp_size : 5;				 // bits [23:19]
	UINT32 rsvdp : 8;					 // bits [31:24]
} __attribute__((packed)) advanced_error_capabilities_and_control_t;

/*
 * PCI Express Advanced Error Reporting Capability Structure
 * CAPABILITY_ID = 0x01
 * Root Error Command Register
 * Offset: 0x2C
 */
typedef struct {
	UINT32 correctable_error_reporting_enable : 1; // bit [0]
	UINT32 non_fatal_error_reporting_enable : 1;   // bit [1]
	UINT32 fatal_error_reporting_enable : 1;       // bit [2]
	UINT32 rsvdp : 29;			       // bits [31:3]
} __attribute__((packed)) root_error_command_t;

/*
 * PCI Express Advanced Error Reporting Capability Structure
 * CAPABILITY_ID = 0x01
 * Root Error Status Register
 * Offset: 0x30
 */
typedef struct {
	UINT32 err_cor_received : 1;			    // bit [0]
	UINT32 multiple_err_cor_received : 1;		    // bit [1]
	UINT32 err_fatal_nonfatal_received : 1;		    // bit [2]
	UINT32 multiple_err_fatal_nonfatal_received : 1;    // bit [3]
	UINT32 first_uncorrectable_fatal : 1;		    // bit [4]
	UINT32 non_fatal_error_messages_received : 1;	    // bit [5]
	UINT32 fatal_error_messages_received : 1;	    // bit [6]
	UINT32 err_cor_subclass : 2;			    // bit [8:7]
	UINT32 rsvdz : 16;				    // bit [9:26]
	UINT32 advanced_error_interrupt_message_number : 5; // bits [31:27]
} __attribute__((packed)) root_error_status_t;

/*
 * PCI Express Advanced Error Reporting Capability Structure
 * CAPABILITY_ID = 0x01
 * Error Source Identification Register
 * Offset: 0x34
 */
typedef struct {
	UINT32 err_cor_source_identification : 16;	      // bits [15:0]
	UINT32 err_fatal_nonfatal_source_identification : 16; // bits [31:16]
} __attribute__((packed)) error_source_id_t;

typedef struct {
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
} __attribute__((packed)) capability_registers;

typedef struct {
	capability_header_t capability_header;
	uncorrectable_error_status_t uncorrectable_error_status;
	uncorrectable_error_mask_t uncorrectable_error_mask;
	uncorrectable_error_severity_t uncorrectable_error_severity;
	correctable_error_status_t correctable_error_status;
	correctable_error_mask_t correctable_error_mask;
	advanced_error_capabilities_and_control_t
		advanced_error_capabilities_and_control;
	UINT32 tlp_header[4];
	root_error_command_t root_error_command;
	root_error_status_t root_error_status;
	error_source_id_t error_source_id;
	union {
		struct { // Non-flit mode TLP prefix logs
			UINT32 log[4];
		} non_flit_logs;
		struct { // Flit mode TLP header logs
			UINT32 header[10];
		} flit_tlp_header_logs;
	} tlp_pfrefix;
} __attribute__((packed)) aer_info_registers;

#ifdef __cplusplus
}
#endif

#endif
