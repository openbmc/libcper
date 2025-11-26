// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <json.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-nvidia-events.h>
#include <libcper/log.h>
#include <string.h>

// NVIDIA Event Section GUID
EFI_GUID gEfiNvidiaEventErrorSectionGuid = {
	0x9068e568,
	0x6ca0,
	0x11f0,
	{ 0xae, 0xaf, 0x15, 0x93, 0x43, 0x59, 0x1e, 0xac }
};

// Hex encode binary data to string
// Returns malloc'd string (caller must free), or NULL on error
static char *hex_encode(const UINT8 *data, size_t data_len, size_t *out_len)
{
	if (data == NULL || out_len == NULL) {
		return NULL;
	}

	size_t hex_len = data_len * 2;
	char *hex_str = (char *)malloc(hex_len + 1);
	if (hex_str == NULL) {
		return NULL;
	}

	for (size_t i = 0; i < data_len; i++) {
		snprintf(hex_str + (i * 2), 3, "%02x", data[i]);
	}
	hex_str[hex_len] = '\0';
	*out_len = hex_len;

	return hex_str;
}

// Convert hex character to nibble value
static int hex_char_to_nibble(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

// Hex decode string to binary data
// Returns malloc'd buffer (caller must free), or NULL on error
static UINT8 *hex_decode(const char *hex_str, size_t hex_len, size_t *out_len)
{
	if (hex_str == NULL || out_len == NULL) {
		return NULL;
	}

	// Must have even number of hex characters
	if (hex_len % 2 != 0) {
		return NULL;
	}

	size_t data_len = hex_len / 2;
	UINT8 *data = (UINT8 *)malloc(data_len);
	if (data == NULL) {
		return NULL;
	}

	for (size_t i = 0; i < data_len; i++) {
		int high = hex_char_to_nibble(hex_str[i * 2]);
		int low = hex_char_to_nibble(hex_str[i * 2 + 1]);
		if (high < 0 || low < 0) {
			free(data);
			return NULL;
		}
		data[i] = (UINT8)((high << 4) | low);
	}

	*out_len = data_len;
	return data;
}

/**
 * NVIDIA Event Binary Structure Layout:
 *
 * The NVIDIA event CPER section has the following binary memory layout:
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_EVENT_HEADER                                      (32 bytes) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   CHAR8   EventVersion                                                  │
 * │   CHAR8   EventContextCount      ← Number of contexts that follow       │
 * │   CHAR8   SourceDeviceType                                              │
 * │   CHAR8   Reserved1                                                     │
 * │   UINT16  EventType                                                     │
 * │   UINT16  EventSubtype                                                  │
 * │   UINT64  EventLinkId                                                   │
 * │   CHAR8   Signature[16]                                                 │
 * └─────────────────────────────────────────────────────────────────────────┘
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_EVENT_INFO_HEADER                                  (3 bytes) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   UINT16  InfoVersion                                                   │
 * │   UINT8   InfoSize        ← Total size (header + device data)           │
 * └─────────────────────────────────────────────────────────────────────────┘
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ Device-Specific Event Info         (InfoSize - INFO_HEADER_SIZE bytes)  │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   e.g., EFI_NVIDIA_CPU_EVENT_INFO                           (29 bytes)  │
 * │     UINT8   SocketNum                                                   │
 * │     UINT32  Architecture                                                │
 * │     UINT32  Ecid[4]                                                     │
 * │     UINT64  InstanceBase                                                │
 * └─────────────────────────────────────────────────────────────────────────┘
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_EVENT_CTX_HEADER (Context 0)                      (16 bytes) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   UINT32  CtxSize                ← Total size of this context           │
 * │   UINT16  CtxVersion                                                    │
 * │   UINT16  Reserved1                                                     │
 * │   UINT16  DataFormatType         ← OPAQUE(0)/TYPE_1(1)/TYPE_2(2)/etc.   │
 * │   UINT16  DataFormatVersion                                             │
 * │   UINT32  DataSize               ← Size of Data[] array below           │
 * │   UINT8   Data[0]                ← Flexible array member                │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ Context Data[]                                        (DataSize bytes)  │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   TYPE_1: Array of EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1  (16 bytes each)    │
 * │     UINT64  Key                                                         │
 * │     UINT64  Value                                                       │
 * │                                                                         │
 * │   TYPE_2: Array of EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2   (8 bytes each)    │
 * │     UINT32  Key                                                         │
 * │     UINT32  Value                                                       │
 * │                                                                         │
 * │   TYPE_3: Array of EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3   (8 bytes each)    │
 * │     UINT64  Value                                                       │
 * │                                                                         │
 * │   TYPE_4: Array of EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4   (4 bytes each)    │
 * │     UINT32  Value                                                       │
 * │                                                                         │
 * │   OPAQUE: Device-specific binary format                                 │
 * └─────────────────────────────────────────────────────────────────────────┘
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ PADDING (if needed)                        (align to 16-byte boundary)  │
 * └─────────────────────────────────────────────────────────────────────────┘
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_EVENT_CTX_HEADER (Context 1)                       (8 bytes) │
 * │   ... (same structure as Context 0)                                     │
 * └─────────────────────────────────────────────────────────────────────────┘
 *     ... repeat for EventContextCount total contexts ...
 *
 * Note: Each context is padded to 16-byte alignment before the next context begins.
 */

/**
 * NVIDIA Event JSON IR Structure:
 *
 * Maps binary structures (above) to JSON using the field name constants (below).
 *
 * {
 *   "eventHeader": { ... }           → EFI_NVIDIA_EVENT_HEADER      (JSON_EVENT_HEADER_*)
 *   "eventInfo": { ... }             → EFI_NVIDIA_EVENT_INFO_*      (JSON_EVENT_INFO_*)
 *   "eventContexts": [               → Array of contexts            (JSON_EVENT_CONTEXT*)
 *     {
 *       "data": {                    → EFI_NVIDIA_EVENT_CTX_DATA_*  (JSON_CONTEXT_DATA_TYPE*)
 *         "keyValArray64": [ ... ]   → TYPE_1 (16 bytes each: key64, val64)
 *         "keyValArray32": [ ... ]   → TYPE_2 ( 8 bytes each: key32, val32)
 *         "valArray64":  [ ... ]     → TYPE_3 ( 8 bytes each: val64)
 *         "valArray32":  [ ... ]     → TYPE_4 ( 4 bytes each: val32)
 *       }
 *     },
 *     { ... }
 *   ]
 * }
 */

// JSON object field names for event structure
#define JSON_EVENT_HEADER		       "eventHeader"
#define JSON_EVENT_HEADER_SIGNATURE	       "signature"
#define JSON_EVENT_HEADER_VERSION	       "version"
#define JSON_EVENT_HEADER_CONTEXT_COUNT	       "contextCount"
#define JSON_EVENT_HEADER_SOURCE_DEVICE_TYPE   "sourceDeviceType"
#define JSON_EVENT_HEADER_TYPE		       "type"
#define JSON_EVENT_HEADER_SUBTYPE	       "subtype"
#define JSON_EVENT_HEADER_LINK_ID	       "linkId"
#define JSON_EVENT_INFO			       "eventInfo"
#define JSON_EVENT_INFO_VERSION	       "version"
#define JSON_EVENT_INFO_SIZE		       "size"
#define JSON_EVENT_CONTEXTS			       "eventContexts"
#define JSON_EVENT_CONTEXT			       "eventContext"
#define JSON_EVENT_CONTEXT_SIZE			       "size"
#define JSON_EVENT_CONTEXT_VERSION	       "version"
#define JSON_EVENT_CONTEXT_DATA_FORMAT_TYPE       "dataFormatType"
#define JSON_EVENT_CONTEXT_DATA_FORMAT_VERSION    "dataFormatVersion"
#define JSON_EVENT_CONTEXT_DATA_SIZE		       "dataSize"
#define JSON_EVENT_CONTEXT_DATA			       "data"
// JSON object field names for event context data types
#define JSON_CONTEXT_DATA_TYPE1_KV64_ARRAY "keyValArray64"
#define JSON_CONTEXT_DATA_TYPE1_KEY64	   "key64"
#define JSON_CONTEXT_DATA_TYPE1_VAL64	   "val64"
#define JSON_CONTEXT_DATA_TYPE2_KV32_ARRAY "keyValArray32"
#define JSON_CONTEXT_DATA_TYPE2_KEY32	   "key32"
#define JSON_CONTEXT_DATA_TYPE2_VAL32	   "val32"
#define JSON_CONTEXT_DATA_TYPE3_V64_ARRAY  "valArray64"
#define JSON_CONTEXT_DATA_TYPE3_VAL64	   "val64"
#define JSON_CONTEXT_DATA_TYPE4_V32_ARRAY  "valArray32"
#define JSON_CONTEXT_DATA_TYPE4_VAL32	   "val32"

// JSON object field names for CPU event info
#define JSON_CPU_INFO_SOCKET_NUM    "SocketNum"
#define JSON_CPU_INFO_ARCHITECTURE  "Architecture"
#define JSON_CPU_INFO_ECID1	    "Ecid1"
#define JSON_CPU_INFO_ECID2	    "Ecid2"
#define JSON_CPU_INFO_ECID3	    "Ecid3"
#define JSON_CPU_INFO_ECID4	    "Ecid4"
#define JSON_CPU_INFO_INSTANCE_BASE "InstanceBase"

// JSON object field names for GPU event info
#define JSON_GPU_INFO_VERSION_MINOR	  "VersionMinor"
#define JSON_GPU_INFO_VERSION_MAJOR	  "VersionMajor"
#define JSON_GPU_INFO_SIZE		  "Size"
#define JSON_GPU_INFO_EVENT_ORIGINATOR	  "EventOriginator"
#define JSON_GPU_INFO_SOURCE_PARTITION	  "SourcePartition"
#define JSON_GPU_INFO_SOURCE_SUBPARTITION "SourceSubPartition"
#define JSON_GPU_INFO_PDI		  "Pdi"

// JSON object field names for GPU-specific context data types
// GPU Initialization Metadata (0x1000)
#define JSON_GPU_METADATA_DEVICE_NAME		     "deviceName"
#define JSON_GPU_METADATA_FIRMWARE_VERSION	     "firmwareVersion"
#define JSON_GPU_METADATA_PF_DRIVER_UCODE_VERSION    "pfDriverMicrocodeVersion"
#define JSON_GPU_METADATA_PF_DRIVER_VERSION	     "pfDriverVersion"
#define JSON_GPU_METADATA_VF_DRIVER_VERSION	     "vfDriverVersion"
#define JSON_GPU_METADATA_CONFIGURATION		     "configuration"
#define JSON_GPU_METADATA_PDI			     "pdi"
#define JSON_GPU_METADATA_ARCHITECTURE_ID	     "architectureId"
#define JSON_GPU_METADATA_HW_INFO_TYPE		     "hardwareInfoType"
#define JSON_GPU_METADATA_PCI_INFO		     "pciInfo"
#define JSON_GPU_METADATA_PCI_CLASS	     "class"
#define JSON_GPU_METADATA_PCI_SUBCLASS	     "subclass"
#define JSON_GPU_METADATA_PCI_REV		     "rev"
#define JSON_GPU_METADATA_PCI_VENDOR_ID	     "vendorId"
#define JSON_GPU_METADATA_PCI_DEVICE_ID	     "deviceId"
#define JSON_GPU_METADATA_PCI_SUBSYS_VENDOR_ID "subsystemVendorId"
#define JSON_GPU_METADATA_PCI_SUBSYS_ID	     "subsystemId"
#define JSON_GPU_METADATA_PCI_BAR0_START	     "bar0Start"
#define JSON_GPU_METADATA_PCI_BAR0_SIZE	     "bar0Size"
#define JSON_GPU_METADATA_PCI_BAR1_START	     "bar1Start"
#define JSON_GPU_METADATA_PCI_BAR1_SIZE	     "bar1Size"
#define JSON_GPU_METADATA_PCI_BAR2_START	     "bar2Start"
#define JSON_GPU_METADATA_PCI_BAR2_SIZE	     "bar2Size"

// GPU Event Legacy Xid (0x1001)
#define JSON_GPU_XID_CODE    "xidCode"
#define JSON_GPU_XID_MESSAGE "message"

// GPU Recommended Actions (0x1002)
#define JSON_GPU_ACTIONS_FLAGS		 "flags"
#define JSON_GPU_ACTIONS_RECOVERY_ACTION "recoveryAction"
#define JSON_GPU_ACTIONS_DIAGNOSTIC_FLOW "diagnosticFlow"

// ============================================================================
// JSON Field Format Configuration System (Naming Convention)
// ============================================================================
// Format is encoded in the #define name suffix for true granularity:
//   - No suffix = decimal (default)
//   - _HEX8    = hex 8-bit  (e.g., "0x2A")
//   - _HEX16   = hex 16-bit (e.g., "0x1234")
//   - _HEX32   = hex 32-bit (e.g., "0x12345678")
//   - _HEX64   = hex 64-bit (e.g., "0x123456789ABCDEF0")
//
// Examples:
//   #define JSON_GPU_METADATA_PCI_BAR0_START_HEX64 "bar0Start"  // Outputs as "0xC0000000"
//   #define JSON_GPU_METADATA_PCI_BAR0_SIZE        "bar0Size"   // Outputs as 67108864
//   #define JSON_BMC_EXAMPLE_BAR0_START            "bar0Start"  // Different field, decimal
//
// Usage:
//   Write: add_json_int_field(obj, JSON_GPU_METADATA_PCI_BAR0_START_HEX64, value)
//   Read:  value = get_json_int_field(obj, JSON_GPU_METADATA_PCI_BAR0_START_HEX64)

typedef enum {
	JSON_FORMAT_DECIMAL,
	JSON_FORMAT_HEX_8,
	JSON_FORMAT_HEX_16,
	JSON_FORMAT_HEX_32,
	JSON_FORMAT_HEX_64
} JSON_NUMBER_FORMAT;

// Helper: Extract format from #define name suffix
// E.g., "JSON_GPU_ABC_HEX64" -> JSON_FORMAT_HEX_64
//       "JSON_GPU_DEF"       -> JSON_FORMAT_DECIMAL (no suffix)
static JSON_NUMBER_FORMAT get_format_from_define_name(const char *define_name)
{
	if (define_name == NULL)
		return JSON_FORMAT_DECIMAL;

	size_t len = strlen(define_name);

	// Check for format suffixes (check longer suffixes first)
	if (len > 6 && strcmp(define_name + len - 6, "_HEX64") == 0)
		return JSON_FORMAT_HEX_64;
	if (len > 6 && strcmp(define_name + len - 6, "_HEX32") == 0)
		return JSON_FORMAT_HEX_32;
	if (len > 6 && strcmp(define_name + len - 6, "_HEX16") == 0)
		return JSON_FORMAT_HEX_16;
	if (len > 5 && strcmp(define_name + len - 5, "_HEX8") == 0)
		return JSON_FORMAT_HEX_8;

	return JSON_FORMAT_DECIMAL; // Default: no suffix = decimal
}

// Helper: Read integer field from JSON (handles both decimal int and hex string)
// Internal implementation - use get_json_int_field() macro instead
static int64_t _get_json_int_field_impl(json_object *obj,
					const char *define_name,
					const char *field_name)
{
	(void)define_name; // Format suffix only used for writing, not reading
	json_object *field_obj = json_object_object_get(obj, field_name);
	if (field_obj == NULL)
		return 0;

	if (json_object_is_type(field_obj, json_type_string)) {
		// Parse hex string like "0x1234" or decimal string
		const char *str = json_object_get_string(field_obj);
		if (str == NULL)
			return 0;
		return (int64_t)strtoll(str, NULL, 0);
	} else {
		return json_object_get_int64(field_obj);
	}
}

// Helper: Read uint64 field from JSON (handles both decimal int and hex string)
// Internal implementation - use get_json_uint64_field() macro instead
static uint64_t _get_json_uint64_field_impl(json_object *obj,
					    const char *define_name,
					    const char *field_name)
{
	(void)define_name; // Format suffix only used for writing, not reading
	json_object *field_obj = json_object_object_get(obj, field_name);
	if (field_obj == NULL)
		return 0;

	if (json_object_is_type(field_obj, json_type_string)) {
		// Parse hex string like "0x1234" or decimal string
		const char *str = json_object_get_string(field_obj);
		if (str == NULL)
			return 0;
		return strtoull(str, NULL, 0);
	} else {
		return (uint64_t)json_object_get_int64(field_obj);
	}
}

// Helper: Write integer field to JSON (uses format from #define name suffix)
// Internal implementation - use add_json_int_field() macro instead
static void _add_json_int_field_impl(json_object *obj, const char *define_name,
				     const char *field_name, int64_t value)
{
	JSON_NUMBER_FORMAT format = get_format_from_define_name(define_name);

	switch (format) {
	case JSON_FORMAT_HEX_8:
		add_int_hex_8(obj, field_name, (uint8_t)value);
		break;
	case JSON_FORMAT_HEX_16:
		add_int_hex_16(obj, field_name, (uint16_t)value);
		break;
	case JSON_FORMAT_HEX_32:
		add_int_hex_64(obj, field_name, (uint32_t)value);
		break;
	case JSON_FORMAT_HEX_64:
		add_int_hex_64(obj, field_name, (uint64_t)value);
		break;
	case JSON_FORMAT_DECIMAL:
	default:
		json_object_object_add(obj, field_name,
				       json_object_new_int64(value));
		break;
	}
}

// Helper: Write uint64 field to JSON (uses format from #define name suffix)
// Internal implementation - use add_json_uint64_field() macro instead
static void _add_json_uint64_field_impl(json_object *obj,
					const char *define_name,
					const char *field_name, uint64_t value)
{
	JSON_NUMBER_FORMAT format = get_format_from_define_name(define_name);

	switch (format) {
	case JSON_FORMAT_HEX_8:
		add_int_hex_8(obj, field_name, (uint8_t)value);
		break;
	case JSON_FORMAT_HEX_16:
		add_int_hex_16(obj, field_name, (uint16_t)value);
		break;
	case JSON_FORMAT_HEX_32:
		add_int_hex_64(obj, field_name, (uint32_t)value);
		break;
	case JSON_FORMAT_HEX_64:
		add_int_hex_64(obj, field_name, value);
		break;
	case JSON_FORMAT_DECIMAL:
	default:
		json_object_object_add(obj, field_name,
				       json_object_new_uint64(value));
		break;
	}
}

// Macro wrappers: Automatically pass both #define name (as string) and its value
// This allows format detection from the #define name suffix
#define get_json_int_field(obj, field_define)                                  \
	_get_json_int_field_impl(obj, #field_define, field_define)

#define get_json_uint64_field(obj, field_define)                               \
	_get_json_uint64_field_impl(obj, #field_define, field_define)

#define add_json_int_field(obj, field_define, value)                           \
	_add_json_int_field_impl(obj, #field_define, field_define, value)

#define add_json_uint64_field(obj, field_define, value)                        \
	_add_json_uint64_field_impl(obj, #field_define, field_define, value)

// ============================================================================
// Enums
typedef enum {
	OPAQUE = 0,
	TYPE_1 = 1,
	TYPE_2 = 2,
	TYPE_3 = 3,
	TYPE_4 = 4,
	// GPU-specific context data types
	GPU_INIT_METADATA = 0x8000,
	GPU_EVENT_LEGACY_XID = 0x8001,
	GPU_RECOMMENDED_ACTIONS = 0x8002
} NVIDIA_EVENT_CTX_DATA_TYPE;

typedef enum {
	CPU = 0,
	GPU = 1,
	DPU = 2,
	NIC = 3,
	SWX = 4,
	BMC = 5
} NVIDIA_EVENT_SRC_DEV;

// Callback structures
typedef struct {
	NVIDIA_EVENT_SRC_DEV srcDev;
	UINT8 major_version; // Expected major version for this handler
	UINT8 minor_version; // Expected minor version for this handler
	void (*callback)(EFI_NVIDIA_EVENT_HEADER *, json_object *);
	size_t (*callback_bin)(json_object *, FILE *);
} NV_EVENT_INFO_CALLBACKS;

typedef struct {
	NVIDIA_EVENT_SRC_DEV srcDev;
	NVIDIA_EVENT_CTX_DATA_TYPE dataFormatType;
	void (*callback)(EFI_NVIDIA_EVENT_HEADER *, size_t, size_t,
			 json_object *);
	size_t (*callback_bin)(json_object *, size_t, FILE *);
} NV_EVENT_CTX_CALLBACKS;

// Helper functions
// CPU info formatters
static void parse_cpu_info_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
				 json_object *event_info_ir);
static size_t parse_cpu_info_to_bin(json_object *event_info_ir, FILE *out);

// GPU info formatters
static void parse_gpu_info_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
				 json_object *event_info_ir);
static size_t parse_gpu_info_to_bin(json_object *event_info_ir, FILE *out);

// GPU context data formatters
static void parse_gpu_ctx_metadata_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
					 size_t total_event_size,
					 size_t ctx_instance,
					 json_object *output_data_ir);
static size_t parse_gpu_ctx_metadata_to_bin(json_object *event_ir,
					    size_t ctx_instance,
					    FILE *output_file_stream);
static void
parse_gpu_ctx_legacy_xid_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
			       size_t total_event_size, size_t ctx_instance,
			       json_object *output_data_ir);
static size_t parse_gpu_ctx_legacy_xid_to_bin(json_object *event_ir,
					      size_t ctx_instance,
					      FILE *output_file_stream);
static void parse_gpu_ctx_recommended_actions_to_ir(
	EFI_NVIDIA_EVENT_HEADER *event_header, size_t total_event_size,
	size_t ctx_instance, json_object *output_data_ir);
static size_t parse_gpu_ctx_recommended_actions_to_bin(
	json_object *event_ir, size_t ctx_instance, FILE *output_file_stream);

// Common context data type0 formatters
static void parse_common_ctx_type0_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
					 size_t total_event_size,
					 size_t ctx_instance,
					 json_object *output_data_ir);
static size_t parse_common_ctx_type0_to_bin(json_object *event_ir,
					    size_t ctx_instance,
					    FILE *output_file_stream);

// Common context data type1 formatters
static void parse_common_ctx_type1_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
					 size_t total_event_size,
					 size_t ctx_instance,
					 json_object *output_data_ir);
static size_t parse_common_ctx_type1_to_bin(json_object *event_ir,
					    size_t ctx_instance,
					    FILE *output_file_stream);

// Common context data type2 formatters
static void parse_common_ctx_type2_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
					 size_t total_event_size,
					 size_t ctx_instance,
					 json_object *output_data_ir);
static size_t parse_common_ctx_type2_to_bin(json_object *event_ir,
					    size_t ctx_instance,
					    FILE *output_file_stream);

// Common context data type3 formatters
static void parse_common_ctx_type3_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
					 size_t total_event_size,
					 size_t ctx_instance,
					 json_object *output_data_ir);
static size_t parse_common_ctx_type3_to_bin(json_object *event_ir,
					    size_t ctx_instance,
					    FILE *output_file_stream);

// Common context data type4 formatters
static void parse_common_ctx_type4_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
					 size_t total_event_size,
					 size_t ctx_instance,
					 json_object *output_data_ir);
static size_t parse_common_ctx_type4_to_bin(json_object *event_ir,
					    size_t ctx_instance,
					    FILE *output_file_stream);

// Macros
#define NVIDIA_EVENT_INFO_HANDLER_COUNT                                        \
	(sizeof(event_info_handlers) / sizeof(event_info_handlers[0]))
#define NVIDIA_GET_EVENT_INFO(header_ptr, dev_type)                            \
	((EFI_NVIDIA_##dev_type##_EVENT_INFO                                   \
		  *)((UINT8 *)(header_ptr) + sizeof(EFI_NVIDIA_EVENT_HEADER) + \
		     sizeof(EFI_NVIDIA_EVENT_INFO_HEADER)))
#define NVIDIA_GET_EVENT_CONTEXT_COUNT(event_header_ptr)                       \
	(size_t)((event_header_ptr)->EventContextCount)
#define NVIDIA_GET_EVENT_INFO_HEADER(event_header_ptr)                         \
	((EFI_NVIDIA_EVENT_INFO_HEADER *)((UINT8 *)(event_header_ptr) +        \
					  sizeof(EFI_NVIDIA_EVENT_HEADER)))
#define NVIDIA_GET_EVENT_CTX_DATA_TYPE(ctx_header_ptr)                         \
	((ctx_header_ptr)->DataFormatType)
#define NVIDIA_GET_EVENT_SOURCE_DEVICE_TYPE(event_header_ptr)                  \
	((NVIDIA_EVENT_SRC_DEV)((event_header_ptr)->SourceDeviceType))
#define NVIDIA_EVENT_CTX_HANDLER_COUNT                                         \
	(sizeof(event_ctx_handlers) / sizeof(event_ctx_handlers[0]))
// Extract major version from event info header: high byte of InfoVersion
#define NVIDIA_GET_INFO_MAJOR_VERSION(info_header_ptr)                         \
	((UINT8)(((info_header_ptr)->InfoVersion >> 8) & 0xFF))
// Extract minor version from event info header: low byte of InfoVersion
#define NVIDIA_GET_INFO_MINOR_VERSION(info_header_ptr)                         \
	((UINT8)((info_header_ptr)->InfoVersion & 0xFF))
// Check if info major version matches - if not, log error and break
#define NVIDIA_CHECK_INFO_MAJOR_VERSION(maj, min, exp_maj, operation)         \
	do {                                                                   \
		if ((maj) != (exp_maj)) {                                      \
			cper_print_log("Error: NVIDIA Event Info major version mismatch: " \
				       "expected %d.x, got %d.%d. Skipping event info %s.\n", \
				       (int)(exp_maj), (int)(maj), (int)(min), operation); \
			break;                                                 \
		}                                                              \
	} while (0)
// Check if info minor version is too old - if so, log error and break
#define NVIDIA_CHECK_INFO_MINOR_VERSION_MIN(maj, min, exp_maj, exp_min, operation) \
	do {                                                                   \
		if ((min) < (exp_min)) {                                       \
			cper_print_log("Error: NVIDIA Event Info minor version too old: " \
				       "expected %d.%d or newer, got %d.%d. Skipping event info %s.\n", \
				       (int)(exp_maj), (int)(exp_min), (int)(maj), (int)(min), operation); \
			break;                                                 \
		}                                                              \
	} while (0)
// Warn if info minor version is newer than expected (forward compatible)
#define NVIDIA_WARN_INFO_MINOR_VERSION_NEWER(maj, min, exp_maj, exp_min, operation) \
	do {                                                                   \
		if ((min) > (exp_min)) {                                       \
			cper_print_log("Warning: NVIDIA Event Info minor version newer than expected: " \
				       "expected %d.%d, got %d.%d. Proceeding with %s.\n", \
				       (int)(exp_maj), (int)(exp_min), (int)(maj), (int)(min), operation); \
		}                                                              \
	} while (0)
// Check if event header version matches - if not, log error and return with value
#define NVIDIA_CHECK_EVENT_HEADER_VERSION(ver, exp_ver, operation, retval)    \
	do {                                                                   \
		if ((ver) != (exp_ver)) {                                      \
			cper_print_log("Error: NVIDIA Event Header version mismatch: " \
				       "expected %d, got %d. Skipping event %s.\n", \
				       (int)(exp_ver), (int)(ver), operation);     \
			return retval;                                         \
		}                                                              \
	} while (0)
//Macro to write padding to 16 byte alignment
#define WRITE_PADDING_TO_16_BYTE_ALIGNMENT(bytes_written, out)                 \
	do {                                                                   \
		size_t __padding = (16 - ((bytes_written) % 16)) % 16;         \
		if (__padding > 0) {                                           \
			UINT8 __zeros[16] = { 0 };                             \
			fwrite(__zeros, 1, __padding, out);                    \
		}                                                              \
	} while (0)

// Event info handler callbacks for different device types.
// Note: The _to_bin callbacks should return the number of bytes written.
//       The caller is responsible for adding 16-byte alignment padding.
NV_EVENT_INFO_CALLBACKS event_info_handlers[] = {
	{ CPU, EFI_NVIDIA_CPU_EVENT_INFO_MAJ, EFI_NVIDIA_CPU_EVENT_INFO_MIN,
	  &parse_cpu_info_to_ir, &parse_cpu_info_to_bin },
	{ GPU, EFI_NVIDIA_GPU_EVENT_INFO_MAJ, EFI_NVIDIA_GPU_EVENT_INFO_MIN,
	  &parse_gpu_info_to_ir, &parse_gpu_info_to_bin }
};

// Event context handler callbacks for device-specific opaque data formats.
// This is where custom/opaque context data type handlers should be registered.
// Add entries here for device types that need special handling beyond the standard TYPE_1-4 formats.
// Note: The _to_bin callbacks should return the number of bytes written.
//       The caller is responsible for adding 16-byte alignment padding.
NV_EVENT_CTX_CALLBACKS event_ctx_handlers[] = {
	// GPU-specific context data handlers
	{ GPU, GPU_INIT_METADATA, &parse_gpu_ctx_metadata_to_ir,
	  &parse_gpu_ctx_metadata_to_bin },
	{ GPU, GPU_EVENT_LEGACY_XID, &parse_gpu_ctx_legacy_xid_to_ir,
	  &parse_gpu_ctx_legacy_xid_to_bin },
	{ GPU, GPU_RECOMMENDED_ACTIONS,
	  &parse_gpu_ctx_recommended_actions_to_ir,
	  &parse_gpu_ctx_recommended_actions_to_bin }
};

// Retrieves a pointer to the nth event context within an NVIDIA event structure.
// Walks through the event header, event info, and variable-sized contexts with bounds checking.
// Returns NULL if the index is out of bounds or if buffer overflow would occur.
static inline EFI_NVIDIA_EVENT_CTX_HEADER *
get_event_context_n(EFI_NVIDIA_EVENT_HEADER *event_header, size_t n,
		    size_t total_size)
{
	UINT8 *start = (UINT8 *)event_header;
	UINT8 *ptr = start + sizeof(EFI_NVIDIA_EVENT_HEADER);
	UINT8 *end = start + total_size;

	if (ptr + sizeof(EFI_NVIDIA_EVENT_INFO_HEADER) > end)
		return NULL;

	EFI_NVIDIA_EVENT_INFO_HEADER *info_header =
		(EFI_NVIDIA_EVENT_INFO_HEADER *)ptr;
	if (ptr + info_header->InfoSize > end)
		return NULL;
	ptr += info_header->InfoSize;
	for (size_t i = 0; i < n; i++) {
		if (ptr + sizeof(EFI_NVIDIA_EVENT_CTX_HEADER) > end)
			return NULL;
		EFI_NVIDIA_EVENT_CTX_HEADER *ctx =
			(EFI_NVIDIA_EVENT_CTX_HEADER *)ptr;
		if (ptr + ctx->CtxSize > end)
			return NULL;
		ptr += ctx->CtxSize;
	}

	if (ptr + sizeof(EFI_NVIDIA_EVENT_CTX_HEADER) > end)
		return NULL;
	return (EFI_NVIDIA_EVENT_CTX_HEADER *)ptr;
}

// Gets the nth event context from a JSON IR Event object.
// Returns NULL if the eventContexts field doesn't exist, isn't an object,
// or if n is out of bounds.
static inline json_object *get_event_context_n_ir(json_object *event_ir,
						  size_t n)
{
	if (event_ir == NULL)
		return NULL;

	// Get the eventContexts object
	json_object *event_contexts_ir =
		json_object_object_get(event_ir, JSON_EVENT_CONTEXTS);
	if (event_contexts_ir == NULL)
		return NULL;

	// Check if it's an array (preferred structure)
	if (json_object_is_type(event_contexts_ir, json_type_array)) {
		size_t array_len = json_object_array_length(event_contexts_ir);
		if (n >= array_len)
			return NULL;
		return json_object_array_get_idx(event_contexts_ir, n);
	}

	// Handle object structure with indexed keys (eventContext0, eventContext1, etc.)
	if (json_object_is_type(event_contexts_ir, json_type_object)) {
		char key[64];
		snprintf(key, sizeof(key), "eventContext%zu", n);
		return json_object_object_get(event_contexts_ir, key);
	}

	return NULL;
}

// Gets the data object from the nth event context in a JSON IR Event object.
// Combines get_event_context_n_ir and extraction of the data field.
// Returns NULL if the context doesn't exist, is out of bounds, or has no data.
static inline json_object *get_event_context_n_data_ir(json_object *event_ir,
						       size_t n)
{
	json_object *event_context_ir = get_event_context_n_ir(event_ir, n);
	if (event_context_ir == NULL)
		return NULL;

	return json_object_object_get(event_context_ir,
				      JSON_EVENT_CONTEXT_DATA);
}

// Parses CPU-specific event info structure into JSON IR format.
// Extracts socket number, architecture, ECID array, and instance base.
/*
 * Example JSON IR "data" output:
 * {
 *   "SocketNum": 0,
 *   "Architecture": 2684420096,
 *   "Ecid1": 1234567890123456789,
 *   "Ecid2": 9876543210987654321,
 *   "Ecid3": 5555555555555555555,
 *   "Ecid4": 1111111111111111111,
 *   "InstanceBase": 281474976710656
 * }
 */
static void parse_cpu_info_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
				 json_object *event_info_ir)
{
	EFI_NVIDIA_CPU_EVENT_INFO *cpu_event_info =
		NVIDIA_GET_EVENT_INFO(event_header, CPU);
	if (cpu_event_info == NULL)
		return;

	add_json_int_field(event_info_ir, JSON_CPU_INFO_SOCKET_NUM,
			   cpu_event_info->SocketNum);
	add_json_int_field(event_info_ir, JSON_CPU_INFO_ARCHITECTURE,
			   cpu_event_info->Architecture);
	add_json_uint64_field(event_info_ir, JSON_CPU_INFO_ECID1,
			      cpu_event_info->Ecid[0]);
	add_json_uint64_field(event_info_ir, JSON_CPU_INFO_ECID2,
			      cpu_event_info->Ecid[1]);
	add_json_uint64_field(event_info_ir, JSON_CPU_INFO_ECID3,
			      cpu_event_info->Ecid[2]);
	add_json_uint64_field(event_info_ir, JSON_CPU_INFO_ECID4,
			      cpu_event_info->Ecid[3]);
	add_json_uint64_field(event_info_ir, JSON_CPU_INFO_INSTANCE_BASE,
			      cpu_event_info->InstanceBase);
}
// Converts CPU-specific event info from JSON IR to CPER binary format.
// Writes socket number, architecture, ECID array, and instance base.
// Returns the number of bytes written.
/*
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_CPU_EVENT_INFO                                    (32 bytes) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   UINT8   SocketNum                                                     │
 * │   [padding - 3 bytes]                                                   │
 * │   UINT32  Architecture                                                  │
 * │   UINT32  Ecid[0]                                                       │
 * │   UINT32  Ecid[1]                                                       │
 * │   UINT32  Ecid[2]                                                       │
 * │   UINT32  Ecid[3]                                                       │
 * │   UINT64  InstanceBase                                                  │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
static size_t parse_cpu_info_to_bin(json_object *event_info_ir, FILE *out)
{
	EFI_NVIDIA_CPU_EVENT_INFO cpu_event_info = { 0 };
	cpu_event_info.SocketNum =
		get_json_int_field(event_info_ir, JSON_CPU_INFO_SOCKET_NUM);
	cpu_event_info.Architecture =
		get_json_int_field(event_info_ir, JSON_CPU_INFO_ARCHITECTURE);
	cpu_event_info.Ecid[0] = json_object_get_uint64(
		json_object_object_get(event_info_ir, JSON_CPU_INFO_ECID1));
	cpu_event_info.Ecid[1] = json_object_get_uint64(
		json_object_object_get(event_info_ir, JSON_CPU_INFO_ECID2));
	cpu_event_info.Ecid[2] = json_object_get_uint64(
		json_object_object_get(event_info_ir, JSON_CPU_INFO_ECID3));
	cpu_event_info.Ecid[3] = json_object_get_uint64(
		json_object_object_get(event_info_ir, JSON_CPU_INFO_ECID4));
	cpu_event_info.InstanceBase = json_object_get_uint64(
		json_object_object_get(event_info_ir,
				       JSON_CPU_INFO_INSTANCE_BASE));
	return fwrite(&cpu_event_info, 1, sizeof(EFI_NVIDIA_CPU_EVENT_INFO),
		      out);
}

// Parses GPU-specific event info structure into JSON IR format.
// Extracts version, size, event originator, partitions, and PDI.
/*
 * Example JSON IR "data" output:
 * {
 *   "EventOriginator": 2,
 *   "SourcePartition": 1,
 *   "SourceSubPartition": 0,
 *   "Pdi": 9876543210987654321
 * }
 */
static void parse_gpu_info_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
				 json_object *event_info_ir)
{
	EFI_NVIDIA_GPU_EVENT_INFO *gpu_event_info =
		NVIDIA_GET_EVENT_INFO(event_header, GPU);
	if (gpu_event_info == NULL)
		return;

	add_json_int_field(event_info_ir, JSON_GPU_INFO_EVENT_ORIGINATOR,
			   gpu_event_info->EventOriginator);	// UINT8
	add_json_int_field(event_info_ir, JSON_GPU_INFO_SOURCE_PARTITION,
			   gpu_event_info->SourcePartition);	// UINT16
	add_json_int_field(event_info_ir, JSON_GPU_INFO_SOURCE_SUBPARTITION,
			   gpu_event_info->SourceSubPartition); // UINT16
	add_json_uint64_field(event_info_ir, JSON_GPU_INFO_PDI,
			      gpu_event_info->Pdi);		// UINT64
}

// Converts GPU-specific event info from JSON IR to CPER binary format.
// Writes version, size, event originator, partitions, and PDI.
// Returns the number of bytes written.
/*
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_GPU_EVENT_INFO                                    (16 bytes) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   UINT8   EventOriginator                                               │
 * │   UINT16  SourcePartition                                               │
 * │   UINT16  SourceSubPartition                                            │
 * │   UINT64  Pdi                                                           │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
static size_t parse_gpu_info_to_bin(json_object *event_info_ir, FILE *out)
{
	EFI_NVIDIA_GPU_EVENT_INFO gpu_event_info = { 0 };

	gpu_event_info.EventOriginator = get_json_int_field(
		event_info_ir, JSON_GPU_INFO_EVENT_ORIGINATOR);
	gpu_event_info.SourcePartition = get_json_int_field(
		event_info_ir, JSON_GPU_INFO_SOURCE_PARTITION);
	gpu_event_info.SourceSubPartition = get_json_int_field(
		event_info_ir, JSON_GPU_INFO_SOURCE_SUBPARTITION);
	gpu_event_info.Pdi = json_object_get_uint64(
		json_object_object_get(event_info_ir, JSON_GPU_INFO_PDI));

	return fwrite(&gpu_event_info, 1, sizeof(EFI_NVIDIA_GPU_EVENT_INFO),
		      out);
}

// GPU Context Data Handlers

// Parses GPU Initialization Metadata (0x1000) context data to JSON IR.
// Extracts device info, firmware versions, PCI info, etc.
/*
 * Example JSON IR "data" output (numeric fields in decimal):
 * {
 *   "deviceName": "NVIDIA H100 80GB HBM3",
 *   "firmwareVersion": "96.00.5B.00.01",
 *   "pfDriverMicrocodeVersion": "535.183.01",
 *   "pfDriverVersion": "535.183.01",
 *   "vfDriverVersion": "535.183.01",
 *   "configuration": 123456789012345,
 *   "pdi": 9876543210987654321,
 *   "architectureId": 2684420096,
 *   "hardwareInfoType": 0,
 *   "pciInfo": {
 *     "class": 3,
 *     "subclass": 2,
 *     "rev": 161,
 *     "vendorId": 4318,
 *     "deviceId": 8711,
 *     "subsystemVendorId": 4318,
 *     "subsystemId": 5145,
 *     "bar0Start": 3758096384,
 *     "bar0Size": 16777216,
 *     "bar1Start": 2415919104,
 *     "bar1Size": 536870912,
 *     "bar2Start": 2416128000,
 *     "bar2Size": 33554432
 *   }
 * }
 */
static void parse_gpu_ctx_metadata_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
					 size_t total_event_size,
					 size_t ctx_instance,
					 json_object *output_data_ir)
{
	EFI_NVIDIA_EVENT_CTX_HEADER *ctx = get_event_context_n(
		event_header, ctx_instance, total_event_size);
	if (ctx == NULL)
		return;

	EFI_NVIDIA_GPU_CTX_METADATA *metadata =
		(EFI_NVIDIA_GPU_CTX_METADATA *)ctx->Data;

	// String fields - use json_object_new_string to stop at first null (no null padding in JSON)
	json_object_object_add(output_data_ir, JSON_GPU_METADATA_DEVICE_NAME,
			       json_object_new_string(metadata->DeviceName));
	json_object_object_add(
		output_data_ir, JSON_GPU_METADATA_FIRMWARE_VERSION,
		json_object_new_string(metadata->FirmwareVersion));
	json_object_object_add(
		output_data_ir, JSON_GPU_METADATA_PF_DRIVER_UCODE_VERSION,
		json_object_new_string(metadata->PfDriverMicrocodeVersion));
	json_object_object_add(
		output_data_ir, JSON_GPU_METADATA_PF_DRIVER_VERSION,
		json_object_new_string(metadata->PfDriverVersion));
	json_object_object_add(
		output_data_ir, JSON_GPU_METADATA_VF_DRIVER_VERSION,
		json_object_new_string(metadata->VfDriverVersion));

	// Numeric fields
	add_json_uint64_field(output_data_ir, JSON_GPU_METADATA_CONFIGURATION,
			      metadata->Configuration);
	add_json_uint64_field(output_data_ir, JSON_GPU_METADATA_PDI,
			      metadata->Pdi);
	add_json_int_field(output_data_ir, JSON_GPU_METADATA_ARCHITECTURE_ID,
			   metadata->ArchitectureId);
	add_json_int_field(output_data_ir, JSON_GPU_METADATA_HW_INFO_TYPE,
			   metadata->HardwareInfoType);

	// PCI Info (if HardwareInfoType == 0)
	if (metadata->HardwareInfoType == 0) {
		json_object *pci_info = json_object_new_object();
		add_json_int_field(pci_info, JSON_GPU_METADATA_PCI_CLASS,
				   metadata->PciInfo.Class);
		add_json_int_field(pci_info, JSON_GPU_METADATA_PCI_SUBCLASS,
				   metadata->PciInfo.Subclass);
		add_json_int_field(pci_info, JSON_GPU_METADATA_PCI_REV,
				   metadata->PciInfo.Rev);
		add_json_int_field(pci_info,
				   JSON_GPU_METADATA_PCI_VENDOR_ID,
				   metadata->PciInfo.VendorId);
		add_json_int_field(pci_info,
				   JSON_GPU_METADATA_PCI_DEVICE_ID,
				   metadata->PciInfo.DeviceId);
		add_json_int_field(pci_info,
				   JSON_GPU_METADATA_PCI_SUBSYS_VENDOR_ID,
				   metadata->PciInfo.SubsystemVendorId);
		add_json_int_field(pci_info,
				   JSON_GPU_METADATA_PCI_SUBSYS_ID,
				   metadata->PciInfo.SubsystemId);
		add_json_uint64_field(pci_info, JSON_GPU_METADATA_PCI_BAR0_START,
				      metadata->PciInfo.Bar0Start);
		add_json_uint64_field(pci_info, JSON_GPU_METADATA_PCI_BAR0_SIZE,
				      metadata->PciInfo.Bar0Size);
		add_json_uint64_field(pci_info, JSON_GPU_METADATA_PCI_BAR1_START,
				      metadata->PciInfo.Bar1Start);
		add_json_uint64_field(pci_info, JSON_GPU_METADATA_PCI_BAR1_SIZE,
				      metadata->PciInfo.Bar1Size);
		add_json_uint64_field(pci_info, JSON_GPU_METADATA_PCI_BAR2_START,
				      metadata->PciInfo.Bar2Start);
		add_json_uint64_field(pci_info, JSON_GPU_METADATA_PCI_BAR2_SIZE,
				      metadata->PciInfo.Bar2Size);
		json_object_object_add(output_data_ir,
				       JSON_GPU_METADATA_PCI_INFO, pci_info);
	}
}

// Converts GPU Initialization Metadata from JSON IR to binary.
// Returns the number of bytes written.
/*
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_GPU_CTX_METADATA                                 (192 bytes) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   CHAR8   DeviceName[48]                                                │
 * │   CHAR8   FirmwareVersion[16]                                           │
 * │   CHAR8   PfDriverMicrocodeVersion[16]                                  │
 * │   CHAR8   PfDriverVersion[16]                                           │
 * │   CHAR8   VfDriverVersion[16]                                           │
 * │   UINT64  Configuration                                                 │
 * │   UINT64  Pdi                                                           │
 * │   UINT32  ArchitectureId                                                │
 * │   UINT8   HardwareInfoType         ← 0=PCI Info, 1-255=Reserved         │
 * │   union (59 bytes):                                                     │
 * │     EFI_NVIDIA_GPU_CTX_METADATA_PCI_INFO PciInfo (when type = 0):       │
 * │       UINT8   Class, Subclass, Rev                                      │
 * │       UINT16  VendorId, DeviceId, SubsystemVendorId, SubsystemId        │
 * │       UINT64  Bar0Start, Bar0Size, Bar1Start, Bar1Size, Bar2Start, ...  │
 * │     UINT8 Reserved[59]             ← for future hardware info types     │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
static size_t parse_gpu_ctx_metadata_to_bin(json_object *event_ir,
					    size_t ctx_instance,
					    FILE *output_file_stream)
{
	json_object *event_context_data_ir =
		get_event_context_n_data_ir(event_ir, ctx_instance);
	if (event_context_data_ir == NULL)
		return 0;

	EFI_NVIDIA_GPU_CTX_METADATA metadata = { 0 };

	// String fields - use memcpy with strnlen to avoid strncpy truncation warnings
	const char *str;
	str = json_object_get_string(json_object_object_get(
		event_context_data_ir, JSON_GPU_METADATA_DEVICE_NAME));
	if (str)
		memcpy(metadata.DeviceName, str,
		       strnlen(str, sizeof(metadata.DeviceName)));

	str = json_object_get_string(json_object_object_get(
		event_context_data_ir, JSON_GPU_METADATA_FIRMWARE_VERSION));
	if (str)
		memcpy(metadata.FirmwareVersion, str,
		       strnlen(str, sizeof(metadata.FirmwareVersion)));

	str = json_object_get_string(json_object_object_get(
		event_context_data_ir,
		JSON_GPU_METADATA_PF_DRIVER_UCODE_VERSION));
	if (str)
		memcpy(metadata.PfDriverMicrocodeVersion, str,
		       strnlen(str, sizeof(metadata.PfDriverMicrocodeVersion)));

	str = json_object_get_string(json_object_object_get(
		event_context_data_ir, JSON_GPU_METADATA_PF_DRIVER_VERSION));
	if (str)
		memcpy(metadata.PfDriverVersion, str,
		       strnlen(str, sizeof(metadata.PfDriverVersion)));

	str = json_object_get_string(json_object_object_get(
		event_context_data_ir, JSON_GPU_METADATA_VF_DRIVER_VERSION));
	if (str)
		memcpy(metadata.VfDriverVersion, str,
		       strnlen(str, sizeof(metadata.VfDriverVersion)));

	// Numeric fields
	metadata.Configuration = json_object_get_uint64(json_object_object_get(
		event_context_data_ir, JSON_GPU_METADATA_CONFIGURATION));
	metadata.Pdi = json_object_get_uint64(json_object_object_get(
		event_context_data_ir, JSON_GPU_METADATA_PDI));
	metadata.ArchitectureId = get_json_int_field(
		event_context_data_ir, JSON_GPU_METADATA_ARCHITECTURE_ID);
	metadata.HardwareInfoType = get_json_int_field(
		event_context_data_ir, JSON_GPU_METADATA_HW_INFO_TYPE);

	// PCI Info (if present and HardwareInfoType == 0)
	json_object *pci_info = json_object_object_get(
		event_context_data_ir, JSON_GPU_METADATA_PCI_INFO);
	if (pci_info != NULL && metadata.HardwareInfoType == 0) {
		metadata.PciInfo.Class =
			get_json_int_field(pci_info, JSON_GPU_METADATA_PCI_CLASS);
		metadata.PciInfo.Subclass = get_json_int_field(
			pci_info, JSON_GPU_METADATA_PCI_SUBCLASS);
		metadata.PciInfo.Rev =
			get_json_int_field(pci_info, JSON_GPU_METADATA_PCI_REV);
		metadata.PciInfo.VendorId = get_json_int_field(
			pci_info, JSON_GPU_METADATA_PCI_VENDOR_ID);
		metadata.PciInfo.DeviceId = get_json_int_field(
			pci_info, JSON_GPU_METADATA_PCI_DEVICE_ID);
		metadata.PciInfo.SubsystemVendorId = get_json_int_field(
			pci_info, JSON_GPU_METADATA_PCI_SUBSYS_VENDOR_ID);
		metadata.PciInfo.SubsystemId = get_json_int_field(
			pci_info, JSON_GPU_METADATA_PCI_SUBSYS_ID);
		metadata.PciInfo.Bar0Start = get_json_uint64_field(
			pci_info, JSON_GPU_METADATA_PCI_BAR0_START);
		metadata.PciInfo.Bar0Size = get_json_uint64_field(
			pci_info, JSON_GPU_METADATA_PCI_BAR0_SIZE);
		metadata.PciInfo.Bar1Start = get_json_uint64_field(
			pci_info, JSON_GPU_METADATA_PCI_BAR1_START);
		metadata.PciInfo.Bar1Size = get_json_uint64_field(
			pci_info, JSON_GPU_METADATA_PCI_BAR1_SIZE);
		metadata.PciInfo.Bar2Start = get_json_uint64_field(
			pci_info, JSON_GPU_METADATA_PCI_BAR2_START);
		metadata.PciInfo.Bar2Size = get_json_uint64_field(
			pci_info, JSON_GPU_METADATA_PCI_BAR2_SIZE);
	}

	return fwrite(&metadata, 1, sizeof(EFI_NVIDIA_GPU_CTX_METADATA),
		      output_file_stream);
}

// Parses GPU Event Legacy Xid (0x1001) context data to JSON IR.
// Extracts Xid code and message string.
/*
 * Example JSON IR "data" output:
 * {
 *   "xidCode": 79,
 *   "message": "GPU has fallen off the bus"
 * }
 */
static void
parse_gpu_ctx_legacy_xid_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
			       size_t total_event_size, size_t ctx_instance,
			       json_object *output_data_ir)
{
	EFI_NVIDIA_EVENT_CTX_HEADER *ctx = get_event_context_n(
		event_header, ctx_instance, total_event_size);
	if (ctx == NULL)
		return;

	EFI_NVIDIA_GPU_CTX_LEGACY_XID *xid =
		(EFI_NVIDIA_GPU_CTX_LEGACY_XID *)ctx->Data;

	add_json_int_field(output_data_ir, JSON_GPU_XID_CODE, xid->XidCode);
	// Use json_object_new_string to stop at first null terminator (no null padding in JSON)
	json_object_object_add(output_data_ir, JSON_GPU_XID_MESSAGE,
			       json_object_new_string(xid->Message));
}

// Converts GPU Event Legacy Xid from JSON IR to binary.
// Returns the number of bytes written.
/*
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_GPU_CTX_LEGACY_XID                               (240 bytes) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   UINT32  XidCode              ← Legacy Xid error code                  │
 * │   CHAR8   Message[236]         ← NUL-terminated ASCII event message     │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
static size_t parse_gpu_ctx_legacy_xid_to_bin(json_object *event_ir,
					      size_t ctx_instance,
					      FILE *output_file_stream)
{
	json_object *event_context_data_ir =
		get_event_context_n_data_ir(event_ir, ctx_instance);
	if (event_context_data_ir == NULL)
		return 0;

	EFI_NVIDIA_GPU_CTX_LEGACY_XID xid = { 0 };

	xid.XidCode =
		get_json_int_field(event_context_data_ir, JSON_GPU_XID_CODE);

	const char *message = json_object_get_string(json_object_object_get(
		event_context_data_ir, JSON_GPU_XID_MESSAGE));
	if (message)
		memcpy(xid.Message, message, strnlen(message, sizeof(xid.Message)));

	return fwrite(&xid, 1, sizeof(EFI_NVIDIA_GPU_CTX_LEGACY_XID),
		      output_file_stream);
}

// Parses GPU Recommended Actions (0x1002) context data to JSON IR.
// Extracts flags, recovery action, and diagnostic flow code.
/*
 * Example JSON IR "data" output:
 * {
 *   "flags": 3,
 *   "recoveryAction": 2,
 *   "diagnosticFlow": 0
 * }
 */
static void parse_gpu_ctx_recommended_actions_to_ir(
	EFI_NVIDIA_EVENT_HEADER *event_header, size_t total_event_size,
	size_t ctx_instance, json_object *output_data_ir)
{
	EFI_NVIDIA_EVENT_CTX_HEADER *ctx = get_event_context_n(
		event_header, ctx_instance, total_event_size);
	if (ctx == NULL)
		return;

	EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS *actions =
		(EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS *)ctx->Data;

	add_json_int_field(output_data_ir, JSON_GPU_ACTIONS_FLAGS,
			   actions->Flags);
	add_json_int_field(output_data_ir, JSON_GPU_ACTIONS_RECOVERY_ACTION,
			   actions->RecoveryAction);
	add_json_int_field(output_data_ir, JSON_GPU_ACTIONS_DIAGNOSTIC_FLOW,
			   actions->DiagnosticFlow);
}

// Converts GPU Recommended Actions from JSON IR to binary.
// Returns the number of bytes written.
/*
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS                       (16 bytes) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   UINT8   Flags                                                         │
 * │   UINT8   Reserved1[3]         ← padding                                │
 * │   UINT16  RecoveryAction                                                │
 * │   UINT16  DiagnosticFlow       ← 0=Unspecified                          │
 * │   UINT64  Reserved2            ← padding to 16-byte alignment           │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
static size_t parse_gpu_ctx_recommended_actions_to_bin(json_object *event_ir,
						       size_t ctx_instance,
						       FILE *output_file_stream)
{
	json_object *event_context_data_ir =
		get_event_context_n_data_ir(event_ir, ctx_instance);
	if (event_context_data_ir == NULL)
		return 0;

	EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS actions = { 0 };

	actions.Flags = get_json_int_field(event_context_data_ir,
					   JSON_GPU_ACTIONS_FLAGS);
	actions.RecoveryAction = get_json_int_field(
		event_context_data_ir, JSON_GPU_ACTIONS_RECOVERY_ACTION);
	actions.DiagnosticFlow = get_json_int_field(
		event_context_data_ir, JSON_GPU_ACTIONS_DIAGNOSTIC_FLOW);

	return fwrite(&actions, 1,
		      sizeof(EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS),
		      output_file_stream);
}

// Parses event context data type 0: Opaque data.
// Extracts the opaque data from the context data.
/*
 * Example JSON IR "data" output:
 * {
 *   "data": "deadbeefcafebabe..."
 * }
 */
static void parse_common_ctx_type0_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
					 size_t total_event_size,
					 size_t ctx_instance,
					 json_object *output_data_ir)
{
	// Get the nth context
	EFI_NVIDIA_EVENT_CTX_HEADER *ctx = get_event_context_n(
		event_header, ctx_instance, total_event_size);
	if (ctx == NULL) {
		cper_print_log(
			"Error: Failed to get context %zu for opaque data\n",
			ctx_instance);
		return;
	}

	// Verify the context doesn't extend past the event boundary
	UINT8 *ctx_start = (UINT8 *)ctx;
	UINT8 *event_start = (UINT8 *)event_header;
	size_t ctx_offset = ctx_start - event_start;
	size_t ctx_total_size =
		sizeof(EFI_NVIDIA_EVENT_CTX_HEADER) + ctx->DataSize;

	if (ctx_offset + ctx_total_size > total_event_size) {
		cper_print_log(
			"Error: Opaque context %zu extends past event boundary\n",
			ctx_instance);
		return;
	}

	// The opaque data starts right after the context header
	UINT8 *opaque_data = (UINT8 *)ctx + sizeof(EFI_NVIDIA_EVENT_CTX_HEADER);
	UINT32 data_size = ctx->DataSize;

	// Encode the opaque data as hex
	size_t encoded_len = 0;
	char *encoded = hex_encode(opaque_data, data_size, &encoded_len);
	if (encoded == NULL) {
		cper_print_log("Error: hex encode of opaque data failed\n");
		return;
	}

	// Add the hex string to the JSON output
	json_object_object_add(output_data_ir, "data",
			       json_object_new_string_len(encoded,
							  (int)encoded_len));
	free(encoded);
}
// Converts opaque context data from JSON IR to binary.
// Returns the number of bytes written.
/*
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ OPAQUE DATA (Context Data Type 0x0000)                 (variable bytes) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   UINT8   Data[]               ← Device-specific binary data            │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
static size_t parse_common_ctx_type0_to_bin(json_object *event_ir,
					    size_t ctx_instance,
					    FILE *output_file_stream)
{
	// Get the context data using the helper function
	json_object *event_context_data_ir =
		get_event_context_n_data_ir(event_ir, ctx_instance);

	if (event_context_data_ir == NULL) {
		cper_print_log(
			"Error: Failed to get context %zu data for opaque conversion\n",
			ctx_instance);
		return 0;
	}

	// Get the base64 encoded data string
	json_object *encoded_data =
		json_object_object_get(event_context_data_ir, "data");

	if (encoded_data == NULL) {
		cper_print_log(
			"Error: No 'data' field found in opaque context\n");
		return 0;
	}

	// Verify the data field is actually a string
	if (!json_object_is_type(encoded_data, json_type_string)) {
		cper_print_log(
			"Error: 'data' field in opaque context is not a string\n");
		return 0;
	}

	const char *encoded_str = json_object_get_string(encoded_data);
	if (encoded_str == NULL) {
		cper_print_log("Error: Failed to get string from 'data' field\n");
		return 0;
	}
	size_t encoded_len = (size_t)json_object_get_string_len(encoded_data);

	// Decode the hex data
	size_t decoded_len = 0;
	UINT8 *decoded = hex_decode(encoded_str, encoded_len, &decoded_len);
	if (decoded == NULL) {
		cper_print_log("Error: hex decode of opaque data failed\n");
		return 0;
	}

	// Write the decoded binary data to the output stream
	size_t bytes_written =
		fwrite(decoded, 1, decoded_len, output_file_stream);
	free(decoded);

	return bytes_written;
}
// Parses event context data type 1: 64-bit key/value pairs.
// Extracts an array of UINT64 key-value pairs from the context data.
/*
 * Example JSON IR "data" output:
 * {
 *   "keyValArray64": [
 *     { "key64": 1234567890123456789, "val64": 9876543210987654321 },
 *     { "key64": 5555555555555555555, "val64": 1111111111111111111 }
 *   ]
 * }
 */
static void parse_common_ctx_type1_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
					 size_t total_event_size,
					 size_t ctx_instance,
					 json_object *output_data_ir)
{
	EFI_NVIDIA_EVENT_CTX_HEADER *ctx = get_event_context_n(
		event_header, ctx_instance, total_event_size);
	if (ctx == NULL)
		return;

	EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1 *data_type1 =
		(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1 *)ctx->Data;
	UINT8 num_elements =
		ctx->DataSize / sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1);

	json_object *kv64arr = json_object_new_array();
	for (int i = 0; i < num_elements; i++, data_type1++) {
		json_object *kv = NULL;
		kv = json_object_new_object();
		add_json_uint64_field(kv, JSON_CONTEXT_DATA_TYPE1_KEY64,
				      data_type1->Key);
		add_json_uint64_field(kv, JSON_CONTEXT_DATA_TYPE1_VAL64,
				      data_type1->Value);

		json_object_array_add(kv64arr, kv);
	}
	json_object_object_add(output_data_ir,
			       JSON_CONTEXT_DATA_TYPE1_KV64_ARRAY, kv64arr);
}
// Converts event context data type 1 from JSON IR to CPER binary format.
// Writes an array of 64-bit key/value pairs to the output stream.
// Returns the total number of bytes written.
/*
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1 (Context Data Type 0x0001) (16 bytes)  │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   UINT64  Key                  ← 64-bit key                             │
 * │   UINT64  Value                ← 64-bit value                           │
 * └─────────────────────────────────────────────────────────────────────────┘
 * Note: This structure repeats for each key-value pair in the array
 */
static size_t parse_common_ctx_type1_to_bin(json_object *event_ir,
					    size_t ctx_instance,
					    FILE *output_file_stream)
{
	json_object *event_context_data_ir =
		get_event_context_n_data_ir(event_ir, ctx_instance);
	if (event_context_data_ir == NULL)
		return 0;

	// Get the kv64-array that was created by parse_common_ctx_type1_to_ir
	json_object *kv64arr = json_object_object_get(
		event_context_data_ir, JSON_CONTEXT_DATA_TYPE1_KV64_ARRAY);
	if (kv64arr == NULL)
		return 0;

	size_t array_len = json_object_array_length(kv64arr);
	size_t bytes_written = 0;

	// Iterate through each key-value pair in the array
	for (size_t i = 0; i < array_len; i++) {
		json_object *kv = json_object_array_get_idx(kv64arr, i);
		if (kv == NULL)
			continue;

		// Create and populate the binary structure
		EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1 data_type1 = { 0 };
		data_type1.Key = json_object_get_uint64(json_object_object_get(
			kv, JSON_CONTEXT_DATA_TYPE1_KEY64));
		data_type1.Value = json_object_get_uint64(
			json_object_object_get(kv,
					       JSON_CONTEXT_DATA_TYPE1_VAL64));

		// Write to binary file
		bytes_written +=
			fwrite(&data_type1, 1,
			       sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1),
			       output_file_stream);
	}
	return bytes_written;
}
// Parses event context data type 2: 32-bit key/value pairs.
// Extracts an array of UINT32 key-value pairs from the context data.
/*
 * Example JSON IR "data" output:
 * {
 *   "keyValArray32": [
 *     { "key32": 123456789, "val32": 987654321 },
 *     { "key32": 555555555, "val32": 111111111 }
 *   ]
 * }
 */
static void parse_common_ctx_type2_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
					 size_t total_event_size,
					 size_t ctx_instance,
					 json_object *output_data_ir)
{
	EFI_NVIDIA_EVENT_CTX_HEADER *ctx = get_event_context_n(
		event_header, ctx_instance, total_event_size);
	if (ctx == NULL)
		return;

	EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2 *data_type2 =
		(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2 *)ctx->Data;
	UINT8 num_elements =
		ctx->DataSize / sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2);

	json_object *kv32arr = json_object_new_array();
	for (int i = 0; i < num_elements; i++, data_type2++) {
		json_object *kv = NULL;
		kv = json_object_new_object();
		add_json_uint64_field(kv, JSON_CONTEXT_DATA_TYPE2_KEY32,
				      data_type2->Key);
		add_json_uint64_field(kv, JSON_CONTEXT_DATA_TYPE2_VAL32,
				      data_type2->Value);

		json_object_array_add(kv32arr, kv);
	}
	json_object_object_add(output_data_ir,
			       JSON_CONTEXT_DATA_TYPE2_KV32_ARRAY, kv32arr);
}
// Converts event context data type 2 from JSON IR to CPER binary format.
// Writes an array of 32-bit key/value pairs to the output stream.
// Returns the total number of bytes written.
/*
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2 (Context Data Type 0x0002)  (8 bytes)  │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   UINT32  Key                  ← 32-bit key                             │
 * │   UINT32  Value                ← 32-bit value                           │
 * └─────────────────────────────────────────────────────────────────────────┘
 * Note: This structure repeats for each key-value pair in the array
 */
static size_t parse_common_ctx_type2_to_bin(json_object *event_ir,
					    size_t ctx_instance,
					    FILE *output_file_stream)
{
	json_object *event_context_data_ir =
		get_event_context_n_data_ir(event_ir, ctx_instance);
	if (event_context_data_ir == NULL)
		return 0;

	// Get the kv32-array that was created by parse_common_ctx_type2_to_ir
	json_object *kv32arr = json_object_object_get(
		event_context_data_ir, JSON_CONTEXT_DATA_TYPE2_KV32_ARRAY);
	if (kv32arr == NULL)
		return 0;

	size_t array_len = json_object_array_length(kv32arr);
	size_t bytes_written = 0;

	// Iterate through each key-value pair in the array
	for (size_t i = 0; i < array_len; i++) {
		json_object *kv = json_object_array_get_idx(kv32arr, i);
		if (kv == NULL)
			continue;

		// Create and populate the binary structure
		EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2 data_type2 = { 0 };
		data_type2.Key = json_object_get_uint64(json_object_object_get(
			kv, JSON_CONTEXT_DATA_TYPE2_KEY32));
		data_type2.Value = json_object_get_uint64(
			json_object_object_get(kv,
					       JSON_CONTEXT_DATA_TYPE2_VAL32));

		// Write to binary file
		bytes_written +=
			fwrite(&data_type2, 1,
			       sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2),
			       output_file_stream);
	}
	return bytes_written;
}
// Parses event context data type 3: 64-bit values only.
// Extracts an array of UINT64 values (no keys) from the context data.
/*
 * Example JSON IR "data" output:
 * {
 *   "valArray64": [
 *     { "val64": 1234567890123456789 },
 *     { "val64": 9876543210987654321 }
 *   ]
 * }
 */
static void parse_common_ctx_type3_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
					 size_t total_event_size,
					 size_t ctx_instance,
					 json_object *output_data_ir)
{
	EFI_NVIDIA_EVENT_CTX_HEADER *ctx = get_event_context_n(
		event_header, ctx_instance, total_event_size);
	if (ctx == NULL)
		return;

	EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3 *data_type3 =
		(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3 *)ctx->Data;
	UINT8 num_elements =
		ctx->DataSize / sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3);

	json_object *val64arr = json_object_new_array();
	for (int i = 0; i < num_elements; i++, data_type3++) {
		json_object *v = NULL;
		v = json_object_new_object();
		add_json_uint64_field(v, JSON_CONTEXT_DATA_TYPE3_VAL64,
				      data_type3->Value);

		json_object_array_add(val64arr, v);
	}
	json_object_object_add(output_data_ir,
			       JSON_CONTEXT_DATA_TYPE3_V64_ARRAY, val64arr);
}
// Converts event context data type 3 from JSON IR to CPER binary format.
// Writes an array of 64-bit values (no keys) to the output stream.
// Returns the total number of bytes written.
/*
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3 (Context Data Type 0x0003)  (8 bytes)  │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   UINT64  Value                ← 64-bit value (no key)                  │
 * └─────────────────────────────────────────────────────────────────────────┘
 * Note: This structure repeats for each value in the array
 */
static size_t parse_common_ctx_type3_to_bin(json_object *event_ir,
					    size_t ctx_instance,
					    FILE *output_file_stream)
{
	json_object *event_context_data_ir =
		get_event_context_n_data_ir(event_ir, ctx_instance);
	if (event_context_data_ir == NULL)
		return 0;

	// Get the v64-array that was created by parse_common_ctx_type3_to_ir
	json_object *v64arr = json_object_object_get(
		event_context_data_ir, JSON_CONTEXT_DATA_TYPE3_V64_ARRAY);
	if (v64arr == NULL)
		return 0;

	size_t array_len = json_object_array_length(v64arr);
	size_t bytes_written = 0;

	// Iterate through each key-value pair in the array
	for (size_t i = 0; i < array_len; i++) {
		json_object *v = json_object_array_get_idx(v64arr, i);
		if (v == NULL)
			continue;

		// Create and populate the binary structure
		EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3 data_type3 = { 0 };
		data_type3.Value = json_object_get_uint64(
			json_object_object_get(v,
					       JSON_CONTEXT_DATA_TYPE3_VAL64));

		// Write to binary file
		bytes_written +=
			fwrite(&data_type3, 1,
			       sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3),
			       output_file_stream);
	}
	return bytes_written;
}
// Parses event context data type 4: 32-bit values only.
// Extracts an array of UINT32 values (no keys) from the context data.
/*
 * Example JSON IR "data" output:
 * {
 *   "valArray32": [
 *     { "val32": 123456789 },
 *     { "val32": 987654321 }
 *   ]
 * }
 */
static void parse_common_ctx_type4_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
					 size_t total_event_size,
					 size_t ctx_instance,
					 json_object *output_data_ir)
{
	EFI_NVIDIA_EVENT_CTX_HEADER *ctx = get_event_context_n(
		event_header, ctx_instance, total_event_size);
	if (ctx == NULL)
		return;

	EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4 *data_type4 =
		(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4 *)ctx->Data;
	UINT8 num_elements =
		ctx->DataSize / sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4);

	json_object *val32arr = json_object_new_array();
	for (int i = 0; i < num_elements; i++, data_type4++) {
		json_object *v = NULL;
		v = json_object_new_object();
		add_json_uint64_field(v, JSON_CONTEXT_DATA_TYPE4_VAL32,
				      data_type4->Value);

		json_object_array_add(val32arr, v);
	}
	json_object_object_add(output_data_ir,
			       JSON_CONTEXT_DATA_TYPE4_V32_ARRAY, val32arr);
}
// Converts event context data type 4 from JSON IR to CPER binary format.
// Writes an array of 32-bit values (no keys) to the output stream.
// Returns the total number of bytes written.
/*
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4 (Context Data Type 0x0004)  (4 bytes)  │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   UINT32  Value                ← 32-bit value (no key)                  │
 * └─────────────────────────────────────────────────────────────────────────┘
 * Note: This structure repeats for each value in the array
 */
static size_t parse_common_ctx_type4_to_bin(json_object *event_ir,
					    size_t ctx_instance,
					    FILE *output_file_stream)
{
	json_object *event_context_data_ir =
		get_event_context_n_data_ir(event_ir, ctx_instance);
	if (event_context_data_ir == NULL)
		return 0;

	// Get the v32-array that was created by parse_common_ctx_type4_to_ir
	json_object *v32arr = json_object_object_get(
		event_context_data_ir, JSON_CONTEXT_DATA_TYPE4_V32_ARRAY);
	if (v32arr == NULL)
		return 0;

	size_t array_len = json_object_array_length(v32arr);
	size_t bytes_written = 0;

	// Iterate through each key-value pair in the array
	for (size_t i = 0; i < array_len; i++) {
		json_object *v = json_object_array_get_idx(v32arr, i);
		if (v == NULL)
			continue;

		// Create and populate the binary structure
		EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4 data_type4 = { 0 };
		data_type4.Value = json_object_get_uint64(
			json_object_object_get(v,
					       JSON_CONTEXT_DATA_TYPE4_VAL32));

		// Write to binary file
		bytes_written +=
			fwrite(&data_type4, 1,
			       sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4),
			       output_file_stream);
	}
	return bytes_written;
}
// Converts a single NVIDIA event-based CPER section into JSON IR format.
// Parses the event header, device-specific event info, and all event contexts.
// Supports custom handlers for specific device types and data formats.
/*
 * Example JSON IR output for a CPU device with Type 1 context:
 * {
 *   "eventHeader": {
 *     "signature": "CPU-FAULT",
 *     "version": 1,
 *     "contextCount": 1,
 *     "sourceDeviceType": 0,
 *     "type": 100,
 *     "subtype": 200,
 *     "linkId": 0
 *   },
 *   "eventInfo": {
 *     "version": 0,
 *     "size": 32,
 *     "SocketNum": 0,
 *     "Architecture": 2684420096,
 *     "Ecid1": 1234567890123456789,
 *     "Ecid2": 9876543210987654321,
 *     "Ecid3": 5555555555555555555,
 *     "Ecid4": 1111111111111111111,
 *     "InstanceBase": 281474976710656
 *   },
 *   "eventContexts": {
 *     "eventContext0": {
 *       "size": 48,
 *       "version": 0,
 *       "dataFormatType": 1,
 *       "dataFormatVersion": 0,
 *       "dataSize": 32,
 *       "data": {
 *         "keyValArray64": [
 *           { "key64": 1234567890123456789, "val64": 9876543210987654321 }
 *         ]
 *       }
 *     }
 *   }
 * }
 */
json_object *cper_section_nvidia_events_to_ir(const UINT8 *section, UINT32 size,
					      char **desc_string)
{
	EFI_NVIDIA_EVENT_HEADER *event_header =
		(EFI_NVIDIA_EVENT_HEADER *)section;
	// Check event header version compatibility
	NVIDIA_CHECK_EVENT_HEADER_VERSION(event_header->EventVersion,
		EFI_NVIDIA_EVENT_HEADER_VERSION,
		"parsing", NULL);

	json_object *event_ir = json_object_new_object();

	// Parse event header fields
	json_object *event_header_ir = json_object_new_object();
	json_object_object_add(event_ir, JSON_EVENT_HEADER, event_header_ir);
	const char *signature = event_header->Signature;
	*desc_string = malloc(SECTION_DESC_STRING_SIZE);
	if (*desc_string == NULL) {
		cper_print_log("Error: Failed to allocate memory for description string\n");
		json_object_put(event_ir);
		return NULL;
	}
	int outstr_len = 0;
	// Signature is 16 bytes and may not be null-terminated, so limit to 16 chars
	outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
			      "A %.16s Nvidia Event occurred", signature);
	if (outstr_len < 0) {
		cper_print_log(
			"Error: Could not write to description string\n");
	} else if (outstr_len > SECTION_DESC_STRING_SIZE) {
		cper_print_log("Error: Description string truncated: %s\n",
			       *desc_string);
	}
	// Signature is 16 bytes and may not be null-terminated
	// Use strnlen to safely get length up to 16 bytes
	size_t sig_len = strnlen(signature, 16);
	add_untrusted_string(event_header_ir, JSON_EVENT_HEADER_SIGNATURE,
			     signature, sig_len);
	add_json_int_field(event_header_ir, JSON_EVENT_HEADER_VERSION,
			   event_header->EventVersion);
	add_json_int_field(event_header_ir, JSON_EVENT_HEADER_CONTEXT_COUNT,
			   event_header->EventContextCount);
	add_json_int_field(event_header_ir,
			   JSON_EVENT_HEADER_SOURCE_DEVICE_TYPE,
			   event_header->SourceDeviceType);
	add_json_int_field(event_header_ir, JSON_EVENT_HEADER_TYPE,
			   event_header->EventType);
	add_json_int_field(event_header_ir, JSON_EVENT_HEADER_SUBTYPE,
			   event_header->EventSubtype);
	add_json_uint64_field(event_header_ir, JSON_EVENT_HEADER_LINK_ID,
			      event_header->EventLinkId);

	// Parse event info structure
	EFI_NVIDIA_EVENT_INFO_HEADER *event_info_header =
		NVIDIA_GET_EVENT_INFO_HEADER(event_header);
	json_object *event_info_ir = json_object_new_object();
	json_object_object_add(event_ir, JSON_EVENT_INFO, event_info_ir);
	add_json_int_field(event_info_ir, JSON_EVENT_INFO_VERSION,
			   event_info_header->InfoVersion);
	add_json_int_field(event_info_ir, JSON_EVENT_INFO_SIZE,
			   event_info_header->InfoSize);
	
	// Extract major and minor version from event info header
	UINT8 info_minor = NVIDIA_GET_INFO_MINOR_VERSION(event_info_header);
	UINT8 info_major = NVIDIA_GET_INFO_MAJOR_VERSION(event_info_header);
	
	// Call device-specific handler to parse additional event info fields
	for (size_t i = 0; i < NVIDIA_EVENT_INFO_HANDLER_COUNT; i++) {
		if (NVIDIA_GET_EVENT_SOURCE_DEVICE_TYPE(event_header) ==
		    event_info_handlers[i].srcDev) {
			// Check version compatibility
			NVIDIA_CHECK_INFO_MAJOR_VERSION(info_major, info_minor,
							event_info_handlers[i].major_version,
							"parsing");
			NVIDIA_CHECK_INFO_MINOR_VERSION_MIN(info_major, info_minor,
							    event_info_handlers[i].major_version,
							    event_info_handlers[i].minor_version,
							    "parsing");
			NVIDIA_WARN_INFO_MINOR_VERSION_NEWER(info_major, info_minor,
							     event_info_handlers[i].major_version,
							     event_info_handlers[i].minor_version,
							     "parsing");
			
			event_info_handlers[i].callback(event_header,
							event_info_ir);
			break;
		}
	}
	// Parse all event contexts into an array
	json_object *event_contexts_ir = json_object_new_array();
	json_object_object_add(event_ir, JSON_EVENT_CONTEXTS,
			       event_contexts_ir);

	for (size_t i = 0; i < NVIDIA_GET_EVENT_CONTEXT_COUNT(event_header);
	     i++) {
		EFI_NVIDIA_EVENT_CTX_HEADER *ctx =
			get_event_context_n(event_header, i, size);
		if (ctx == NULL)
			continue;
		// Parse common context header fields
		json_object *event_context_ir = json_object_new_object();
		// Add context to array
		json_object_array_add(event_contexts_ir, event_context_ir);
		add_json_int_field(event_context_ir, JSON_EVENT_CONTEXT_SIZE,
				   ctx->CtxSize);
		add_json_int_field(event_context_ir, JSON_EVENT_CONTEXT_VERSION,
				   ctx->CtxVersion);
		add_json_int_field(event_context_ir,
				   JSON_EVENT_CONTEXT_DATA_FORMAT_TYPE,
				   ctx->DataFormatType);
		add_json_int_field(event_context_ir,
				   JSON_EVENT_CONTEXT_DATA_FORMAT_VERSION,
				   ctx->DataFormatVersion);
		add_json_int_field(event_context_ir,
				   JSON_EVENT_CONTEXT_DATA_SIZE, ctx->DataSize);
		json_object *data_ir = json_object_new_object();
		json_object_object_add(event_context_ir,
				       JSON_EVENT_CONTEXT_DATA, data_ir);
		// Check for device/format-specific custom handler
		bool handler_override_found = false;
		for (size_t handler_idx = 0;
		     handler_idx < NVIDIA_EVENT_CTX_HANDLER_COUNT;
		     handler_idx++) {
			if (event_ctx_handlers[handler_idx].srcDev ==
				    NVIDIA_GET_EVENT_SOURCE_DEVICE_TYPE(
					    event_header) &&
			    event_ctx_handlers[handler_idx].dataFormatType ==
				    NVIDIA_GET_EVENT_CTX_DATA_TYPE(ctx)) {
				if (event_ctx_handlers[handler_idx].callback !=
				    NULL) {
					event_ctx_handlers[handler_idx].callback(
						event_header, size, i, data_ir);
					handler_override_found = true;
					break;
				}
			}
		}
		if (handler_override_found)
			continue;
		// Use default parser based on data format type
		switch (NVIDIA_GET_EVENT_CTX_DATA_TYPE(ctx)) {
		case TYPE_1:
			parse_common_ctx_type1_to_ir(event_header, size, i,
						     data_ir);
			break;
		case TYPE_2:
			parse_common_ctx_type2_to_ir(event_header, size, i,
						     data_ir);
			break;
		case TYPE_3:
			parse_common_ctx_type3_to_ir(event_header, size, i,
						     data_ir);
			break;
		case TYPE_4:
			parse_common_ctx_type4_to_ir(event_header, size, i,
						     data_ir);
			break;
		default:
			parse_common_ctx_type0_to_ir(event_header, size, i,
						     data_ir);
			break;
		}
	}
	return event_ir;
}
// Converts a single NVIDIA event JSON IR structure back into CPER binary format.
// Writes the event header, device-specific event info, and all event contexts to binary.
// Handles 16-byte alignment padding as required by the CPER specification.
/*
 * Binary output structure (NVIDIA Event-based CPER):
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_EVENT_HEADER                                      (32 bytes) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ EFI_NVIDIA_EVENT_INFO_HEADER                                  (3 bytes) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ Device-Specific Event Info                              (variable size) │
 * │   e.g., EFI_NVIDIA_CPU_EVENT_INFO (32 bytes)                            │
 * │     or  EFI_NVIDIA_GPU_EVENT_INFO (16 bytes)                            │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ PADDING (if needed)                        (align to 16-byte boundary)  │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ EFI_NVIDIA_EVENT_CTX_HEADER (Context 0)                      (16 bytes) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ Context Data (Type-specific)                            (variable size) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ PADDING (if needed)                        (align to 16-byte boundary)  │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ EFI_NVIDIA_EVENT_CTX_HEADER (Context N)                      (16 bytes) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ Context Data (Type-specific)                            (variable size) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ PADDING (if needed)                        (align to 16-byte boundary)  │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
void ir_section_nvidia_events_to_cper(json_object *section, FILE *out)
{
	json_object *event_header_ir =
		json_object_object_get(section, JSON_EVENT_HEADER);
	EFI_NVIDIA_EVENT_HEADER event_header = { 0 };
	event_header.EventVersion =
		get_json_int_field(event_header_ir, JSON_EVENT_HEADER_VERSION);
	// Check event header version compatibility
	NVIDIA_CHECK_EVENT_HEADER_VERSION(event_header.EventVersion,
		EFI_NVIDIA_EVENT_HEADER_VERSION,
		"generation", );
	event_header.EventContextCount = get_json_int_field(
		event_header_ir, JSON_EVENT_HEADER_CONTEXT_COUNT);
	event_header.SourceDeviceType = get_json_int_field(
		event_header_ir, JSON_EVENT_HEADER_SOURCE_DEVICE_TYPE);
	event_header.Reserved1 = 0;
	event_header.EventType =
		get_json_int_field(event_header_ir, JSON_EVENT_HEADER_TYPE);
	event_header.EventSubtype =
		get_json_int_field(event_header_ir, JSON_EVENT_HEADER_SUBTYPE);
	event_header.EventLinkId = json_object_get_uint64(
		json_object_object_get(event_header_ir,
				       JSON_EVENT_HEADER_LINK_ID));
	
	// Signature is optional - only copy if present
	json_object *signature_obj = json_object_object_get(
		event_header_ir, JSON_EVENT_HEADER_SIGNATURE);
	if (signature_obj != NULL) {
		const char *sig_str = json_object_get_string(signature_obj);
		if (sig_str != NULL) {
			// Copy up to 16 bytes, don't force null termination
			// (signature can be exactly 16 chars with no null terminator)
			size_t sig_len = strlen(sig_str);
			size_t copy_len = sig_len < sizeof(event_header.Signature) ? 
					  sig_len : sizeof(event_header.Signature);
			memcpy(event_header.Signature, sig_str, copy_len);
			// Only null-terminate if there's room
			if (sig_len < sizeof(event_header.Signature)) {
				event_header.Signature[sig_len] = '\0';
			}
		}
	}
	
	fwrite(&event_header, sizeof(EFI_NVIDIA_EVENT_HEADER), 1, out);

	json_object *event_info_ir =
		json_object_object_get(section, JSON_EVENT_INFO);
	EFI_NVIDIA_EVENT_INFO_HEADER event_info_header = { 0 };
	event_info_header.InfoVersion =
		get_json_int_field(event_info_ir, JSON_EVENT_INFO_VERSION);
	event_info_header.InfoSize =
		get_json_int_field(event_info_ir, JSON_EVENT_INFO_SIZE);

	size_t bytes_written = fwrite(&event_info_header, 1,
				      sizeof(EFI_NVIDIA_EVENT_INFO_HEADER),
				      out);
	
	// Extract major and minor version from event info header
	UINT8 info_minor = NVIDIA_GET_INFO_MINOR_VERSION(&event_info_header);
	UINT8 info_major = NVIDIA_GET_INFO_MAJOR_VERSION(&event_info_header);
	
	// Call device-specific handler to parse additional event info fields
	for (size_t i = 0; i < NVIDIA_EVENT_INFO_HANDLER_COUNT; i++) {
		if (NVIDIA_GET_EVENT_SOURCE_DEVICE_TYPE(&event_header) ==
		    event_info_handlers[i].srcDev) {
			// Check version compatibility
			NVIDIA_CHECK_INFO_MAJOR_VERSION(info_major, info_minor,
							event_info_handlers[i].major_version,
							"generation");
			NVIDIA_CHECK_INFO_MINOR_VERSION_MIN(info_major, info_minor,
							    event_info_handlers[i].major_version,
							    event_info_handlers[i].minor_version,
							    "generation");
			NVIDIA_WARN_INFO_MINOR_VERSION_NEWER(info_major, info_minor,
							     event_info_handlers[i].major_version,
							     event_info_handlers[i].minor_version,
							     "generation");
			
			bytes_written += event_info_handlers[i].callback_bin(
				event_info_ir, out);
			break;
		}
	}
	WRITE_PADDING_TO_16_BYTE_ALIGNMENT(bytes_written, out);

	json_object *event_contexts_ir =
		json_object_object_get(section, JSON_EVENT_CONTEXTS);
	
	// Check if eventContexts field exists before iterating
	if (event_contexts_ir == NULL) {
		cper_print_log("Warning: Missing eventContexts field in Nvidia Event JSON\n");
		return;
	}
	
	// Determine the number of contexts based on whether it's an array or object
	size_t ctx_count = 0;
	bool is_array = json_object_is_type(event_contexts_ir, json_type_array);
	if (is_array) {
		ctx_count = json_object_array_length(event_contexts_ir);
	} else if (json_object_is_type(event_contexts_ir, json_type_object)) {
		// Backward compatibility with old object format
		ctx_count = json_object_object_length(event_contexts_ir);
	}

	for (size_t ctx_instance = 0; ctx_instance < ctx_count; ctx_instance++) {
		json_object *value = NULL;
		if (is_array) {
			value = json_object_array_get_idx(event_contexts_ir, ctx_instance);
		} else {
			// Backward compatibility: get by key name
			char key[64];
			snprintf(key, sizeof(key), "eventContext%zu", ctx_instance);
			value = json_object_object_get(event_contexts_ir, key);
		}
		if (value == NULL)
			continue;

		EFI_NVIDIA_EVENT_CTX_HEADER ctx = { 0 };
		ctx.CtxSize = json_object_get_int(json_object_object_get(
			value, JSON_EVENT_CONTEXT_SIZE));
		ctx.CtxVersion = (uint16_t)get_json_int_field(
			value, JSON_EVENT_CONTEXT_VERSION);
		ctx.DataFormatType = (uint16_t)get_json_int_field(
			value, JSON_EVENT_CONTEXT_DATA_FORMAT_TYPE);
		ctx.DataFormatVersion = (uint16_t)get_json_int_field(
			value, JSON_EVENT_CONTEXT_DATA_FORMAT_VERSION);
		ctx.DataSize = json_object_get_int(json_object_object_get(
			value, JSON_EVENT_CONTEXT_DATA_SIZE));
		bytes_written = fwrite(
			&ctx, 1, sizeof(EFI_NVIDIA_EVENT_CTX_HEADER), out);

		// Check for device/format-specific custom handler
		bool handler_override_found = false;
		for (size_t j = 0; j < NVIDIA_EVENT_CTX_HANDLER_COUNT; j++) {
			if (event_ctx_handlers[j].srcDev ==
				    NVIDIA_GET_EVENT_SOURCE_DEVICE_TYPE(
					    &event_header) &&
			    event_ctx_handlers[j].dataFormatType ==
				    NVIDIA_GET_EVENT_CTX_DATA_TYPE(&ctx)) {
				bytes_written +=
					event_ctx_handlers[j].callback_bin(
						section, ctx_instance, out);
				handler_override_found = true;
				break;
			}
		}
		// If no handler override found, use default parser based on data format type
		if (!handler_override_found) {
			switch (NVIDIA_GET_EVENT_CTX_DATA_TYPE(&ctx)) {
			case TYPE_1:
				bytes_written += parse_common_ctx_type1_to_bin(
					section, ctx_instance, out);
				break;
			case TYPE_2:
				bytes_written += parse_common_ctx_type2_to_bin(
					section, ctx_instance, out);
				break;
			case TYPE_3:
				bytes_written += parse_common_ctx_type3_to_bin(
					section, ctx_instance, out);
				break;
			case TYPE_4:
				bytes_written += parse_common_ctx_type4_to_bin(
					section, ctx_instance, out);
				break;
			default:
				bytes_written += parse_common_ctx_type0_to_bin(
					section, ctx_instance, out);
				break;
			}
		}
		WRITE_PADDING_TO_16_BYTE_ALIGNMENT(bytes_written, out);
	}
}
