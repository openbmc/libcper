// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <json.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-nvidia-events.h>
#include <libcper/log.h>

// NVIDIA Event Section GUID
EFI_GUID gEfiNvidiaEventErrorSectionGuid = { 0x9068e568,
					     0x6ca0,
					     0x11f0,
					     { 0xae, 0xaf, 0x15, 0x93, 0x43,
					       0x59, 0x1e, 0xac } };

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
 * │   UINT64  EventTraceId                                                  │
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
 * │   UINT32  CtxSize                ← header + data + padding, 16B-aligned │
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
 * │ PADDING (if needed)               ← counted inside CtxSize above        │
 * └─────────────────────────────────────────────────────────────────────────┘
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_EVENT_CTX_HEADER (Context 1)                      (16 bytes) │
 * │   ... (same structure as Context 0)                                     │
 * └─────────────────────────────────────────────────────────────────────────┘
 *     ... repeat for EventContextCount total contexts ...
 *
 * Note: CtxSize is header + data + padding, rounded up to a 16-byte boundary,
 *       so readers advance to the next context with ptr += CtxSize.
 */

/**
 * NVIDIA Event JSON IR Structure:
 *
 * Maps binary structures (above) to JSON using the field name constants (below).
 * Device-specific eventInfo is nested under a variant key ("cpu"/"gpu").
 * Context data is nested under a variant key (e.g., "type1", "gpuInitMetadata").
 *
 * {
 *   "eventHeader": { ... }           → EFI_NVIDIA_EVENT_HEADER
 *   "eventInfo": {                   → EFI_NVIDIA_EVENT_INFO_*
 *     "version": "0.1",
 *     "cpu": { ... }                 → variant: EFI_NVIDIA_CPU_EVENT_INFO (or "gpu")
 *   },
 *   "eventContexts": [               → Array of contexts
 *     {
 *       "data": {                    → EFI_NVIDIA_EVENT_CTX_DATA_*
 *         "type1": {                 → variant key for data
 *           "keyValArray64": [ ... ] → TYPE_1 (16 bytes each: key64, val64)
 *         }
 *       }
 *     },
 *     { ... }
 *   ]
 * }
 *
 * Data variant keys: "opaque" (TYPE_0), "type1" (TYPE_1), "type2" (TYPE_2),
 *   "type3" (TYPE_3), "type4" (TYPE_4), "gpuInitMetadata", "gpuLegacyXid",
 *   "gpuRecommendedActions", "gpuTimeoutData"
 */

// ============================================================================
// Enums
typedef enum {
	OPAQUE = 0,
	TYPE_1 = 1,
	TYPE_2 = 2,
	TYPE_3 = 3,
	TYPE_4 = 4,
	// GPU-specific context data types
	GPU_EVENT_LEGACY_XID = 0x8001,
	GPU_RECOMMENDED_ACTIONS = 0x8002,
	GPU_TIMEOUT_DATA = 0x9001,
	GPU_INIT_METADATA = 0xA001
} NVIDIA_EVENT_CTX_DATA_TYPE;

typedef enum {
	CPU = 0,
	GPU = 1,
	DPU = 2,
	NIC = 3,
	SWX = 4,
	BMC = 5
} NVIDIA_EVENT_SRC_DEV;

typedef struct {
	UINT16 type;
	const char *name;
} NVIDIA_GPU_EVENT_TYPE_NAME;

static const NVIDIA_GPU_EVENT_TYPE_NAME gpu_event_type_names[] = {
	{ 0x0001, "Timeout" },
	{ 0x0002, "MemoryIntegrityError" },
	{ 0x0003, "InterconnectError" },
	{ 0x0004, "CorruptionDetected" },
	{ 0x0005, "SecurityError" },
	{ 0x0006, "PowerError" },
	{ 0x0007, "ThermalError" },
	{ 0x0008, "FirmwareFault" },
	{ 0x0009, "EngineError" },
	{ 0x000A, "ResourceExhausted" },
	{ 0x000B, "TranslationFault" },
	{ 0x7FFF, "UnclassifiedError" },
	{ 0x8000, "Initialization" },
	{ 0x8001, "Shutdown" },
	{ 0x8002, "StateChanged" },
	{ 0x8003, "ConfigChanged" },
	{ 0x8004, "ResourceRetirement" },
	{ 0x8005, "ResourceThreshold" },
	{ 0xFFFE, "Telemetry" },
	{ 0xFFFF, "Debug" },
};

static const char *gpu_event_type_name(UINT16 event_type)
{
	for (size_t i = 0;
	     i < sizeof(gpu_event_type_names) / sizeof(gpu_event_type_names[0]);
	     i++) {
		if (gpu_event_type_names[i].type == event_type) {
			return gpu_event_type_names[i].name;
		}
	}
	return NULL;
}

// Callback structures
typedef struct {
	NVIDIA_EVENT_SRC_DEV srcDev;
	UINT8 major_version; // Expected major version for this handler
	UINT8 minor_version; // Expected minor version for this handler
	void (*callback)(EFI_NVIDIA_EVENT_HEADER *, json_object *);
	size_t (*callback_bin)(json_object *, FILE *);
	size_t info_size;
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
static void parse_gpu_info_v1_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
				    json_object *event_info_ir);
static size_t parse_gpu_info_v1_to_bin(json_object *event_info_ir, FILE *out);
static void parse_gpu_info_v2_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
				    json_object *event_info_ir);
static size_t parse_gpu_info_v2_to_bin(json_object *event_info_ir, FILE *out);

// GPU context data formatters
static void
parse_gpu_ctx_init_metadata_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
				  size_t total_event_size, size_t ctx_instance,
				  json_object *output_data_ir);
static size_t parse_gpu_ctx_init_metadata_to_bin(json_object *event_ir,
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
static void
parse_gpu_ctx_timeout_data_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
				 size_t total_event_size, size_t ctx_instance,
				 json_object *output_data_ir);
static size_t parse_gpu_ctx_timeout_data_to_bin(json_object *event_ir,
						size_t ctx_instance,
						FILE *output_file_stream);

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

// Helper: Get pointer to device-specific event info (after headers)
static inline void *get_event_info(EFI_NVIDIA_EVENT_HEADER *header)
{
	return (UINT8 *)header + sizeof(EFI_NVIDIA_EVENT_HEADER) +
	       sizeof(EFI_NVIDIA_EVENT_INFO_HEADER);
}

// Helper: Get pointer to event info header (after event header)
static inline EFI_NVIDIA_EVENT_INFO_HEADER *
get_event_info_header(EFI_NVIDIA_EVENT_HEADER *header)
{
	return (EFI_NVIDIA_EVENT_INFO_HEADER *)((UINT8 *)header +
						sizeof(EFI_NVIDIA_EVENT_HEADER));
}

// Helper: Extract major version from event info header (high byte)
static inline UINT8 get_info_major_version(EFI_NVIDIA_EVENT_INFO_HEADER *header)
{
	return (UINT8)((header->InfoVersion >> 8) & 0xFF);
}

// Helper: Extract minor version from event info header (low byte)
static inline UINT8 get_info_minor_version(EFI_NVIDIA_EVENT_INFO_HEADER *header)
{
	return (UINT8)(header->InfoVersion & 0xFF);
}

// Helper: Check if event header version matches - returns false and logs on mismatch
static bool check_event_header_version(UINT16 ver, UINT16 exp_ver,
				       const char *operation)
{
	if (ver != exp_ver) {
		cper_print_log("Error: NVIDIA Event Header version mismatch: "
			       "expected %d, got %d. Skipping event %s.\n",
			       (int)exp_ver, (int)ver, operation);
		return false;
	}
	return true;
}

// Helper: Write zero-padding to align to 16-byte boundary
static void write_padding_to_16_byte_alignment(size_t bytes_written, FILE *out)
{
	size_t padding = (16 - (bytes_written % 16)) % 16;
	if (padding > 0) {
		UINT8 zeros[16] = { 0 };
		fwrite(zeros, 1, padding, out);
	}
}

// Event info handler callbacks for different device types.
// Note: The _to_bin callbacks should return the number of bytes written.
//       The caller is responsible for adding 16-byte alignment padding.
NV_EVENT_INFO_CALLBACKS nv_event_types[] = {
	{ CPU, EFI_NVIDIA_CPU_EVENT_INFO_MAJ, EFI_NVIDIA_CPU_EVENT_INFO_MIN,
	  &parse_cpu_info_to_ir, &parse_cpu_info_to_bin,
	  sizeof(EFI_NVIDIA_CPU_EVENT_INFO) },
	{ GPU, EFI_NVIDIA_GPU_EVENT_INFO_V1_MAJ,
	  EFI_NVIDIA_GPU_EVENT_INFO_V1_MIN, &parse_gpu_info_v1_to_ir,
	  &parse_gpu_info_v1_to_bin, sizeof(EFI_NVIDIA_GPU_EVENT_INFO_V1) },
	{ GPU, EFI_NVIDIA_GPU_EVENT_INFO_V2_MAJ,
	  EFI_NVIDIA_GPU_EVENT_INFO_V2_MIN, &parse_gpu_info_v2_to_ir,
	  &parse_gpu_info_v2_to_bin, sizeof(EFI_NVIDIA_GPU_EVENT_INFO_V2) }
};

// Event context handler callbacks for device-specific opaque data formats.
// This is where custom/opaque context data type handlers should be registered.
// Add entries here for device types that need special handling beyond the standard TYPE_1-4 formats.
// Note: The _to_bin callbacks should return the number of bytes written.
//       The caller is responsible for adding 16-byte alignment padding.
NV_EVENT_CTX_CALLBACKS event_ctx_handlers[] = {
	// GPU-specific context data handlers
	{ GPU, GPU_INIT_METADATA, &parse_gpu_ctx_init_metadata_to_ir,
	  &parse_gpu_ctx_init_metadata_to_bin },
	{ GPU, GPU_EVENT_LEGACY_XID, &parse_gpu_ctx_legacy_xid_to_ir,
	  &parse_gpu_ctx_legacy_xid_to_bin },
	{ GPU, GPU_RECOMMENDED_ACTIONS,
	  &parse_gpu_ctx_recommended_actions_to_ir,
	  &parse_gpu_ctx_recommended_actions_to_bin },
	{ GPU, GPU_TIMEOUT_DATA, &parse_gpu_ctx_timeout_data_to_ir,
	  &parse_gpu_ctx_timeout_data_to_bin }
};

// Returns the JSON variant key for a given event info device type.
// e.g., CPU → "cpu", GPU → "gpu"
static const char *event_info_variant_key(NVIDIA_EVENT_SRC_DEV dev)
{
	switch (dev) {
	case CPU:
		return "cpu";
	case GPU:
		return "gpu";
	default:
		return NULL;
	}
}

// Returns the JSON variant key for a given context data format type and device.
// Device-specific handlers (GPU metadata, legacy XID, recommended actions) take
// priority; common types fall through to the standard keys.
// e.g., TYPE_1 → "type1", GPU_INIT_METADATA → "gpuInitMetadata"
static const char *
event_ctx_data_variant_key(NVIDIA_EVENT_SRC_DEV dev,
			   NVIDIA_EVENT_CTX_DATA_TYPE data_format_type)
{
	// Device-specific overrides
	if (dev == GPU) {
		switch (data_format_type) {
		case GPU_INIT_METADATA:
			return "gpuInitMetadata";
		case GPU_EVENT_LEGACY_XID:
			return "gpuLegacyXid";
		case GPU_RECOMMENDED_ACTIONS:
			return "gpuRecommendedActions";
		case GPU_TIMEOUT_DATA:
			return "gpuTimeoutData";
		default:
			break;
		}
	}

	// Common data format types
	switch (data_format_type) {
	case TYPE_1:
		return "type1";
	case TYPE_2:
		return "type2";
	case TYPE_3:
		return "type3";
	case TYPE_4:
		return "type4";
	default:
		return "opaque";
	}
}

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

	if (ptr + sizeof(EFI_NVIDIA_EVENT_INFO_HEADER) > end) {
		return NULL;
	}

	EFI_NVIDIA_EVENT_INFO_HEADER *info_header =
		(EFI_NVIDIA_EVENT_INFO_HEADER *)ptr;
	if (ptr + info_header->InfoSize > end) {
		return NULL;
	}
	ptr += info_header->InfoSize;
	for (size_t i = 0; i < n; i++) {
		if (ptr + sizeof(EFI_NVIDIA_EVENT_CTX_HEADER) > end) {
			return NULL;
		}
		EFI_NVIDIA_EVENT_CTX_HEADER *ctx =
			(EFI_NVIDIA_EVENT_CTX_HEADER *)ptr;
		if (ctx->CtxSize == 0 || ptr + ctx->CtxSize > end) {
			return NULL;
		}
		ptr += ctx->CtxSize;
	}

	if (ptr + sizeof(EFI_NVIDIA_EVENT_CTX_HEADER) > end) {
		return NULL;
	}
	return (EFI_NVIDIA_EVENT_CTX_HEADER *)ptr;
}

// Gets the nth event context from a JSON IR Event object.
// Returns NULL if the eventContexts field doesn't exist, isn't an object,
// or if n is out of bounds.
static inline json_object *get_event_context_n_ir(json_object *event_ir,
						  size_t n)
{
	if (event_ir == NULL) {
		return NULL;
	}

	// Get the eventContexts object
	json_object *event_contexts_ir =
		json_object_object_get(event_ir, "eventContexts");
	if (event_contexts_ir == NULL) {
		return NULL;
	}

	// Check if it's an array (preferred structure)
	if (json_object_is_type(event_contexts_ir, json_type_array)) {
		size_t array_len = json_object_array_length(event_contexts_ir);
		if (n >= array_len) {
			return NULL;
		}
		return json_object_array_get_idx(event_contexts_ir, n);
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
	if (event_context_ir == NULL) {
		return NULL;
	}

	return json_object_object_get(event_context_ir, "data");
}

// GPU EVENT_INFO originator names shared by v1 and v2 parsers. Match the
// values currently implemented by the GPU driver; all other values are
// reported as Unknown.
static const char *gpu_event_originator_names[] = {
	[0] = "Invalid",   [2] = "PF_GSP_FW", [3] = "VF_GSP_FW",
	[4] = "PF_DRIVER", [5] = "VF_DRIVER",
};
static const size_t gpu_event_originator_names_count =
	sizeof(gpu_event_originator_names) /
	sizeof(gpu_event_originator_names[0]);

// Format an originator enum value as a JSON string ("Invalid"/"PF_GSP_FW"/.../"Unknown").
static void add_gpu_event_originator(json_object *ir, const char *field,
				     UINT8 value)
{
	if (value < gpu_event_originator_names_count &&
	    gpu_event_originator_names[value] != NULL) {
		json_object_object_add(
			ir, field,
			json_object_new_string(
				gpu_event_originator_names[value]));
	} else {
		json_object_object_add(ir, field,
				       json_object_new_string("Unknown"));
	}
}

// Reverse lookup: match originator string to its numeric value (0 on no match).
static UINT8 gpu_event_originator_from_string(const char *name)
{
	if (name == NULL) {
		return 0;
	}
	for (size_t i = 0; i < gpu_event_originator_names_count; i++) {
		if (gpu_event_originator_names[i] != NULL &&
		    strcmp(name, gpu_event_originator_names[i]) == 0) {
			return (UINT8)i;
		}
	}
	return 0;
}

// PDI is represented in the IR as an eight-byte, MSB-first identifier.
static void add_gpu_pdi(json_object *ir, UINT64 pdi)
{
	UINT8 pdi_bytes[8];
	char pdi_str[24]; // "XX:XX:XX:XX:XX:XX:XX:XX\0"

	memcpy(pdi_bytes, &pdi, sizeof(pdi_bytes));
	snprintf(pdi_str, sizeof(pdi_str),
		 "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", pdi_bytes[7],
		 pdi_bytes[6], pdi_bytes[5], pdi_bytes[4], pdi_bytes[3],
		 pdi_bytes[2], pdi_bytes[1], pdi_bytes[0]);
	json_object_object_add(ir, "Pdi", json_object_new_string(pdi_str));
}

static void get_gpu_pdi(json_object *ir, UINT64 *pdi)
{
	const char *pdi_str =
		json_object_get_string(json_object_object_get(ir, "Pdi"));
	if (pdi_str == NULL) {
		return;
	}

	unsigned int b[8] = { 0 };
	if (sscanf(pdi_str, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", &b[0],
		   &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7]) != 8) {
		return;
	}

	UINT8 pdi_bytes[8];
	for (int k = 0; k < 8; k++) {
		pdi_bytes[k] = (UINT8)b[7 - k];
	}
	memcpy(pdi, pdi_bytes, sizeof(*pdi));
}

// Parses CPU-specific event info structure into JSON IR format.
// Extracts socket number, architecture (decoded), ECID array, and instance base.
// Output is placed inside the "cpu" variant within eventInfo.
/*
 * Example JSON IR (inside eventInfo.cpu):
 * {
 *   "SocketNum": 0,
 *   "Architecture": {
 *     "hidFam": "0x07",
 *     "revision": "1.1",
 *     "chipId": "0x41",
 *     "preSiPlatform": "Silicon",
 *     "errorInjection": false
 *   },
 *   "Ecid1": "0x499602d2",
 *   "Ecid2": "0x89abcdef",
 *   "Ecid3": "0x4d2b0ca3",
 *   "Ecid4": "0x0f6b75c7",
 *   "InstanceBase": "0x0000ffff00000000"
 * }
 */
static void parse_cpu_info_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
				 json_object *event_info_ir)
{
	// Verify InfoSize is large enough for CPU event info
	EFI_NVIDIA_EVENT_INFO_HEADER *info_header =
		get_event_info_header(event_header);
	size_t required_size = sizeof(EFI_NVIDIA_EVENT_INFO_HEADER) +
			       sizeof(EFI_NVIDIA_CPU_EVENT_INFO);
	if (info_header->InfoSize < required_size) {
		cper_print_log(
			"Error: CPU event info size too small: got %d, need %zu\n",
			info_header->InfoSize, required_size);
		return;
	}

	EFI_NVIDIA_CPU_EVENT_INFO *cpu_event_info =
		(EFI_NVIDIA_CPU_EVENT_INFO *)get_event_info(event_header);
	if (cpu_event_info == NULL) {
		return;
	}

	add_uint(event_info_ir, "SocketNum", cpu_event_info->SocketNum);

	// Decode Architecture field into components
	const EFI_NVIDIA_CPU_ARCHITECTURE *arch = &cpu_event_info->Architecture;
	json_object *arch_ir = json_object_new_object();

	// hidFam: 2-digit hex
	char hid_fam_str[8];
	snprintf(hid_fam_str, sizeof(hid_fam_str), "0x%02X",
		 (UINT32)arch->HidFam);
	json_object_object_add(arch_ir, "hidFam",
			       json_object_new_string(hid_fam_str));

	// revision: "majorRev.minorRev"
	UINT8 major_rev = arch->MajorRev;
	UINT8 minor_rev = arch->MinorRev;
	char revision_str[8];
	snprintf(revision_str, sizeof(revision_str), "%u.%u", major_rev,
		 minor_rev);
	json_object_object_add(arch_ir, "revision",
			       json_object_new_string(revision_str));

	// chipId: 2-digit hex
	char chip_id_str[8];
	snprintf(chip_id_str, sizeof(chip_id_str), "0x%02X",
		 (UINT32)arch->ChipId);
	json_object_object_add(arch_ir, "chipId",
			       json_object_new_string(chip_id_str));

	// preSiPlatform: 0 = Silicon, non-zero = PreSilicon
	json_object_object_add(arch_ir, "preSiPlatform",
			       json_object_new_string(arch->PreSiPlatform == 0 ?
							      "Silicon" :
							      "PreSilicon"));

	json_object_object_add(arch_ir, "errorInjection",
			       json_object_new_boolean(arch->ErrorInjection));
	json_object_object_add(event_info_ir, "Architecture", arch_ir);

	add_int_hex_32(event_info_ir, "Ecid1", cpu_event_info->Ecid[0]);
	add_int_hex_32(event_info_ir, "Ecid2", cpu_event_info->Ecid[1]);
	add_int_hex_32(event_info_ir, "Ecid3", cpu_event_info->Ecid[2]);
	add_int_hex_32(event_info_ir, "Ecid4", cpu_event_info->Ecid[3]);
	add_int_hex_64(event_info_ir, "InstanceBase",
		       cpu_event_info->InstanceBase);
}
// Converts CPU-specific event info from JSON IR to CPER binary format.
// Writes socket number, architecture (reconstructed), ECID array, instance base.
// Returns the number of bytes written.
/*
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_CPU_EVENT_INFO              (29 bytes device-specific,       │
 * │                                         plus 3-byte shared info header) │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   UINT8   SocketNum                                                     │
 * │   UINT32  Architecture                                                  │
 * │   UINT32  Ecid[0]                                                       │
 * │   UINT32  Ecid[1]                                                       │
 * │   UINT32  Ecid[2]                                                       │
 * │   UINT32  Ecid[3]                                                       │
 * │   UINT64  InstanceBase                                                  │
 * └─────────────────────────────────────────────────────────────────────────┘
 * Note: __attribute__((packed)) removes natural alignment padding between
 *       SocketNum and Architecture; the byte layout is contiguous.
 */
static size_t parse_cpu_info_to_bin(json_object *event_info_ir, FILE *out)
{
	EFI_NVIDIA_CPU_EVENT_INFO cpu_event_info = { 0 };
	cpu_event_info.SocketNum = json_object_get_int64(
		json_object_object_get(event_info_ir, "SocketNum"));

	// Reconstruct Architecture from decoded components
	json_object *arch_ir =
		json_object_object_get(event_info_ir, "Architecture");

	// hidFam: parse "0xNN" hex string
	const char *hid_fam_str = json_object_get_string(
		json_object_object_get(arch_ir, "hidFam"));
	UINT32 hid_fam = hid_fam_str ? (UINT32)strtoul(hid_fam_str, NULL, 0) :
				       0;

	// revision: parse "major.minor" string
	const char *revision_str = json_object_get_string(
		json_object_object_get(arch_ir, "revision"));
	UINT32 major_rev = 0;
	UINT32 minor_rev = 0;
	if (revision_str) {
		sscanf(revision_str, "%u.%u", &major_rev, &minor_rev);
	}

	// chipId: parse "0xNN" hex string
	const char *chip_id_str = json_object_get_string(
		json_object_object_get(arch_ir, "chipId"));
	UINT32 chip_id = chip_id_str ? (UINT32)strtoul(chip_id_str, NULL, 0) :
				       0;

	// preSiPlatform: "Silicon" = 0, anything else = 1
	const char *pre_si_str = json_object_get_string(
		json_object_object_get(arch_ir, "preSiPlatform"));
	UINT32 pre_si =
		(pre_si_str != NULL && strcmp(pre_si_str, "Silicon") == 0) ? 0 :
									     1;

	// errorInjection: boolean
	UINT32 einj_tag = json_object_get_boolean(json_object_object_get(
				  arch_ir, "errorInjection")) ?
				  1 :
				  0;

	cpu_event_info.Architecture.HidFam = hid_fam;
	cpu_event_info.Architecture.MajorRev = major_rev;
	cpu_event_info.Architecture.ChipId = chip_id;
	cpu_event_info.Architecture.MinorRev = minor_rev;
	cpu_event_info.Architecture.PreSiPlatform = pre_si;
	cpu_event_info.Architecture.ErrorInjection = einj_tag;

	get_value_hex_32(event_info_ir, "Ecid1", &cpu_event_info.Ecid[0]);
	get_value_hex_32(event_info_ir, "Ecid2", &cpu_event_info.Ecid[1]);
	get_value_hex_32(event_info_ir, "Ecid3", &cpu_event_info.Ecid[2]);
	get_value_hex_32(event_info_ir, "Ecid4", &cpu_event_info.Ecid[3]);
	get_value_hex_64(event_info_ir, "InstanceBase",
			 &cpu_event_info.InstanceBase);
	return fwrite(&cpu_event_info, 1, sizeof(EFI_NVIDIA_CPU_EVENT_INFO),
		      out);
}

// Parses GPU EVENT_INFO v1.0 into JSON IR. The two 16-bit words between
// EventOriginator and Pdi are reserved; they are intentionally not exposed in
// the IR because they never carried defined SourcePartition semantics.
static void parse_gpu_info_v1_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
				    json_object *event_info_ir)
{
	EFI_NVIDIA_EVENT_INFO_HEADER *info_header =
		get_event_info_header(event_header);
	size_t required_size = sizeof(EFI_NVIDIA_EVENT_INFO_HEADER) +
			       sizeof(EFI_NVIDIA_GPU_EVENT_INFO_V1);
	if (info_header->InfoSize < required_size) {
		cper_print_log(
			"Error: GPU v1 event info size too small: got %d, need %zu\n",
			info_header->InfoSize, required_size);
		return;
	}

	EFI_NVIDIA_GPU_EVENT_INFO_V1 *info =
		(EFI_NVIDIA_GPU_EVENT_INFO_V1 *)get_event_info(event_header);
	if (info == NULL) {
		return;
	}

	add_gpu_event_originator(event_info_ir, "EventOriginator",
				 info->EventOriginator);
	add_gpu_pdi(event_info_ir, info->Pdi);
}

// Emits GPU EVENT_INFO v1.0. Reserved words are always written as zero.
static size_t parse_gpu_info_v1_to_bin(json_object *event_info_ir, FILE *out)
{
	EFI_NVIDIA_GPU_EVENT_INFO_V1 info = { 0 };
	json_object *originator_obj =
		json_object_object_get(event_info_ir, "EventOriginator");
	if (originator_obj != NULL) {
		info.EventOriginator = gpu_event_originator_from_string(
			json_object_get_string(originator_obj));
	}
	UINT64 pdi = 0;
	get_gpu_pdi(event_info_ir, &pdi);
	info.Pdi = pdi;

	return fwrite(&info, 1, sizeof(info), out);
}

// Parses GPU EVENT_INFO v2.0 into JSON IR.
// Extracts event originator, module instance, chiplet id, MIG attribution,
// event scope, and PDI. Output is placed inside the "gpu" variant in eventInfo.
/*
 * Example JSON IR (inside eventInfo.gpu):
 * {
 *   "EventOriginator": "PF_GSP_FW",
 *   "moduleInstance": 3,
 *   "chipletId": 1,
 *   "migAttribution": "2:3",
 *   "eventScope": 0,
 *   "Pdi": "89:34:56:78:9A:BC:DE:F1"
 * }
 *
 * MigAttribution encodes as "GpuInstance:ComputeInstance" (high nibble : low
 * nibble). The raw value 0xFF means "N/A".
 */
static void parse_gpu_info_v2_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
				    json_object *event_info_ir)
{
	// Verify InfoSize is large enough for GPU v2 event info
	EFI_NVIDIA_EVENT_INFO_HEADER *info_header =
		get_event_info_header(event_header);
	size_t required_size = sizeof(EFI_NVIDIA_EVENT_INFO_HEADER) +
			       sizeof(EFI_NVIDIA_GPU_EVENT_INFO_V2);
	if (info_header->InfoSize < required_size) {
		cper_print_log(
			"Error: GPU v2 event info size too small: got %d, need %zu\n",
			info_header->InfoSize, required_size);
		return;
	}

	EFI_NVIDIA_GPU_EVENT_INFO_V2 *info =
		(EFI_NVIDIA_GPU_EVENT_INFO_V2 *)get_event_info(event_header);
	if (info == NULL) {
		return;
	}

	add_gpu_event_originator(event_info_ir, "EventOriginator",
				 info->EventOriginator);
	add_uint(event_info_ir, "moduleInstance", info->ModuleInstance);
	add_uint(event_info_ir, "chipletId", info->ChipletId);

	// MIG Attribution: 0xFF = "N/A", otherwise "GpuInstance:ComputeInstance"
	// (high nibble : low nibble).
	{
		char mig_str[8];
		if (info->MigAttribution == 0xFF) {
			snprintf(mig_str, sizeof(mig_str), "N/A");
		} else {
			snprintf(mig_str, sizeof(mig_str), "%u:%u",
				 (info->MigAttribution >> 4) & 0xF,
				 info->MigAttribution & 0xF);
		}
		json_object_object_add(event_info_ir, "migAttribution",
				       json_object_new_string(mig_str));
	}

	add_uint(event_info_ir, "eventScope", info->EventScope);

	add_gpu_pdi(event_info_ir, info->Pdi);
}

// Converts GPU-specific event info from JSON IR to CPER binary format.
// Writes event originator, module instance, chiplet id, MIG attribution,
// event scope, and PDI. Returns the number of bytes written.
/*
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_GPU_EVENT_INFO_V2             (13 bytes device-specific,     │
 * │                                           plus 3-byte shared info hdr)  │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │   UINT8   EventOriginator                                               │
 * │   UINT8   ModuleInstance                                                │
 * │   UINT8   ChipletId                                                     │
 * │   UINT8   MigAttribution      ← high 4 bits : low 4 bits, 0xFF = N/A    │
 * │   UINT8   EventScope                                                    │
 * │   UINT64  Pdi                                                           │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
static size_t parse_gpu_info_v2_to_bin(json_object *event_info_ir, FILE *out)
{
	EFI_NVIDIA_GPU_EVENT_INFO_V2 gpu_event_info = { 0 };

	// EventOriginator: flat enum string - reverse lookup
	json_object *originator_obj =
		json_object_object_get(event_info_ir, "EventOriginator");
	if (originator_obj != NULL) {
		gpu_event_info.EventOriginator =
			gpu_event_originator_from_string(
				json_object_get_string(originator_obj));
	}

	gpu_event_info.ModuleInstance = (UINT8)json_object_get_int64(
		json_object_object_get(event_info_ir, "moduleInstance"));
	gpu_event_info.ChipletId = (UINT8)json_object_get_int64(
		json_object_object_get(event_info_ir, "chipletId"));

	// MIG Attribution: "N/A" -> 0xFF, else "GpuInstance:ComputeInstance"
	// (high nibble : low nibble). Missing field defaults to 0xFF (N/A).
	{
		const char *mig_str = json_object_get_string(
			json_object_object_get(event_info_ir,
					       "migAttribution"));
		if (mig_str == NULL || strcmp(mig_str, "N/A") == 0) {
			gpu_event_info.MigAttribution = 0xFF;
		} else {
			unsigned int gpu_inst = 0;
			unsigned int comp_inst = 0;
			if (sscanf(mig_str, "%u:%u", &gpu_inst, &comp_inst) ==
			    2) {
				gpu_event_info.MigAttribution =
					(UINT8)(((gpu_inst & 0xF) << 4) |
						(comp_inst & 0xF));
			} else {
				gpu_event_info.MigAttribution = 0xFF;
			}
		}
	}

	gpu_event_info.EventScope = (UINT8)json_object_get_int64(
		json_object_object_get(event_info_ir, "eventScope"));

	UINT64 pdi = 0;
	get_gpu_pdi(event_info_ir, &pdi);
	gpu_event_info.Pdi = pdi;

	return fwrite(&gpu_event_info, 1, sizeof(EFI_NVIDIA_GPU_EVENT_INFO_V2),
		      out);
}

// GPU Context Data Handlers

// Parses GPU Initialization Metadata (0xA001) context data to JSON IR.
// Extracts device info, firmware versions, PCI info, etc.
// Output is placed inside the "gpuInitMetadata" variant within data.
/*
 * Example JSON IR (inside data.gpuInitMetadata):
 * {
 *   "deviceName": "NVIDIA H100 80GB HBM3",
 *   "firmwareVersion": "96.00.5B.00.01",
 *   "pfDriverMicrocodeVersion": "535.183.01",
 *   "pfDriverVersion": "535.183.01",
 *   "vfDriverVersion": "535.183.01",
 *   "configuration": "0x00007048860DEB39",
 *   "pdi": "12:34:56:78:9A:BC:DE:F0",
 *   "architectureId": {
 *     "raw": "0x1A200000",
 *     "architecture": "Blackwell"
 *   },
 *   "hardwareInfoType": 0,
 *   "pciInfo": {
 *     "class": "0x03",
 *     "subclass": "0x02",
 *     "rev": "0xA1",
 *     "vendorId": "0x10DE",
 *     "deviceId": "0x2207",
 *     "subsystemVendorId": "0x10DE",
 *     "subsystemId": "0x1419",
 *     "bar0Start": "0x00000000E0000000",
 *     "bar0Size": "0x0000000001000000",
 *     "bar1Start": "0x9000000000000000",
 *     "bar1Size": "0x0000000020000000",
 *     "bar2Start": "0x9002000000000000",
 *     "bar2Size": "0x0000000002000000"
 *   }
 * }
 */
static void
parse_gpu_ctx_init_metadata_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
				  size_t total_event_size, size_t ctx_instance,
				  json_object *output_data_ir)
{
	EFI_NVIDIA_EVENT_CTX_HEADER *ctx = get_event_context_n(
		event_header, ctx_instance, total_event_size);
	if (ctx == NULL) {
		return;
	}

	// Verify the context data doesn't extend past the event boundary
	UINT8 *event_end = (UINT8 *)event_header + total_event_size;
	UINT8 *data_end = (UINT8 *)ctx->Data + ctx->DataSize;
	if (data_end > event_end ||
	    ctx->DataSize < sizeof(EFI_NVIDIA_GPU_CTX_INIT_METADATA)) {
		cper_print_log(
			"Error: GPU metadata context %zu extends past event boundary or is too small\n",
			ctx_instance);
		return;
	}

	EFI_NVIDIA_GPU_CTX_INIT_METADATA *metadata =
		(EFI_NVIDIA_GPU_CTX_INIT_METADATA *)ctx->Data;

	// String fields: default to "" then override with add_untrusted_string.
	// add_untrusted_string safely bounds reads and rejects non-printable or
	// unterminated strings, leaving the "" default in place for invalid data.
	add_string(output_data_ir, "deviceName", "");
	add_untrusted_string(output_data_ir, "deviceName", metadata->DeviceName,
			     sizeof(metadata->DeviceName));
	add_string(output_data_ir, "firmwareVersion", "");
	add_untrusted_string(output_data_ir, "firmwareVersion",
			     metadata->FirmwareVersion,
			     sizeof(metadata->FirmwareVersion));
	add_string(output_data_ir, "pfDriverMicrocodeVersion", "");
	add_untrusted_string(output_data_ir, "pfDriverMicrocodeVersion",
			     metadata->PfDriverMicrocodeVersion,
			     sizeof(metadata->PfDriverMicrocodeVersion));
	add_string(output_data_ir, "pfDriverVersion", "");
	add_untrusted_string(output_data_ir, "pfDriverVersion",
			     metadata->PfDriverVersion,
			     sizeof(metadata->PfDriverVersion));
	add_string(output_data_ir, "vfDriverVersion", "");
	add_untrusted_string(output_data_ir, "vfDriverVersion",
			     metadata->VfDriverVersion,
			     sizeof(metadata->VfDriverVersion));

	// Numeric fields
	add_int_hex_64(output_data_ir, "configuration",
		       metadata->Configuration);

	// PDI: MAC-style 8-byte string XX:XX:XX:XX:XX:XX:XX:XX (MSB first)
	// e.g., PDI 0x123456789ABCDEF0 → "12:34:56:78:9A:BC:DE:F0"
	{
		UINT64 pdi_val = metadata->Pdi;
		UINT8 pdi_bytes[8];
		memcpy(pdi_bytes, &pdi_val, sizeof(pdi_bytes));
		char pdi_str[24]; // "XX:XX:XX:XX:XX:XX:XX:XX\0"
		snprintf(pdi_str, sizeof(pdi_str),
			 "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
			 pdi_bytes[7], pdi_bytes[6], pdi_bytes[5], pdi_bytes[4],
			 pdi_bytes[3], pdi_bytes[2], pdi_bytes[1],
			 pdi_bytes[0]);
		json_object_object_add(output_data_ir, "pdi",
				       json_object_new_string(pdi_str));
	}

	// ArchitectureId: decomposed {raw, architecture} object
	// Bitfield layout (NV_PMC_BOOT_42):
	//   bits 29:24 = architecture
	{
		static const char *arch_names[] = {
			[0x16] = "Turing",    [0x17] = "Ampere",
			[0x18] = "Hopper",    [0x19] = "Ada",
			[0x1A] = "Blackwell", [0x1B] = "Blackwell2",
			[0x1C] = "Rubin",
		};
		static const size_t arch_names_count =
			sizeof(arch_names) / sizeof(arch_names[0]);
		UINT32 arch_id = metadata->ArchitectureId;
		UINT8 architecture = (arch_id >> 24) & 0x3F;

		json_object *arch_ir = json_object_new_object();
		add_int_hex_32(arch_ir, "raw", arch_id);

		if (architecture < arch_names_count &&
		    arch_names[architecture] != NULL) {
			json_object_object_add(
				arch_ir, "architecture",
				json_object_new_string(
					arch_names[architecture]));
		} else {
			json_object_object_add(
				arch_ir, "architecture",
				json_object_new_string("Unknown"));
		}
		json_object_object_add(output_data_ir, "architectureId",
				       arch_ir);
	}

	add_int(output_data_ir, "hardwareInfoType", metadata->HardwareInfoType);

	// PCI Info (if HardwareInfoType == 0). For any other type, round-trip the
	// 59 reserved bytes as an "opaqueHardwareInfo" hex string so data is not
	// lost across parse/emit while future types are still undefined in spec.
	if (metadata->HardwareInfoType == 0) {
		json_object *pci_info = json_object_new_object();
		add_int_hex_8(pci_info, "class", metadata->PciInfo.Class);
		add_int_hex_8(pci_info, "subclass", metadata->PciInfo.Subclass);
		add_int_hex_8(pci_info, "rev", metadata->PciInfo.Rev);
		add_int_hex_16(pci_info, "vendorId",
			       metadata->PciInfo.VendorId);
		add_int_hex_16(pci_info, "deviceId",
			       metadata->PciInfo.DeviceId);
		add_int_hex_16(pci_info, "subsystemVendorId",
			       metadata->PciInfo.SubsystemVendorId);
		add_int_hex_16(pci_info, "subsystemId",
			       metadata->PciInfo.SubsystemId);
		add_int_hex_64(pci_info, "bar0Start",
			       metadata->PciInfo.Bar0Start);
		add_int_hex_64(pci_info, "bar0Size",
			       metadata->PciInfo.Bar0Size);
		add_int_hex_64(pci_info, "bar1Start",
			       metadata->PciInfo.Bar1Start);
		add_int_hex_64(pci_info, "bar1Size",
			       metadata->PciInfo.Bar1Size);
		add_int_hex_64(pci_info, "bar2Start",
			       metadata->PciInfo.Bar2Start);
		add_int_hex_64(pci_info, "bar2Size",
			       metadata->PciInfo.Bar2Size);
		json_object_object_add(output_data_ir, "pciInfo", pci_info);
	} else {
		const UINT8 *reserved = (const UINT8 *)&metadata->PciInfo;
		add_bytes_hex(output_data_ir, "opaqueHardwareInfo", reserved,
			      sizeof(metadata->PciInfo));
	}
}

// Converts GPU Initialization Metadata from JSON IR to binary.
// Returns the number of bytes written.
/*
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ EFI_NVIDIA_GPU_CTX_INIT_METADATA                                 (192 bytes) │
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
 * │     EFI_NVIDIA_GPU_CTX_INIT_METADATA_PCI_INFO PciInfo (when type = 0):       │
 * │       UINT8   Class, Subclass, Rev                                      │
 * │       UINT16  VendorId, DeviceId, SubsystemVendorId, SubsystemId        │
 * │       UINT64  Bar0Start, Bar0Size, Bar1Start, Bar1Size, Bar2Start, ...  │
 * │     UINT8 Reserved[59]             ← for future hardware info types     │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
static size_t parse_gpu_ctx_init_metadata_to_bin(json_object *event_ir,
						 size_t ctx_instance,
						 FILE *output_file_stream)
{
	json_object *event_context_data_ir =
		get_event_context_n_data_ir(event_ir, ctx_instance);
	if (event_context_data_ir == NULL) {
		return 0;
	}

	// Unwrap from "gpuInitMetadata" variant
	json_object *inner = json_object_object_get(event_context_data_ir,
						    "gpuInitMetadata");
	if (inner != NULL) {
		event_context_data_ir = inner;
	}

	EFI_NVIDIA_GPU_CTX_INIT_METADATA metadata = { 0 };

	// String fields - use memcpy with strnlen to avoid strncpy truncation warnings
	const char *str;
	str = json_object_get_string(
		json_object_object_get(event_context_data_ir, "deviceName"));
	if (str) {
		memcpy(metadata.DeviceName, str,
		       strnlen(str, sizeof(metadata.DeviceName)));
	}

	str = json_object_get_string(json_object_object_get(
		event_context_data_ir, "firmwareVersion"));
	if (str) {
		memcpy(metadata.FirmwareVersion, str,
		       strnlen(str, sizeof(metadata.FirmwareVersion)));
	}

	str = json_object_get_string(json_object_object_get(
		event_context_data_ir, "pfDriverMicrocodeVersion"));
	if (str) {
		memcpy(metadata.PfDriverMicrocodeVersion, str,
		       strnlen(str, sizeof(metadata.PfDriverMicrocodeVersion)));
	}

	str = json_object_get_string(json_object_object_get(
		event_context_data_ir, "pfDriverVersion"));
	if (str) {
		memcpy(metadata.PfDriverVersion, str,
		       strnlen(str, sizeof(metadata.PfDriverVersion)));
	}

	str = json_object_get_string(json_object_object_get(
		event_context_data_ir, "vfDriverVersion"));
	if (str) {
		memcpy(metadata.VfDriverVersion, str,
		       strnlen(str, sizeof(metadata.VfDriverVersion)));
	}

	// Numeric fields
	get_value_hex_64(event_context_data_ir, "configuration",
			 &metadata.Configuration);

	// PDI: MAC-style string XX:XX:XX:XX:XX:XX:XX:XX (MSB first) → UINT64
	// e.g., "12:34:56:78:9A:BC:DE:F0" → PDI 0x123456789ABCDEF0
	{
		const char *pdi_str = json_object_get_string(
			json_object_object_get(event_context_data_ir, "pdi"));
		if (pdi_str != NULL) {
			UINT8 pdi_bytes[8] = { 0 };
			unsigned int b[8] = { 0 };
			if (sscanf(pdi_str,
				   "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
				   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5],
				   &b[6], &b[7]) == 8) {
				for (int k = 0; k < 8; k++) {
					pdi_bytes[k] = (UINT8)b[7 - k];
				}
				memcpy(&metadata.Pdi, pdi_bytes,
				       sizeof(metadata.Pdi));
			}
		}
	}

	// ArchitectureId: decomposed {raw, architecture} → extract raw
	{
		json_object *arch_obj = json_object_object_get(
			event_context_data_ir, "architectureId");
		if (arch_obj != NULL) {
			get_value_hex_32(arch_obj, "raw",
					 &metadata.ArchitectureId);
		}
	}

	metadata.HardwareInfoType = json_object_get_int64(
		json_object_object_get(event_context_data_ir,
				       "hardwareInfoType"));

	// PCI Info (if present and HardwareInfoType == 0). For any other type,
	// read back the reserved bytes through the "opaqueHardwareInfo" key
	// (populated by the round-trip parser path above).
	json_object *pci_info =
		json_object_object_get(event_context_data_ir, "pciInfo");
	if (pci_info != NULL && metadata.HardwareInfoType == 0) {
		get_value_hex_8(pci_info, "class", &metadata.PciInfo.Class);
		get_value_hex_8(pci_info, "subclass",
				&metadata.PciInfo.Subclass);
		get_value_hex_8(pci_info, "rev", &metadata.PciInfo.Rev);
		get_value_hex_16(pci_info, "vendorId",
				 &metadata.PciInfo.VendorId);
		get_value_hex_16(pci_info, "deviceId",
				 &metadata.PciInfo.DeviceId);
		get_value_hex_16(pci_info, "subsystemVendorId",
				 &metadata.PciInfo.SubsystemVendorId);
		get_value_hex_16(pci_info, "subsystemId",
				 &metadata.PciInfo.SubsystemId);
		get_value_hex_64(pci_info, "bar0Start",
				 &metadata.PciInfo.Bar0Start);
		get_value_hex_64(pci_info, "bar0Size",
				 &metadata.PciInfo.Bar0Size);
		get_value_hex_64(pci_info, "bar1Start",
				 &metadata.PciInfo.Bar1Start);
		get_value_hex_64(pci_info, "bar1Size",
				 &metadata.PciInfo.Bar1Size);
		get_value_hex_64(pci_info, "bar2Start",
				 &metadata.PciInfo.Bar2Start);
		get_value_hex_64(pci_info, "bar2Size",
				 &metadata.PciInfo.Bar2Size);
	} else if (metadata.HardwareInfoType != 0) {
		size_t opaque_len = 0;
		UINT8 *opaque_bytes = get_bytes_hex(event_context_data_ir,
						    "opaqueHardwareInfo",
						    &opaque_len);
		if (opaque_bytes != NULL) {
			size_t copy_len = opaque_len;
			if (copy_len > sizeof(metadata.PciInfo)) {
				copy_len = sizeof(metadata.PciInfo);
			}
			memcpy(&metadata.PciInfo, opaque_bytes, copy_len);
			free(opaque_bytes);
		}
	}

	return fwrite(&metadata, 1, sizeof(EFI_NVIDIA_GPU_CTX_INIT_METADATA),
		      output_file_stream);
}

// Parses GPU Event Legacy Xid (0x8001) context data to JSON IR.
// Extracts Xid code and message string.
// Output is placed inside the "gpuLegacyXid" variant within data.
/*
 * Example JSON IR (inside data.gpuLegacyXid):
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
	if (ctx == NULL) {
		return;
	}

	// Verify the context data doesn't extend past the event boundary.
	// DataSize may be less than sizeof(EFI_NVIDIA_GPU_CTX_LEGACY_XID)
	// because Message[236] is a max-size buffer; actual message may be shorter.
	// Minimum required: XidCode (4 bytes).
	UINT8 *event_end = (UINT8 *)event_header + total_event_size;
	UINT8 *data_end = (UINT8 *)ctx->Data + ctx->DataSize;
	if (data_end > event_end ||
	    ctx->DataSize < offsetof(EFI_NVIDIA_GPU_CTX_LEGACY_XID, Message)) {
		cper_print_log(
			"Error: GPU legacy XID context %zu extends past event boundary or is too small\n",
			ctx_instance);
		return;
	}

	EFI_NVIDIA_GPU_CTX_LEGACY_XID *xid =
		(EFI_NVIDIA_GPU_CTX_LEGACY_XID *)ctx->Data;

	add_int(output_data_ir, "xidCode", xid->XidCode);
	// Default to "" then override with add_untrusted_string (safe for
	// unterminated or non-printable binary data).
	// Use actual available bytes for message, not sizeof(xid->Message),
	// since DataSize may be smaller than the full struct.
	add_string(output_data_ir, "message", "");
	size_t msg_avail = ctx->DataSize -
			   offsetof(EFI_NVIDIA_GPU_CTX_LEGACY_XID, Message);
	if (msg_avail > sizeof(xid->Message)) {
		msg_avail = sizeof(xid->Message);
	}
	add_untrusted_string(output_data_ir, "message", xid->Message,
			     msg_avail);
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
	if (event_context_data_ir == NULL) {
		return 0;
	}

	// Unwrap from "gpuLegacyXid" variant
	json_object *inner =
		json_object_object_get(event_context_data_ir, "gpuLegacyXid");
	if (inner != NULL) {
		event_context_data_ir = inner;
	}

	EFI_NVIDIA_GPU_CTX_LEGACY_XID xid = { 0 };

	xid.XidCode = json_object_get_int64(
		json_object_object_get(event_context_data_ir, "xidCode"));

	const char *message = json_object_get_string(
		json_object_object_get(event_context_data_ir, "message"));
	if (message) {
		memcpy(xid.Message, message,
		       strnlen(message, sizeof(xid.Message)));
	}

	// Write only DataSize bytes (not the full struct), since the original
	// record may have a shorter message field than the max 236 bytes.
	json_object *ctx_ir = get_event_context_n_ir(event_ir, ctx_instance);
	UINT32 data_size = sizeof(EFI_NVIDIA_GPU_CTX_LEGACY_XID);
	if (ctx_ir != NULL) {
		json_object *ds_obj =
			json_object_object_get(ctx_ir, "dataSize");
		if (ds_obj != NULL) {
			UINT32 ds = (UINT32)json_object_get_int(ds_obj);
			if (ds > 0 &&
			    ds <= sizeof(EFI_NVIDIA_GPU_CTX_LEGACY_XID)) {
				data_size = ds;
			}
		}
	}

	return fwrite(&xid, 1, data_size, output_file_stream);
}

// GPU Recovery Action enum per spec v0.6:
//   0 = Ignore
//   1 = Driver Reload (Drain Applications)
//   2 = GPU Function-Level Reset
//   3 = GPU Hot Reset
//   4 = GPU Warm Reset
//   5 = GPU Cold Reset
//   6 = Node Reset
//   7..65535 = Reserved for future use
static const char *gpu_recovery_action_names[] = {
	[0] = "Ignore",	     [1] = "DriverReload", [2] = "GpuFlr",
	[3] = "GpuHotReset", [4] = "GpuWarmReset", [5] = "GpuColdReset",
	[6] = "NodeReset",
};
static const size_t gpu_recovery_action_names_count =
	sizeof(gpu_recovery_action_names) /
	sizeof(gpu_recovery_action_names[0]);

// Reverse lookup for emit side: accept either enum string or raw integer.
// Returns true if the JSON object was recognized; otherwise *out is unchanged.
static bool gpu_recovery_action_from_json(json_object *obj, UINT16 *out)
{
	if (obj == NULL) {
		return false;
	}
	if (json_object_is_type(obj, json_type_string)) {
		const char *s = json_object_get_string(obj);
		if (s == NULL) {
			return false;
		}
		for (size_t i = 0; i < gpu_recovery_action_names_count; i++) {
			if (gpu_recovery_action_names[i] != NULL &&
			    strcmp(s, gpu_recovery_action_names[i]) == 0) {
				*out = (UINT16)i;
				return true;
			}
		}
		return false;
	}
	// Any numeric json_type (int, double) gets coerced via int64.
	*out = (UINT16)json_object_get_int64(obj);
	return true;
}

// Parses GPU Recommended Actions (0x8002) context data to JSON IR.
// Extracts flags, recovery action, and diagnostic flow code.
// Output is placed inside the "gpuRecommendedActions" variant within data.
/*
 * Example JSON IR (inside data.gpuRecommendedActions):
 * {
 *   "flags": {
 *     "raw": "0x03",
 *     "recoveryPerformed": true,     // bit 0
 *     "immediateActionRequired": true, // bit 1
 *     "recoveryActionAmbiguous": false // bit 2
 *   },
 *   "recoveryAction": "GpuFlr",      // or integer for Reserved range
 *   "diagnosticFlow": 0
 * }
 */
static void parse_gpu_ctx_recommended_actions_to_ir(
	EFI_NVIDIA_EVENT_HEADER *event_header, size_t total_event_size,
	size_t ctx_instance, json_object *output_data_ir)
{
	EFI_NVIDIA_EVENT_CTX_HEADER *ctx = get_event_context_n(
		event_header, ctx_instance, total_event_size);
	if (ctx == NULL) {
		return;
	}

	// Verify the context data doesn't extend past the event boundary
	UINT8 *event_end = (UINT8 *)event_header + total_event_size;
	UINT8 *data_end = (UINT8 *)ctx->Data + ctx->DataSize;
	if (data_end > event_end ||
	    ctx->DataSize < sizeof(EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS)) {
		cper_print_log(
			"Error: GPU recommended actions context %zu extends past event boundary or is too small\n",
			ctx_instance);
		return;
	}

	EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS *actions =
		(EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS *)ctx->Data;

	// Flags decomposed per spec v0.6: bit 0 = recovery already performed,
	// bit 1 = immediate action required, bit 2 = recovery action ambiguous.
	// "raw" preserves the full byte including future-reserved bits 3-7.
	{
		json_object *flags_ir = json_object_new_object();
		add_int_hex_8(flags_ir, "raw", actions->Flags);
		add_bool(flags_ir, "recoveryPerformed",
			 (actions->Flags & 0x01) != 0);
		add_bool(flags_ir, "immediateActionRequired",
			 (actions->Flags & 0x02) != 0);
		add_bool(flags_ir, "recoveryActionAmbiguous",
			 (actions->Flags & 0x04) != 0);
		json_object_object_add(output_data_ir, "flags", flags_ir);
	}

	// Recovery action as enum string when within the defined range,
	// otherwise pass through as an integer to preserve future values.
	if (actions->RecoveryAction < gpu_recovery_action_names_count &&
	    gpu_recovery_action_names[actions->RecoveryAction] != NULL) {
		json_object_object_add(
			output_data_ir, "recoveryAction",
			json_object_new_string(
				gpu_recovery_action_names
					[actions->RecoveryAction]));
	} else {
		add_int(output_data_ir, "recoveryAction",
			actions->RecoveryAction);
	}

	add_int(output_data_ir, "diagnosticFlow", actions->DiagnosticFlow);
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
	if (event_context_data_ir == NULL) {
		return 0;
	}

	// Unwrap from "gpuRecommendedActions" variant
	json_object *inner = json_object_object_get(event_context_data_ir,
						    "gpuRecommendedActions");
	if (inner != NULL) {
		event_context_data_ir = inner;
	}

	EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS actions = { 0 };

	// Flags: accept either an object with "raw"/named bit keys (new shape)
	// or a legacy "0xNN" hex string (old shape). "raw" is authoritative when
	// present; otherwise the bit booleans are OR'd together.
	{
		json_object *flags_obj =
			json_object_object_get(event_context_data_ir, "flags");
		if (flags_obj != NULL &&
		    json_object_is_type(flags_obj, json_type_object)) {
			UINT8 raw = 0;
			get_value_hex_8(flags_obj, "raw", &raw);
			if (raw == 0) {
				if (json_object_get_boolean(
					    json_object_object_get(
						    flags_obj,
						    "recoveryPerformed"))) {
					raw |= 0x01;
				}
				if (json_object_get_boolean(
					    json_object_object_get(
						    flags_obj,
						    "immediateActionRequired"))) {
					raw |= 0x02;
				}
				if (json_object_get_boolean(
					    json_object_object_get(
						    flags_obj,
						    "recoveryActionAmbiguous"))) {
					raw |= 0x04;
				}
			}
			actions.Flags = raw;
		} else {
			// Legacy: "flags": "0xNN" hex string.
			get_value_hex_8(event_context_data_ir, "flags",
					&actions.Flags);
		}
	}

	// recoveryAction: accept enum string (new) or integer (legacy).
	UINT16 recovery_action = 0;
	gpu_recovery_action_from_json(
		json_object_object_get(event_context_data_ir, "recoveryAction"),
		&recovery_action);
	actions.RecoveryAction = recovery_action;

	actions.DiagnosticFlow = json_object_get_int64(json_object_object_get(
		event_context_data_ir, "diagnosticFlow"));

	return fwrite(&actions, 1,
		      sizeof(EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS),
		      output_file_stream);
}

// Parses the GPU timeout category context (0x9001, version 1.0).
// Unknown future 0x900x category contexts continue through the opaque path.
static void
parse_gpu_ctx_timeout_data_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
				 size_t total_event_size, size_t ctx_instance,
				 json_object *output_data_ir)
{
	EFI_NVIDIA_EVENT_CTX_HEADER *ctx = get_event_context_n(
		event_header, ctx_instance, total_event_size);
	if (ctx == NULL) {
		return;
	}

	size_t minimum_size = sizeof(EFI_NVIDIA_GPU_CTX_TIMEOUT_DATA);
	size_t maximum_size =
		minimum_size + EFI_NVIDIA_GPU_CTX_TIMEOUT_WAIT_TARGET_MAX + 1;
	UINT8 *event_end = (UINT8 *)event_header + total_event_size;
	UINT8 *data_end = (UINT8 *)ctx->Data + ctx->DataSize;
	if (ctx->CtxSize < sizeof(EFI_NVIDIA_EVENT_CTX_HEADER) ||
	    ctx->DataSize >
		    ctx->CtxSize - sizeof(EFI_NVIDIA_EVENT_CTX_HEADER) ||
	    data_end > event_end || ctx->DataSize < minimum_size ||
	    ctx->DataSize > maximum_size) {
		cper_print_log(
			"Error: GPU timeout context %zu extends past event boundary or has invalid size\n",
			ctx_instance);
		return;
	}

	EFI_NVIDIA_GPU_CTX_TIMEOUT_DATA *timeout =
		(EFI_NVIDIA_GPU_CTX_TIMEOUT_DATA *)ctx->Data;
	add_int_hex_64(output_data_ir, "timeoutNs", timeout->TimeoutNs);
	add_int_hex_64(output_data_ir, "elapsedNs", timeout->ElapsedNs);
	add_string(output_data_ir, "waitTarget", "");
	size_t wait_target_size = ctx->DataSize - minimum_size;
	if (wait_target_size > 0) {
		add_untrusted_string(output_data_ir, "waitTarget",
				     timeout->WaitTarget, wait_target_size);
	}
}

// Converts the GPU timeout category context from JSON IR to binary.
// The context's dataSize controls the variable string area so decoded records
// retain their original payload length on re-encode.
static size_t parse_gpu_ctx_timeout_data_to_bin(json_object *event_ir,
						size_t ctx_instance,
						FILE *output_file_stream)
{
	json_object *event_context_data_ir =
		get_event_context_n_data_ir(event_ir, ctx_instance);
	json_object *ctx_ir = get_event_context_n_ir(event_ir, ctx_instance);
	if (event_context_data_ir == NULL || ctx_ir == NULL) {
		return 0;
	}

	json_object *inner =
		json_object_object_get(event_context_data_ir, "gpuTimeoutData");
	if (inner != NULL) {
		event_context_data_ir = inner;
	}

	UINT8 payload[sizeof(EFI_NVIDIA_GPU_CTX_TIMEOUT_DATA) +
		      EFI_NVIDIA_GPU_CTX_TIMEOUT_WAIT_TARGET_MAX + 1] = { 0 };
	EFI_NVIDIA_GPU_CTX_TIMEOUT_DATA *timeout = (void *)payload;
	get_value_hex_64(event_context_data_ir, "timeoutNs",
			 &timeout->TimeoutNs);
	get_value_hex_64(event_context_data_ir, "elapsedNs",
			 &timeout->ElapsedNs);

	size_t minimum_size = sizeof(*timeout);
	size_t data_size = minimum_size;
	json_object *data_size_obj = json_object_object_get(ctx_ir, "dataSize");
	if (data_size_obj != NULL) {
		size_t requested =
			(size_t)json_object_get_uint64(data_size_obj);
		if (requested >= minimum_size && requested <= sizeof(payload)) {
			data_size = requested;
		}
	}

	const char *wait_target = json_object_get_string(
		json_object_object_get(event_context_data_ir, "waitTarget"));
	if (wait_target != NULL) {
		if (data_size == minimum_size) {
			size_t string_size = strlen(wait_target) + 1;
			if (string_size >
			    EFI_NVIDIA_GPU_CTX_TIMEOUT_WAIT_TARGET_MAX + 1) {
				string_size =
					EFI_NVIDIA_GPU_CTX_TIMEOUT_WAIT_TARGET_MAX +
					1;
			}
			data_size += string_size;
		}
		size_t capacity = data_size - minimum_size;
		if (capacity > 0) {
			size_t copy_len = strnlen(wait_target, capacity - 1);
			memcpy(timeout->WaitTarget, wait_target, copy_len);
		}
	}

	return fwrite(payload, 1, data_size, output_file_stream);
}

// Parses event context data type 0: Opaque data.
// Extracts the opaque data from the context data.
// Output is placed as a direct hex string under the "opaque" variant key.
/*
 * Example JSON IR (data.opaque is a hex string, not an object):
 *   "opaque": "deadbeefcafebabe..."
 */
static void parse_common_ctx_type0_to_ir(EFI_NVIDIA_EVENT_HEADER *event_header,
					 size_t total_event_size,
					 size_t ctx_instance,
					 json_object *data_ir)
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

	// Add the hex-encoded opaque data directly under the "opaque" key.
	// Unlike other variants which are objects, opaque is a flat hex string.
	add_bytes_hex(data_ir, "opaque", opaque_data, data_size);
}
// Converts opaque context data from JSON IR to binary.
// The "opaque" variant is a flat hex string (not a nested object).
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

	// "opaque" is a direct hex string, not a nested object
	json_object *opaque_str =
		json_object_object_get(event_context_data_ir, "opaque");
	if (opaque_str == NULL) {
		cper_print_log("Error: missing 'opaque' key in data\n");
		return 0;
	}

	const char *hex_string = json_object_get_string(opaque_str);
	if (hex_string == NULL) {
		cper_print_log("Error: opaque value is not a string\n");
		return 0;
	}

	size_t hex_len = strlen(hex_string);
	size_t decoded_len = hex_len / 2;
	UINT8 *decoded = malloc(decoded_len);
	if (decoded == NULL) {
		return 0;
	}

	if (hex_string_to_bytes(hex_string, hex_len, decoded, decoded_len) !=
	    decoded_len) {
		cper_print_log("Error: hex decode of opaque data failed\n");
		free(decoded);
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
// Output is placed inside the "type1" variant within data.
/*
 * Example JSON IR (inside data.type1):
 * {
 *   "keyValArray64": [
 *     { "key64": "0x112210f47de98115", "val64": "0x893456789abcdef1" },
 *     { "key64": "0x4d2b0ca3d3a2f9c3", "val64": "0x0f6b75c7f1a7b3c7" }
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
	if (ctx == NULL) {
		return;
	}

	// Verify the context data doesn't extend past the event boundary
	UINT8 *event_end = (UINT8 *)event_header + total_event_size;
	UINT8 *data_end = (UINT8 *)ctx->Data + ctx->DataSize;
	if (data_end > event_end) {
		cper_print_log(
			"Error: Type 1 context %zu extends past event boundary\n",
			ctx_instance);
		return;
	}

	EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1 *data_type1 =
		(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1 *)ctx->Data;
	UINT8 num_elements =
		ctx->DataSize / sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1);

	json_object *kv64arr = json_object_new_array();
	for (int i = 0; i < num_elements; i++, data_type1++) {
		json_object *kv = NULL;
		kv = json_object_new_object();
		add_int_hex_64(kv, "key64", data_type1->Key);
		add_int_hex_64(kv, "val64", data_type1->Value);

		json_object_array_add(kv64arr, kv);
	}
	json_object_object_add(output_data_ir, "keyValArray64", kv64arr);
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
	if (event_context_data_ir == NULL) {
		return 0;
	}

	// Unwrap from "type1" variant
	json_object *inner =
		json_object_object_get(event_context_data_ir, "type1");
	if (inner != NULL) {
		event_context_data_ir = inner;
	}

	// Get the kv64-array that was created by parse_common_ctx_type1_to_ir
	json_object *kv64arr =
		json_object_object_get(event_context_data_ir, "keyValArray64");
	if (kv64arr == NULL) {
		return 0;
	}

	size_t array_len = json_object_array_length(kv64arr);
	size_t bytes_written = 0;

	// Iterate through each key-value pair in the array
	for (size_t i = 0; i < array_len; i++) {
		json_object *kv = json_object_array_get_idx(kv64arr, i);
		if (kv == NULL) {
			continue;
		}

		// Create and populate the binary structure
		EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1 data_type1 = { 0 };
		get_value_hex_64(kv, "key64", &data_type1.Key);
		get_value_hex_64(kv, "val64", &data_type1.Value);

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
// Output is placed inside the "type2" variant within data.
/*
 * Example JSON IR (inside data.type2):
 * {
 *   "keyValArray32": [
 *     { "key32": "0x075bcd15", "val32": "0x3ade68b1" },
 *     { "key32": "0x211d1ae3", "val32": "0x069f6bc7" }
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
	if (ctx == NULL) {
		return;
	}

	// Verify the context data doesn't extend past the event boundary
	UINT8 *event_end = (UINT8 *)event_header + total_event_size;
	UINT8 *data_end = (UINT8 *)ctx->Data + ctx->DataSize;
	if (data_end > event_end) {
		cper_print_log(
			"Error: Type 2 context %zu extends past event boundary\n",
			ctx_instance);
		return;
	}

	EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2 *data_type2 =
		(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2 *)ctx->Data;
	UINT8 num_elements =
		ctx->DataSize / sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2);

	json_object *kv32arr = json_object_new_array();
	for (int i = 0; i < num_elements; i++, data_type2++) {
		json_object *kv = NULL;
		kv = json_object_new_object();
		add_int_hex_32(kv, "key32", data_type2->Key);
		add_int_hex_32(kv, "val32", data_type2->Value);

		json_object_array_add(kv32arr, kv);
	}
	json_object_object_add(output_data_ir, "keyValArray32", kv32arr);
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
	if (event_context_data_ir == NULL) {
		return 0;
	}

	// Unwrap from "type2" variant
	json_object *inner =
		json_object_object_get(event_context_data_ir, "type2");
	if (inner != NULL) {
		event_context_data_ir = inner;
	}

	// Get the kv32-array that was created by parse_common_ctx_type2_to_ir
	json_object *kv32arr =
		json_object_object_get(event_context_data_ir, "keyValArray32");
	if (kv32arr == NULL) {
		return 0;
	}

	size_t array_len = json_object_array_length(kv32arr);
	size_t bytes_written = 0;

	// Iterate through each key-value pair in the array
	for (size_t i = 0; i < array_len; i++) {
		json_object *kv = json_object_array_get_idx(kv32arr, i);
		if (kv == NULL) {
			continue;
		}

		// Create and populate the binary structure
		EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2 data_type2 = { 0 };
		get_value_hex_32(kv, "key32", &data_type2.Key);
		get_value_hex_32(kv, "val32", &data_type2.Value);

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
// Output is placed inside the "type3" variant within data.
/*
 * Example JSON IR (inside data.type3):
 * {
 *   "valArray64": [
 *     { "val64": "0x112210f47de98115" },
 *     { "val64": "0x893456789abcdef1" }
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
	if (ctx == NULL) {
		return;
	}

	// Verify the context data doesn't extend past the event boundary
	UINT8 *event_end = (UINT8 *)event_header + total_event_size;
	UINT8 *data_end = (UINT8 *)ctx->Data + ctx->DataSize;
	if (data_end > event_end) {
		cper_print_log(
			"Error: Type 3 context %zu extends past event boundary\n",
			ctx_instance);
		return;
	}

	EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3 *data_type3 =
		(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3 *)ctx->Data;
	UINT8 num_elements =
		ctx->DataSize / sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3);

	json_object *val64arr = json_object_new_array();
	for (int i = 0; i < num_elements; i++, data_type3++) {
		json_object *v = NULL;
		v = json_object_new_object();
		add_int_hex_64(v, "val64", data_type3->Value);

		json_object_array_add(val64arr, v);
	}
	json_object_object_add(output_data_ir, "valArray64", val64arr);
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
	if (event_context_data_ir == NULL) {
		return 0;
	}

	// Unwrap from "type3" variant
	json_object *inner =
		json_object_object_get(event_context_data_ir, "type3");
	if (inner != NULL) {
		event_context_data_ir = inner;
	}

	// Get the v64-array that was created by parse_common_ctx_type3_to_ir
	json_object *v64arr =
		json_object_object_get(event_context_data_ir, "valArray64");
	if (v64arr == NULL) {
		return 0;
	}

	size_t array_len = json_object_array_length(v64arr);
	size_t bytes_written = 0;

	// Iterate through each key-value pair in the array
	for (size_t i = 0; i < array_len; i++) {
		json_object *v = json_object_array_get_idx(v64arr, i);
		if (v == NULL) {
			continue;
		}

		// Create and populate the binary structure
		EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3 data_type3 = { 0 };
		get_value_hex_64(v, "val64", &data_type3.Value);

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
// Output is placed inside the "type4" variant within data.
/*
 * Example JSON IR (inside data.type4):
 * {
 *   "valArray32": [
 *     { "val32": "0x075bcd15" },
 *     { "val32": "0x3ade68b1" }
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
	if (ctx == NULL) {
		return;
	}

	// Verify the context data doesn't extend past the event boundary
	UINT8 *event_end = (UINT8 *)event_header + total_event_size;
	UINT8 *data_end = (UINT8 *)ctx->Data + ctx->DataSize;
	if (data_end > event_end) {
		cper_print_log(
			"Error: Type 4 context %zu extends past event boundary\n",
			ctx_instance);
		return;
	}

	EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4 *data_type4 =
		(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4 *)ctx->Data;
	UINT8 num_elements =
		ctx->DataSize / sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4);

	json_object *val32arr = json_object_new_array();
	for (int i = 0; i < num_elements; i++, data_type4++) {
		json_object *v = NULL;
		v = json_object_new_object();
		add_int_hex_32(v, "val32", data_type4->Value);

		json_object_array_add(val32arr, v);
	}
	json_object_object_add(output_data_ir, "valArray32", val32arr);
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
	if (event_context_data_ir == NULL) {
		return 0;
	}

	// Unwrap from "type4" variant
	json_object *inner =
		json_object_object_get(event_context_data_ir, "type4");
	if (inner != NULL) {
		event_context_data_ir = inner;
	}

	// Get the v32-array that was created by parse_common_ctx_type4_to_ir
	json_object *v32arr =
		json_object_object_get(event_context_data_ir, "valArray32");
	if (v32arr == NULL) {
		return 0;
	}

	size_t array_len = json_object_array_length(v32arr);
	size_t bytes_written = 0;

	// Iterate through each key-value pair in the array
	for (size_t i = 0; i < array_len; i++) {
		json_object *v = json_object_array_get_idx(v32arr, i);
		if (v == NULL) {
			continue;
		}

		// Create and populate the binary structure
		EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4 data_type4 = { 0 };
		get_value_hex_32(v, "val32", &data_type4.Value);

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
 *     "sourceDeviceType": "CPU",
 *     "type": "0x0064",
 *     "subtype": "0x00C8",
 *     "traceId": "0x0000000000000000"
 *   },
 *   "eventInfo": {
 *     "version": "0.1",
 *     "cpu": {
 *       "SocketNum": 0,
 *       "Architecture": {
 *         "hidFam": "0x07",
 *         "revision": "1.1",
 *         "chipId": "0x41",
 *         "preSiPlatform": "Silicon",
 *         "errorInjection": false
 *       },
 *       "Ecid1": "0x499602d2",
 *       "Ecid2": "0x89abcdef",
 *       "Ecid3": "0x4d2b0ca3",
 *       "Ecid4": "0x0f6b75c7",
 *       "InstanceBase": "0x0000ffff00000000"
 *     }
 *   },
 *   "eventContexts": [
 *     {
 *       "version": 0,
 *       "dataFormatType": "0x0001",
 *       "dataFormatVersion": "0.0",
 *       "dataSize": 32,
 *       "data": {
 *         "type1": {
 *           "keyValArray64": [
 *             { "key64": "0x112210f47de98115", "val64": "0x893456789abcdef1" }
 *           ]
 *         }
 *       }
 *     }
 *   ]
 * }
 */
json_object *cper_section_nvidia_events_to_ir(const UINT8 *section, UINT32 size,
					      char **desc_string)
{
	if (size < sizeof(EFI_NVIDIA_EVENT_HEADER) +
			   sizeof(EFI_NVIDIA_EVENT_INFO_HEADER)) {
		cper_print_log("NVIDIA Events section too small: %u < %zu",
			       size,
			       sizeof(EFI_NVIDIA_EVENT_HEADER) +
				       sizeof(EFI_NVIDIA_EVENT_INFO_HEADER));
		return NULL;
	}

	EFI_NVIDIA_EVENT_HEADER *event_header =
		(EFI_NVIDIA_EVENT_HEADER *)section;
	// Check event header version compatibility
	if (!check_event_header_version(event_header->EventVersion,
					EFI_NVIDIA_EVENT_HEADER_VERSION,
					"parsing")) {
		return NULL;
	}

	json_object *event_ir = json_object_new_object();

	// Parse event header fields
	json_object *event_header_ir = json_object_new_object();
	json_object_object_add(event_ir, "eventHeader", event_header_ir);
	*desc_string = malloc(SECTION_DESC_STRING_SIZE);
	if (*desc_string == NULL) {
		cper_print_log(
			"Error: Failed to allocate memory for description string\n");
		json_object_put(event_ir);
		return NULL;
	}
	int outstr_len = 0;
	const char *signature = event_header->Signature;
	int sig_len = cper_printable_string_length(
		event_header->Signature, sizeof(event_header->Signature));
	if (sig_len <= 0) {
		signature = "";
		sig_len = 0;
	}
	outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
			      "A %.*s Nvidia Event occurred", sig_len,
			      signature);
	if (outstr_len < 0) {
		cper_print_log(
			"Error: Could not write to description string\n");
	} else if (outstr_len > SECTION_DESC_STRING_SIZE) {
		cper_print_log("Error: Description string truncated: %s\n",
			       *desc_string);
	}
	add_untrusted_string(event_header_ir, "signature", signature, 16);
	add_int(event_header_ir, "version", event_header->EventVersion);
	static const char *sourceDeviceTypeNames[] = { "CPU", "GPU", "DPU",
						       "NIC", "SWX", "BMC" };
	UINT8 sdt = (UINT8)event_header->SourceDeviceType;
	if (sdt <
	    sizeof(sourceDeviceTypeNames) / sizeof(sourceDeviceTypeNames[0])) {
		json_object_object_add(
			event_header_ir, "sourceDeviceType",
			json_object_new_string(sourceDeviceTypeNames[sdt]));
	} else {
		json_object_object_add(event_header_ir, "sourceDeviceType",
				       json_object_new_string("Unknown"));
	}
	add_int_hex_16(event_header_ir, "type", event_header->EventType);
	if (sdt == GPU) {
		const char *type_name =
			gpu_event_type_name(event_header->EventType);
		if (type_name != NULL) {
			json_object_object_add(
				event_header_ir, "typeName",
				json_object_new_string(type_name));
		}
	}
	add_int_hex_16(event_header_ir, "subtype", event_header->EventSubtype);
	if (event_header->EventTraceId != 0) {
		add_int_hex_64(event_header_ir, "traceId",
			       event_header->EventTraceId);
	}

	// Parse event info structure
	EFI_NVIDIA_EVENT_INFO_HEADER *event_info_header =
		get_event_info_header(event_header);
	if (sizeof(EFI_NVIDIA_EVENT_HEADER) + event_info_header->InfoSize >
	    size) {
		cper_print_log(
			"NVIDIA Events info extends past section: %zu + %u > %u",
			sizeof(EFI_NVIDIA_EVENT_HEADER),
			event_info_header->InfoSize, size);
		json_object_put(event_ir);
		return NULL;
	}
	json_object *event_info_ir = json_object_new_object();
	json_object_object_add(event_ir, "eventInfo", event_info_ir);
	// Format version as "major.minor" string (high byte = major, low byte = minor)
	UINT8 info_major = get_info_major_version(event_info_header);
	UINT8 info_minor = get_info_minor_version(event_info_header);
	char info_version_str[8];
	snprintf(info_version_str, sizeof(info_version_str), "%u.%u",
		 info_major, info_minor);
	json_object_object_add(event_info_ir, "version",
			       json_object_new_string(info_version_str));

	// Call device-specific handler to parse additional event info fields.
	// Device-specific fields are nested under a variant key (e.g., "cpu", "gpu").
	// Selection is by (SourceDeviceType, major version) so future major
	// revisions of the same device-type layout can coexist.
	NVIDIA_EVENT_SRC_DEV src_dev =
		(NVIDIA_EVENT_SRC_DEV)event_header->SourceDeviceType;
	bool info_handler_found = false;
	for (size_t i = 0;
	     i < sizeof(nv_event_types) / sizeof(nv_event_types[0]); i++) {
		if (src_dev != nv_event_types[i].srcDev) {
			continue;
		}
		if (info_major != nv_event_types[i].major_version) {
			continue;
		}
		const char *variant = event_info_variant_key(src_dev);
		json_object *device_info_ir = json_object_new_object();
		json_object_object_add(event_info_ir, variant, device_info_ir);
		nv_event_types[i].callback(event_header, device_info_ir);
		info_handler_found = true;
		break;
	}
	if (!info_handler_found) {
		cper_print_log(
			"Warning: no NVIDIA Event Info handler for srcDev=%u, "
			"version %u.%u. Device-specific info skipped.\n",
			(unsigned)src_dev, (unsigned)info_major,
			(unsigned)info_minor);
	}
	// Parse all event contexts into an array
	json_object *event_contexts_ir = json_object_new_array();
	json_object_object_add(event_ir, "eventContexts", event_contexts_ir);

	size_t max_contexts = (size - sizeof(EFI_NVIDIA_EVENT_HEADER) -
			       sizeof(EFI_NVIDIA_EVENT_INFO_HEADER)) /
			      sizeof(EFI_NVIDIA_EVENT_CTX_HEADER);
	UINT8 ctx_count = event_header->EventContextCount;
	if (ctx_count > max_contexts) {
		cper_print_log(
			"NVIDIA Events context count %u exceeds maximum %zu for section size %u",
			ctx_count, max_contexts, size);
		ctx_count = (UINT8)max_contexts;
	}

	for (size_t i = 0; i < (size_t)ctx_count; i++) {
		EFI_NVIDIA_EVENT_CTX_HEADER *ctx =
			get_event_context_n(event_header, i, size);
		if (ctx == NULL) {
			continue;
		}
		// Parse common context header fields
		json_object *event_context_ir = json_object_new_object();
		// Add context to array
		json_object_array_add(event_contexts_ir, event_context_ir);
		add_int(event_context_ir, "version", ctx->CtxVersion);
		add_int_hex_16(event_context_ir, "dataFormatType",
			       ctx->DataFormatType);
		// DataFormatVersion encoded as "major.minor" per spec v0.6:
		// "encode the version using the same major.minor semantics of
		// the other 2-byte version fields in this specification."
		{
			char dfv_str[8];
			snprintf(dfv_str, sizeof(dfv_str), "%u.%u",
				 (unsigned)((ctx->DataFormatVersion >> 8) &
					    0xFF),
				 (unsigned)(ctx->DataFormatVersion & 0xFF));
			json_object_object_add(event_context_ir,
					       "dataFormatVersion",
					       json_object_new_string(dfv_str));
		}
		add_int(event_context_ir, "dataSize", ctx->DataSize);
		json_object *data_ir = json_object_new_object();
		json_object_object_add(event_context_ir, "data", data_ir);

		// Opaque (type0) is a flat hex string under "opaque" key,
		// all other variants are objects under their variant key.
		if (ctx->DataFormatType == OPAQUE) {
			// Opaque adds "opaque": "<hex>" directly to data_ir
			parse_common_ctx_type0_to_ir(event_header, size, i,
						     data_ir);
			continue;
		}

		// Context data is nested under a variant key (e.g., "type1", "gpuInitMetadata")
		const char *variant = event_ctx_data_variant_key(
			src_dev, ctx->DataFormatType);
		json_object *inner_data_ir = json_object_new_object();
		json_object_object_add(data_ir, variant, inner_data_ir);

		// Check for device/format-specific custom handler first
		bool handler_override_found = false;
		for (size_t handler_idx = 0;
		     handler_idx <
		     sizeof(event_ctx_handlers) / sizeof(event_ctx_handlers[0]);
		     handler_idx++) {
			if (event_ctx_handlers[handler_idx].srcDev == src_dev &&
			    event_ctx_handlers[handler_idx].dataFormatType ==
				    ctx->DataFormatType) {
				if (event_ctx_handlers[handler_idx].callback !=
				    NULL) {
					event_ctx_handlers[handler_idx].callback(
						event_header, size, i,
						inner_data_ir);
					handler_override_found = true;
					break;
				}
			}
		}
		if (handler_override_found) {
			continue;
		}
		// Use default parser based on data format type
		switch (ctx->DataFormatType) {
		case TYPE_1:
			parse_common_ctx_type1_to_ir(event_header, size, i,
						     inner_data_ir);
			break;
		case TYPE_2:
			parse_common_ctx_type2_to_ir(event_header, size, i,
						     inner_data_ir);
			break;
		case TYPE_3:
			parse_common_ctx_type3_to_ir(event_header, size, i,
						     inner_data_ir);
			break;
		case TYPE_4:
			parse_common_ctx_type4_to_ir(event_header, size, i,
						     inner_data_ir);
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
 * │   e.g., EFI_NVIDIA_CPU_EVENT_INFO (29 bytes)                            │
 * │     or  EFI_NVIDIA_GPU_EVENT_INFO_V1/V2 (13 bytes)                     │
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
		json_object_object_get(section, "eventHeader");
	EFI_NVIDIA_EVENT_HEADER event_header = { 0 };
	event_header.EventVersion = json_object_get_int64(
		json_object_object_get(event_header_ir, "version"));
	// Check event header version compatibility
	if (!check_event_header_version(event_header.EventVersion,
					EFI_NVIDIA_EVENT_HEADER_VERSION,
					"generation")) {
		return;
	}
	json_object *sourceDeviceType_obj;
	if (json_object_object_get_ex(event_header_ir, "sourceDeviceType",
				      &sourceDeviceType_obj)) {
		const char *sdt_str =
			json_object_get_string(sourceDeviceType_obj);
		static const char *sourceDeviceTypeNames[] = { "CPU", "GPU",
							       "DPU", "NIC",
							       "SWX", "BMC" };
		for (size_t i = 0; i < sizeof(sourceDeviceTypeNames) /
					       sizeof(sourceDeviceTypeNames[0]);
		     i++) {
			if (strcmp(sdt_str, sourceDeviceTypeNames[i]) == 0) {
				event_header.SourceDeviceType = i;
				break;
			}
		}
	}

	event_header.Reserved1 = 0;
	get_value_hex_16(event_header_ir, "type", &event_header.EventType);
	get_value_hex_16(event_header_ir, "subtype",
			 &event_header.EventSubtype);
	// Accept the new "traceId" key per spec v0.6 (Event Trace ID, byte 8, 8 bytes).
	// For backward compat, fall back to the legacy "linkId" key.
	if (json_object_object_get(event_header_ir, "traceId") != NULL) {
		get_value_hex_64(event_header_ir, "traceId",
				 &event_header.EventTraceId);
	} else {
		get_value_hex_64(event_header_ir, "linkId",
				 &event_header.EventTraceId);
	}

	// Signature is optional - only copy if present
	json_object *signature_obj =
		json_object_object_get(event_header_ir, "signature");
	if (signature_obj != NULL) {
		const char *sig_str = json_object_get_string(signature_obj);
		if (sig_str != NULL) {
			// Copy up to 16 bytes, don't force null termination
			// (signature can be exactly 16 chars with no null terminator)
			size_t sig_len = strlen(sig_str);
			size_t copy_len =
				sig_len < sizeof(event_header.Signature) ?
					sig_len :
					sizeof(event_header.Signature);
			memcpy(event_header.Signature, sig_str, copy_len);
			// Only null-terminate if there's room
			if (sig_len < sizeof(event_header.Signature)) {
				event_header.Signature[sig_len] = '\0';
			}
		}
	}

	// Get event contexts and count them before writing header
	// (EventContextCount must be set before fwrite)
	json_object *event_contexts_ir =
		json_object_object_get(section, "eventContexts");
	size_t ctx_count = 0;
	if (event_contexts_ir != NULL &&
	    json_object_is_type(event_contexts_ir, json_type_array)) {
		ctx_count = json_object_array_length(event_contexts_ir);
		// EventContextCount is a single byte; cap to avoid silent wrap.
		if (ctx_count > UINT8_MAX) {
			cper_print_log(
				"Warning: NVIDIA Events context array length %zu "
				"exceeds EventContextCount max 255; truncating.\n",
				ctx_count);
			ctx_count = UINT8_MAX;
		}
		event_header.EventContextCount = (UINT8)ctx_count;
	}

	fwrite(&event_header, sizeof(EFI_NVIDIA_EVENT_HEADER), 1, out);

	json_object *event_info_ir =
		json_object_object_get(section, "eventInfo");
	EFI_NVIDIA_EVENT_INFO_HEADER event_info_header = { 0 };
	// Parse "major.minor" version string back to UINT16 (high byte = major, low byte = minor)
	const char *info_ver_str = json_object_get_string(
		json_object_object_get(event_info_ir, "version"));
	UINT32 info_major = 0;
	UINT32 info_minor = 0;
	if (info_ver_str) {
		sscanf(info_ver_str, "%u.%u", &info_major, &info_minor);
	}
	event_info_header.InfoVersion =
		(UINT16)((info_major << 8) | (info_minor & 0xFF));

	// Look up by (srcDev, major version).
	NVIDIA_EVENT_SRC_DEV srcDev =
		(NVIDIA_EVENT_SRC_DEV)event_header.SourceDeviceType;
	NV_EVENT_INFO_CALLBACKS *nv_event_info_callback = NULL;
	for (size_t i = 0;
	     i < sizeof(nv_event_types) / sizeof(nv_event_types[0]); i++) {
		NV_EVENT_INFO_CALLBACKS *callback = &nv_event_types[i];
		if (srcDev != callback->srcDev) {
			continue;
		}
		if ((UINT8)info_major != callback->major_version) {
			continue;
		}
		nv_event_info_callback = callback;
		break;
	}
	if (nv_event_info_callback == NULL) {
		cper_print_log("NVIDIA Events: no info handler for srcDev=%u, "
			       "version %u.%u. Skipping section write.\n",
			       (unsigned)srcDev, (unsigned)info_major,
			       (unsigned)info_minor);
		return;
	}

	event_info_header.InfoSize = sizeof(EFI_NVIDIA_EVENT_INFO_HEADER) +
				     nv_event_info_callback->info_size;

	size_t bytes_written = fwrite(&event_info_header, 1,
				      sizeof(EFI_NVIDIA_EVENT_INFO_HEADER),
				      out);
	// Unwrap device-specific fields from variant key (e.g., "cpu", "gpu")
	const char *variant = event_info_variant_key(
		(NVIDIA_EVENT_SRC_DEV)event_header.SourceDeviceType);
	json_object *device_info_ir =
		json_object_object_get(event_info_ir, variant);
	if (device_info_ir == NULL) {
		// Fallback: try flat format for backward compatibility
		device_info_ir = event_info_ir;
	}
	bytes_written +=
		nv_event_info_callback->callback_bin(device_info_ir, out);

	write_padding_to_16_byte_alignment(bytes_written, out);

	// Check if eventContexts field exists before iterating
	if (event_contexts_ir == NULL) {
		cper_print_log(
			"Warning: Missing eventContexts field in Nvidia Event JSON\n");
		return;
	}

	for (size_t ctx_instance = 0; ctx_instance < ctx_count;
	     ctx_instance++) {
		json_object *value = json_object_array_get_idx(
			event_contexts_ir, ctx_instance);
		if (value == NULL) {
			continue;
		}

		EFI_NVIDIA_EVENT_CTX_HEADER ctx = { 0 };
		ctx.CtxVersion = (uint16_t)json_object_get_int64(
			json_object_object_get(value, "version"));
		get_value_hex_16(value, "dataFormatType", &ctx.DataFormatType);
		// DataFormatVersion: accept "major.minor" string (spec v0.6) or
		// a plain integer (legacy libcper IR) for backward compat.
		{
			json_object *dfv_obj = json_object_object_get(
				value, "dataFormatVersion");
			ctx.DataFormatVersion = 0;
			if (dfv_obj != NULL &&
			    json_object_is_type(dfv_obj, json_type_string)) {
				unsigned int dfv_maj = 0;
				unsigned int dfv_min = 0;
				const char *s = json_object_get_string(dfv_obj);
				if (s != NULL && sscanf(s, "%u.%u", &dfv_maj,
							&dfv_min) == 2) {
					ctx.DataFormatVersion =
						(UINT16)(((dfv_maj & 0xFF)
							  << 8) |
							 (dfv_min & 0xFF));
				}
			} else if (dfv_obj != NULL) {
				ctx.DataFormatVersion =
					(UINT16)json_object_get_int64(dfv_obj);
			}
		}
		ctx.DataSize = json_object_get_int(
			json_object_object_get(value, "dataSize"));
		// CtxSize includes 16-byte alignment padding so the reader
		// can advance to the next context with ptr += CtxSize.
		{
			UINT32 raw = sizeof(EFI_NVIDIA_EVENT_CTX_HEADER) +
				     ctx.DataSize;
			ctx.CtxSize = (raw + 15) & ~(UINT32)15;
		}
		bytes_written = fwrite(
			&ctx, 1, sizeof(EFI_NVIDIA_EVENT_CTX_HEADER), out);

		// Check for device/format-specific custom handler
		bool handler_override_found = false;
		for (size_t j = 0; j < sizeof(event_ctx_handlers) /
					       sizeof(event_ctx_handlers[0]);
		     j++) {
			if (event_ctx_handlers[j].srcDev ==
				    (NVIDIA_EVENT_SRC_DEV)
					    event_header.SourceDeviceType &&
			    event_ctx_handlers[j].dataFormatType ==
				    ctx.DataFormatType) {
				bytes_written +=
					event_ctx_handlers[j].callback_bin(
						section, ctx_instance, out);
				handler_override_found = true;
				break;
			}
		}
		// If no handler override found, use default parser based on data format type
		if (!handler_override_found) {
			switch (ctx.DataFormatType) {
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
		write_padding_to_16_byte_alignment(bytes_written, out);
	}
}
