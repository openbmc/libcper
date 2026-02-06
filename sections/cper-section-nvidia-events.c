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
 *   "eventHeader": { ... }           → EFI_NVIDIA_EVENT_HEADER
 *   "eventInfo": { ... }             → EFI_NVIDIA_EVENT_INFO_*
 *   "eventContexts": [               → Array of contexts            ("eventContext"*)
 *     {
 *       "data": {                    → EFI_NVIDIA_EVENT_CTX_DATA_*
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

// Helper: Check if info major version matches - returns false and logs on mismatch
static bool check_info_major_version(UINT8 maj, UINT8 min, UINT8 exp_maj,
				     const char *operation)
{
	if (maj != exp_maj) {
		cper_print_log(
			"Error: NVIDIA Event Info major version mismatch: "
			"expected %d.x, got %d.%d. Skipping event info %s.\n",
			(int)exp_maj, (int)maj, (int)min, operation);
		return false;
	}
	return true;
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
	{ GPU, EFI_NVIDIA_GPU_EVENT_INFO_MAJ, EFI_NVIDIA_GPU_EVENT_INFO_MIN,
	  &parse_gpu_info_to_ir, &parse_gpu_info_to_bin,
	  sizeof(EFI_NVIDIA_GPU_EVENT_INFO) }
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
		if (ptr + ctx->CtxSize > end) {
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
	if (event_context_ir == NULL) {
		return NULL;
	}

	return json_object_object_get(event_context_ir, "data");
}

// Parses CPU-specific event info structure into JSON IR format.
// Extracts socket number, architecture (decoded), ECID array, and instance base.
/*
 * Example JSON IR "data" output:
 * {
 *   "SocketNum": 0,
 *   "Architecture": {
 *     "hidFam": 7,
 *     "majorRev": 1,
 *     "chipId": 65,
 *     "minorRev": 1,
 *     "preSiPlatform": { "raw": 0, "value": "Silicon" },
 *     "einjTag": false
 *   },
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

	json_object_object_add(
		event_info_ir, "SocketNum",
		json_object_new_int64(cpu_event_info->SocketNum));

	// Decode Architecture field into components
	UINT32 arch = cpu_event_info->Architecture;
	json_object *arch_ir = json_object_new_object();
	json_object_object_add(arch_ir, "hidFam",
			       json_object_new_int((arch >> 0) & 0xF));
	json_object_object_add(arch_ir, "majorRev",
			       json_object_new_int((arch >> 4) & 0xF));
	json_object_object_add(arch_ir, "chipId",
			       json_object_new_int((arch >> 8) & 0xFF));
	json_object_object_add(arch_ir, "minorRev",
			       json_object_new_int((arch >> 16) & 0xF));

	// preSiPlatform: 0 = Silicon, non-zero = PreSilicon
	UINT8 pre_si = (arch >> 20) & 0x1F;
	json_object *pre_si_ir = json_object_new_object();
	json_object_object_add(pre_si_ir, "raw", json_object_new_int(pre_si));
	json_object_object_add(
		pre_si_ir, "value",
		json_object_new_string(pre_si == 0 ? "Silicon" : "PreSilicon"));
	json_object_object_add(arch_ir, "preSiPlatform", pre_si_ir);

	json_object_object_add(arch_ir, "einjTag",
			       json_object_new_boolean((arch >> 31) & 0x1));
	json_object_object_add(event_info_ir, "Architecture", arch_ir);

	json_object_object_add(event_info_ir, "Ecid1",
			       json_object_new_uint64(cpu_event_info->Ecid[0]));
	json_object_object_add(event_info_ir, "Ecid2",
			       json_object_new_uint64(cpu_event_info->Ecid[1]));
	json_object_object_add(event_info_ir, "Ecid3",
			       json_object_new_uint64(cpu_event_info->Ecid[2]));
	json_object_object_add(event_info_ir, "Ecid4",
			       json_object_new_uint64(cpu_event_info->Ecid[3]));
	json_object_object_add(
		event_info_ir, "InstanceBase",
		json_object_new_uint64(cpu_event_info->InstanceBase));
}
// Converts CPU-specific event info from JSON IR to CPER binary format.
// Writes socket number, architecture (reconstructed), ECID array, instance base.
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
	cpu_event_info.SocketNum = json_object_get_int64(
		json_object_object_get(event_info_ir, "SocketNum"));

	// Reconstruct Architecture from decoded components
	json_object *arch_ir =
		json_object_object_get(event_info_ir, "Architecture");
	UINT32 hid_fam =
		json_object_get_int(json_object_object_get(arch_ir, "hidFam"));
	UINT32 major_rev = json_object_get_int(
		json_object_object_get(arch_ir, "majorRev"));
	UINT32 chip_id =
		json_object_get_int(json_object_object_get(arch_ir, "chipId"));
	UINT32 minor_rev = json_object_get_int(
		json_object_object_get(arch_ir, "minorRev"));
	json_object *pre_si_ir =
		json_object_object_get(arch_ir, "preSiPlatform");
	UINT32 pre_si =
		json_object_get_int(json_object_object_get(pre_si_ir, "raw"));
	UINT32 einj_tag = json_object_get_boolean(
				  json_object_object_get(arch_ir, "einjTag")) ?
				  1 :
				  0;

	cpu_event_info.Architecture =
		(hid_fam & 0xF) | ((major_rev & 0xF) << 4) |
		((chip_id & 0xFF) << 8) | ((minor_rev & 0xF) << 16) |
		((pre_si & 0x1F) << 20) | ((einj_tag & 0x1) << 31);

	cpu_event_info.Ecid[0] = json_object_get_uint64(
		json_object_object_get(event_info_ir, "Ecid1"));
	cpu_event_info.Ecid[1] = json_object_get_uint64(
		json_object_object_get(event_info_ir, "Ecid2"));
	cpu_event_info.Ecid[2] = json_object_get_uint64(
		json_object_object_get(event_info_ir, "Ecid3"));
	cpu_event_info.Ecid[3] = json_object_get_uint64(
		json_object_object_get(event_info_ir, "Ecid4"));
	cpu_event_info.InstanceBase = json_object_get_uint64(
		json_object_object_get(event_info_ir, "InstanceBase"));
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
	// Verify InfoSize is large enough for GPU event info
	EFI_NVIDIA_EVENT_INFO_HEADER *info_header =
		get_event_info_header(event_header);
	size_t required_size = sizeof(EFI_NVIDIA_EVENT_INFO_HEADER) +
			       sizeof(EFI_NVIDIA_GPU_EVENT_INFO);
	if (info_header->InfoSize < required_size) {
		cper_print_log(
			"Error: GPU event info size too small: got %d, need %zu\n",
			info_header->InfoSize, required_size);
		return;
	}

	EFI_NVIDIA_GPU_EVENT_INFO *gpu_event_info =
		(EFI_NVIDIA_GPU_EVENT_INFO *)get_event_info(event_header);
	if (gpu_event_info == NULL) {
		return;
	}

	json_object_object_add(
		event_info_ir, "EventOriginator",
		json_object_new_int64(
			gpu_event_info->EventOriginator)); // UINT8
	json_object_object_add(
		event_info_ir, "SourcePartition",
		json_object_new_int64(
			gpu_event_info->SourcePartition)); // UINT16
	json_object_object_add(
		event_info_ir, "SourceSubPartition",
		json_object_new_int64(
			gpu_event_info->SourceSubPartition)); // UINT16
	json_object_object_add(
		event_info_ir, "Pdi",
		json_object_new_uint64(gpu_event_info->Pdi)); // UINT64
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

	gpu_event_info.EventOriginator = json_object_get_uint64(
		json_object_object_get(event_info_ir, "EventOriginator"));
	gpu_event_info.SourcePartition = json_object_get_int64(
		json_object_object_get(event_info_ir, "SourcePartition"));
	gpu_event_info.SourceSubPartition = json_object_get_int64(
		json_object_object_get(event_info_ir, "SourceSubPartition"));
	gpu_event_info.Pdi = json_object_get_uint64(
		json_object_object_get(event_info_ir, "Pdi"));

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
	if (ctx == NULL) {
		return;
	}

	EFI_NVIDIA_GPU_CTX_METADATA *metadata =
		(EFI_NVIDIA_GPU_CTX_METADATA *)ctx->Data;

	// String fields - use json_object_new_string to stop at first null (no null padding in JSON)
	json_object_object_add(output_data_ir, "deviceName",
			       json_object_new_string(metadata->DeviceName));
	json_object_object_add(
		output_data_ir, "firmwareVersion",
		json_object_new_string(metadata->FirmwareVersion));
	json_object_object_add(
		output_data_ir, "pfDriverMicrocodeVersion",
		json_object_new_string(metadata->PfDriverMicrocodeVersion));
	json_object_object_add(
		output_data_ir, "pfDriverVersion",
		json_object_new_string(metadata->PfDriverVersion));
	json_object_object_add(
		output_data_ir, "vfDriverVersion",
		json_object_new_string(metadata->VfDriverVersion));

	// Numeric fields
	json_object_object_add(output_data_ir, "configuration",
			       json_object_new_uint64(metadata->Configuration));
	json_object_object_add(output_data_ir, "pdi",
			       json_object_new_uint64(metadata->Pdi));
	json_object_object_add(output_data_ir, "architectureId",
			       json_object_new_int64(metadata->ArchitectureId));
	json_object_object_add(
		output_data_ir, "hardwareInfoType",
		json_object_new_int64(metadata->HardwareInfoType));

	// PCI Info (if HardwareInfoType == 0)
	if (metadata->HardwareInfoType == 0) {
		json_object *pci_info = json_object_new_object();
		json_object_object_add(
			pci_info, "class",
			json_object_new_int64(metadata->PciInfo.Class));
		json_object_object_add(
			pci_info, "subclass",
			json_object_new_int64(metadata->PciInfo.Subclass));
		json_object_object_add(
			pci_info, "rev",
			json_object_new_int64(metadata->PciInfo.Rev));
		json_object_object_add(
			pci_info, "vendorId",
			json_object_new_int64(metadata->PciInfo.VendorId));
		json_object_object_add(
			pci_info, "deviceId",
			json_object_new_int64(metadata->PciInfo.DeviceId));
		json_object_object_add(
			pci_info, "subsystemVendorId",
			json_object_new_int64(
				metadata->PciInfo.SubsystemVendorId));
		json_object_object_add(
			pci_info, "subsystemId",
			json_object_new_int64(metadata->PciInfo.SubsystemId));
		json_object_object_add(
			pci_info, "bar0Start",
			json_object_new_uint64(metadata->PciInfo.Bar0Start));
		json_object_object_add(
			pci_info, "bar0Size",
			json_object_new_uint64(metadata->PciInfo.Bar0Size));
		json_object_object_add(
			pci_info, "bar1Start",
			json_object_new_uint64(metadata->PciInfo.Bar1Start));
		json_object_object_add(
			pci_info, "bar1Size",
			json_object_new_uint64(metadata->PciInfo.Bar1Size));
		json_object_object_add(
			pci_info, "bar2Start",
			json_object_new_uint64(metadata->PciInfo.Bar2Start));
		json_object_object_add(
			pci_info, "bar2Size",
			json_object_new_uint64(metadata->PciInfo.Bar2Size));
		json_object_object_add(output_data_ir, "pciInfo", pci_info);
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
	if (event_context_data_ir == NULL) {
		return 0;
	}

	EFI_NVIDIA_GPU_CTX_METADATA metadata = { 0 };

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
	metadata.Configuration = json_object_get_uint64(
		json_object_object_get(event_context_data_ir, "configuration"));
	metadata.Pdi = json_object_get_uint64(
		json_object_object_get(event_context_data_ir, "pdi"));
	metadata.ArchitectureId = json_object_get_int64(json_object_object_get(
		event_context_data_ir, "architectureId"));
	metadata.HardwareInfoType = json_object_get_int64(
		json_object_object_get(event_context_data_ir,
				       "hardwareInfoType"));

	// PCI Info (if present and HardwareInfoType == 0)
	json_object *pci_info =
		json_object_object_get(event_context_data_ir, "pciInfo");
	if (pci_info != NULL && metadata.HardwareInfoType == 0) {
		metadata.PciInfo.Class = json_object_get_int64(
			json_object_object_get(pci_info, "class"));
		metadata.PciInfo.Subclass = json_object_get_int64(
			json_object_object_get(pci_info, "subclass"));
		metadata.PciInfo.Rev = json_object_get_int64(
			json_object_object_get(pci_info, "rev"));
		metadata.PciInfo.VendorId = json_object_get_int64(
			json_object_object_get(pci_info, "vendorId"));
		metadata.PciInfo.DeviceId = json_object_get_int64(
			json_object_object_get(pci_info, "deviceId"));
		metadata.PciInfo.SubsystemVendorId = json_object_get_int64(
			json_object_object_get(pci_info, "subsystemVendorId"));
		metadata.PciInfo.SubsystemId = json_object_get_int64(
			json_object_object_get(pci_info, "subsystemId"));
		metadata.PciInfo.Bar0Start = json_object_get_uint64(
			json_object_object_get(pci_info, "bar0Start"));
		metadata.PciInfo.Bar0Size = json_object_get_uint64(
			json_object_object_get(pci_info, "bar0Size"));
		metadata.PciInfo.Bar1Start = json_object_get_uint64(
			json_object_object_get(pci_info, "bar1Start"));
		metadata.PciInfo.Bar1Size = json_object_get_uint64(
			json_object_object_get(pci_info, "bar1Size"));
		metadata.PciInfo.Bar2Start = json_object_get_uint64(
			json_object_object_get(pci_info, "bar2Start"));
		metadata.PciInfo.Bar2Size = json_object_get_uint64(
			json_object_object_get(pci_info, "bar2Size"));
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
	if (ctx == NULL) {
		return;
	}

	EFI_NVIDIA_GPU_CTX_LEGACY_XID *xid =
		(EFI_NVIDIA_GPU_CTX_LEGACY_XID *)ctx->Data;

	json_object_object_add(output_data_ir, "xidCode",
			       json_object_new_int64(xid->XidCode));
	// Use json_object_new_string to stop at first null terminator (no null padding in JSON)
	json_object_object_add(output_data_ir, "message",
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
	if (event_context_data_ir == NULL) {
		return 0;
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
	if (ctx == NULL) {
		return;
	}

	EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS *actions =
		(EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS *)ctx->Data;

	json_object_object_add(output_data_ir, "flags",
			       json_object_new_int64(actions->Flags));
	json_object_object_add(output_data_ir, "recoveryAction",
			       json_object_new_int64(actions->RecoveryAction));
	json_object_object_add(output_data_ir, "diagnosticFlow",
			       json_object_new_int64(actions->DiagnosticFlow));
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

	EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS actions = { 0 };

	actions.Flags = json_object_get_int64(
		json_object_object_get(event_context_data_ir, "flags"));
	actions.RecoveryAction = json_object_get_int64(json_object_object_get(
		event_context_data_ir, "recoveryAction"));
	actions.DiagnosticFlow = json_object_get_int64(json_object_object_get(
		event_context_data_ir, "diagnosticFlow"));

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

	// Add the hex-encoded opaque data to JSON output
	add_bytes_hex(output_data_ir, "data", opaque_data, data_size);
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

	// Decode the hex data from the "data" field
	size_t decoded_len = 0;
	UINT8 *decoded =
		get_bytes_hex(event_context_data_ir, "data", &decoded_len);
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
		json_object_object_add(kv, "key64",
				       json_object_new_uint64(data_type1->Key));
		json_object_object_add(
			kv, "val64", json_object_new_uint64(data_type1->Value));

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
		data_type1.Key = json_object_get_uint64(
			json_object_object_get(kv, "key64"));
		data_type1.Value = json_object_get_uint64(
			json_object_object_get(kv, "val64"));

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
		json_object_object_add(kv, "key32",
				       json_object_new_uint64(data_type2->Key));
		json_object_object_add(
			kv, "val32", json_object_new_uint64(data_type2->Value));

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
		data_type2.Key = json_object_get_uint64(
			json_object_object_get(kv, "key32"));
		data_type2.Value = json_object_get_uint64(
			json_object_object_get(kv, "val32"));

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
		json_object_object_add(
			v, "val64", json_object_new_uint64(data_type3->Value));

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
		data_type3.Value = json_object_get_uint64(
			json_object_object_get(v, "val64"));

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
		json_object_object_add(
			v, "val32", json_object_new_uint64(data_type4->Value));

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
		data_type4.Value = json_object_get_uint64(
			json_object_object_get(v, "val32"));

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
 *     "sourceDeviceType": 0,
 *     "type": 100,
 *     "subtype": 200,
 *     "linkId": 0
 *   },
 *   "eventInfo": {
 *     "version": 0,
 *     "SocketNum": 0,
 *     "Architecture": {
 *       "hidFam": 7,
 *       "majorRev": 1,
 *       "chipId": 65,
 *       "minorRev": 1,
 *       "preSiPlatform": { "raw": 0, "value": "Silicon" },
 *       "einjTag": false
 *     },
 *     "Ecid1": 1234567890123456789,
 *     "Ecid2": 9876543210987654321,
 *     "Ecid3": 5555555555555555555,
 *     "Ecid4": 1111111111111111111,
 *     "InstanceBase": 281474976710656
 *   },
 *   "eventContexts": {
 *     "eventContext0": {
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
	json_object_object_add(
		event_header_ir, "version",
		json_object_new_int64(event_header->EventVersion));
	static const char *sourceDeviceType[2] = { "CPU", "GPU" };
	add_dict(event_header_ir, "sourceDeviceType",
		 event_header->SourceDeviceType, sourceDeviceType,
		 sizeof(sourceDeviceType) / sizeof(sourceDeviceType[0]));
	json_object_object_add(event_header_ir, "type",
			       json_object_new_int64(event_header->EventType));
	json_object_object_add(
		event_header_ir, "subtype",
		json_object_new_int64(event_header->EventSubtype));
	if (event_header->EventLinkId != 0) {
		json_object_object_add(
			event_header_ir, "linkId",
			json_object_new_uint64(event_header->EventLinkId));
	}

	// Parse event info structure
	EFI_NVIDIA_EVENT_INFO_HEADER *event_info_header =
		get_event_info_header(event_header);
	json_object *event_info_ir = json_object_new_object();
	json_object_object_add(event_ir, "eventInfo", event_info_ir);
	json_object_object_add(
		event_info_ir, "version",
		json_object_new_int64(event_info_header->InfoVersion));

	// Extract major and minor version from event info header
	UINT8 info_minor = get_info_minor_version(event_info_header);
	UINT8 info_major = get_info_major_version(event_info_header);

	// Call device-specific handler to parse additional event info fields
	for (size_t i = 0;
	     i < sizeof(nv_event_types) / sizeof(nv_event_types[0]); i++) {
		if ((NVIDIA_EVENT_SRC_DEV)event_header->SourceDeviceType ==
		    nv_event_types[i].srcDev) {
			// Check version compatibility
			if (!check_info_major_version(
				    info_major, info_minor,
				    nv_event_types[i].major_version,
				    "parsing")) {
				break;
			}
			nv_event_types[i].callback(event_header, event_info_ir);
			break;
		}
	}
	// Parse all event contexts into an array
	json_object *event_contexts_ir = json_object_new_array();
	json_object_object_add(event_ir, "eventContexts", event_contexts_ir);

	for (size_t i = 0; i < (size_t)event_header->EventContextCount; i++) {
		EFI_NVIDIA_EVENT_CTX_HEADER *ctx =
			get_event_context_n(event_header, i, size);
		if (ctx == NULL) {
			continue;
		}
		// Parse common context header fields
		json_object *event_context_ir = json_object_new_object();
		// Add context to array
		json_object_array_add(event_contexts_ir, event_context_ir);
		json_object_object_add(event_context_ir, "version",
				       json_object_new_int64(ctx->CtxVersion));
		json_object_object_add(
			event_context_ir, "dataFormatType",
			json_object_new_int64(ctx->DataFormatType));
		json_object_object_add(
			event_context_ir, "dataFormatVersion",
			json_object_new_int64(ctx->DataFormatVersion));
		json_object_object_add(event_context_ir, "dataSize",
				       json_object_new_int64(ctx->DataSize));
		json_object *data_ir = json_object_new_object();
		json_object_object_add(event_context_ir, "data", data_ir);
		// Check for device/format-specific custom handler
		bool handler_override_found = false;
		for (size_t handler_idx = 0;
		     handler_idx <
		     sizeof(event_ctx_handlers) / sizeof(event_ctx_handlers[0]);
		     handler_idx++) {
			if (event_ctx_handlers[handler_idx].srcDev ==
				    (NVIDIA_EVENT_SRC_DEV)
					    event_header->SourceDeviceType &&
			    event_ctx_handlers[handler_idx].dataFormatType ==
				    ctx->DataFormatType) {
				if (event_ctx_handlers[handler_idx].callback !=
				    NULL) {
					event_ctx_handlers[handler_idx].callback(
						event_header, size, i, data_ir);
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
		json_object *raw_obj;
		if (json_object_object_get_ex(sourceDeviceType_obj, "raw",
					      &raw_obj)) {
			event_header.SourceDeviceType =
				json_object_get_uint64(raw_obj);
		}
	}

	event_header.Reserved1 = 0;
	event_header.EventType = json_object_get_int64(
		json_object_object_get(event_header_ir, "type"));
	event_header.EventSubtype = json_object_get_int64(
		json_object_object_get(event_header_ir, "subtype"));
	event_header.EventLinkId = json_object_get_uint64(
		json_object_object_get(event_header_ir, "linkId"));

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

	fwrite(&event_header, sizeof(EFI_NVIDIA_EVENT_HEADER), 1, out);

	json_object *event_info_ir =
		json_object_object_get(section, "eventInfo");
	EFI_NVIDIA_EVENT_INFO_HEADER event_info_header = { 0 };
	event_info_header.InfoVersion = json_object_get_int64(
		json_object_object_get(event_info_ir, "version"));

	NV_EVENT_INFO_CALLBACKS *nv_event_info_callback = NULL;
	// Extract major and minor version from event info header
	UINT8 info_minor = get_info_minor_version(&event_info_header);
	UINT8 info_major = get_info_major_version(&event_info_header);
	for (size_t i = 0;
	     i < sizeof(nv_event_types) / sizeof(nv_event_types[0]); i++) {
		NV_EVENT_INFO_CALLBACKS *callback = &nv_event_types[i];
		NVIDIA_EVENT_SRC_DEV srcDev =
			(NVIDIA_EVENT_SRC_DEV)event_header.SourceDeviceType;
		if (srcDev != callback->srcDev) {
			continue;
		}
		// Check version compatibility
		if (!check_info_major_version(info_major, info_minor,
					      callback->major_version,
					      "generation")) {
			break;
		}
		nv_event_info_callback = callback;
		break;
	}
	if (nv_event_info_callback == NULL) {
		return;
	}

	event_info_header.InfoSize = sizeof(EFI_NVIDIA_EVENT_INFO_HEADER) +
				     nv_event_info_callback->info_size;

	size_t bytes_written = fwrite(&event_info_header, 1,
				      sizeof(EFI_NVIDIA_EVENT_INFO_HEADER),
				      out);
	// Call device-specific handler to parse additional event info fields
	bytes_written +=
		nv_event_info_callback->callback_bin(event_info_ir, out);

	write_padding_to_16_byte_alignment(bytes_written, out);

	json_object *event_contexts_ir =
		json_object_object_get(section, "eventContexts");

	// Check if eventContexts field exists before iterating
	if (event_contexts_ir == NULL) {
		cper_print_log(
			"Warning: Missing eventContexts field in Nvidia Event JSON\n");
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
	event_header.EventContextCount = ctx_count;

	for (size_t ctx_instance = 0; ctx_instance < ctx_count;
	     ctx_instance++) {
		json_object *value = NULL;
		if (is_array) {
			value = json_object_array_get_idx(event_contexts_ir,
							  ctx_instance);
		} else {
			// Backward compatibility: get by key name
			char key[64];
			snprintf(key, sizeof(key), "eventContext%zu",
				 ctx_instance);
			value = json_object_object_get(event_contexts_ir, key);
		}
		if (value == NULL) {
			continue;
		}

		EFI_NVIDIA_EVENT_CTX_HEADER ctx = { 0 };
		ctx.CtxVersion = (uint16_t)json_object_get_int64(
			json_object_object_get(value, "version"));
		ctx.DataFormatType = (uint16_t)json_object_get_int64(
			json_object_object_get(value, "dataFormatType"));
		ctx.DataFormatVersion = (uint16_t)json_object_get_int64(
			json_object_object_get(value, "dataFormatVersion"));
		ctx.DataSize = json_object_get_int(
			json_object_object_get(value, "dataSize"));
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
