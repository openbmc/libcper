// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <libcper/BaseTypes.h>
#include <libcper/Cper.h>
#include <libcper/generator/gen-utils.h>
#include <libcper/generator/sections/gen-section.h>
#include <libcper/sections/cper-section-nvidia-events.h>
#include <libcper/log.h>

// Context data format types
#define NVIDIA_CTX_TYPE_OPAQUE 0x0000
#define NVIDIA_CTX_TYPE_1      0x0001
#define NVIDIA_CTX_TYPE_2      0x0002
#define NVIDIA_CTX_TYPE_3      0x0003
#define NVIDIA_CTX_TYPE_4      0x0004
// GPU-specific context data format types (top bit set per spec)
#define NVIDIA_CTX_TYPE_GPU_LEGACY_XID		0x8001
#define NVIDIA_CTX_TYPE_GPU_RECOMMENDED_ACTIONS 0x8002
#define NVIDIA_CTX_TYPE_GPU_TIMEOUT_DATA	0x9001
#define NVIDIA_CTX_TYPE_GPU_INIT_METADATA	0xA001

static const char signatures[][16 + 1] = {
	"SOCHUB\0\0\0\0\0\0\0\0\0\0",	 "PCIe\0\0\0\0\0\0\0\0\0\0\0\0",
	"L0 RESET\0\0\0\0\0\0\0\0",	 "L1 RESET\0\0\0\0\0\0\0\0",
	"L2 RESET\0\0\0\0\0\0\0\0",	 "RAS-TELEMETRY\0\0\0",
	"MSS\0\0\0\0\0\0\0\0\0\0\0\0\0", "HUB\0\0\0\0\0\0\0\0\0\0\0\0\0",
	"HSM U/I ERROR\0\0\0",		 "HSM\0\0\0\0\0\0\0\0\0\0\0\0\0",
	"HSM_FABRIC\0\0\0\0\0\0",	 "FWERROR\0\0\0\0\0\0\0\0\0",
	"CCPLEXUCF\0\0\0\0\0\0\0",	 "GPU-STATUS\0\0\0\0\0\0",
	"GPU-CONT-GRS\0\0\0\0",
};

// Helper to calculate context data size based on type.
// For GPU Legacy Xid (variable-length Message), num_elements is the total
// data size (4 bytes XidCode + message bytes including terminator).
static size_t get_context_data_size(UINT16 ctx_type, UINT32 num_elements)
{
	switch (ctx_type) {
	case NVIDIA_CTX_TYPE_OPAQUE:
		return num_elements; // num_elements = byte count for opaque
	case NVIDIA_CTX_TYPE_1:
		return num_elements * sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1);
	case NVIDIA_CTX_TYPE_2:
		return num_elements * sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2);
	case NVIDIA_CTX_TYPE_3:
		return num_elements * sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3);
	case NVIDIA_CTX_TYPE_4:
		return num_elements * sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4);
	case NVIDIA_CTX_TYPE_GPU_INIT_METADATA:
		return sizeof(EFI_NVIDIA_GPU_CTX_INIT_METADATA);
	case NVIDIA_CTX_TYPE_GPU_LEGACY_XID:
		return num_elements; // total payload size, 4 <= size <= 240
	case NVIDIA_CTX_TYPE_GPU_RECOMMENDED_ACTIONS:
		return sizeof(EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS);
	case NVIDIA_CTX_TYPE_GPU_TIMEOUT_DATA:
		return num_elements; // total payload size, 16 <= size <= 48
	default:
		return 0;
	}
}

// Fill a CHAR8 buffer with a random printable ASCII string + NUL terminator.
// Always writes at least one NUL so untrusted-string parsers accept it.
static void fill_random_ascii(CHAR8 *buf, size_t buf_len)
{
	if (buf_len == 0) {
		return;
	}
	size_t len = 1 + (cper_rand() % (buf_len - 1 ? buf_len - 1 : 1));
	if (len >= buf_len) {
		len = buf_len - 1;
	}
	for (size_t i = 0; i < len; i++) {
		// Printable ASCII: 0x20..0x7E
		buf[i] = (CHAR8)(0x20 + (cper_rand() % (0x7F - 0x20)));
	}
	buf[len] = '\0';
}

// Helper to fill context data based on type
static void fill_context_data(UINT8 *data, UINT16 ctx_type, UINT32 num_elements)
{
	switch (ctx_type) {
	case NVIDIA_CTX_TYPE_OPAQUE:
		// Fill with random bytes
		for (UINT32 i = 0; i < num_elements; i++) {
			data[i] = (UINT8)(cper_rand() & 0xFF);
		}
		break;
	case NVIDIA_CTX_TYPE_1: {
		EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1 *pairs =
			(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1 *)data;
		for (UINT32 i = 0; i < num_elements; i++) {
			pairs[i].Key = ((UINT64)cper_rand() << 32) |
				       (UINT64)cper_rand();
			pairs[i].Value = ((UINT64)cper_rand() << 32) |
					 (UINT64)cper_rand();
		}
		break;
	}
	case NVIDIA_CTX_TYPE_2: {
		EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2 *pairs =
			(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2 *)data;
		for (UINT32 i = 0; i < num_elements; i++) {
			pairs[i].Key = cper_rand();
			pairs[i].Value = cper_rand();
		}
		break;
	}
	case NVIDIA_CTX_TYPE_3: {
		EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3 *vals =
			(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3 *)data;
		for (UINT32 i = 0; i < num_elements; i++) {
			vals[i].Value = ((UINT64)cper_rand() << 32) |
					(UINT64)cper_rand();
		}
		break;
	}
	case NVIDIA_CTX_TYPE_4: {
		EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4 *vals =
			(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4 *)data;
		for (UINT32 i = 0; i < num_elements; i++) {
			vals[i].Value = cper_rand();
		}
		break;
	}
	case NVIDIA_CTX_TYPE_GPU_INIT_METADATA: {
		EFI_NVIDIA_GPU_CTX_INIT_METADATA *md =
			(EFI_NVIDIA_GPU_CTX_INIT_METADATA *)data;
		fill_random_ascii(md->DeviceName, sizeof(md->DeviceName));
		fill_random_ascii(md->FirmwareVersion,
				  sizeof(md->FirmwareVersion));
		fill_random_ascii(md->PfDriverMicrocodeVersion,
				  sizeof(md->PfDriverMicrocodeVersion));
		fill_random_ascii(md->PfDriverVersion,
				  sizeof(md->PfDriverVersion));
		fill_random_ascii(md->VfDriverVersion,
				  sizeof(md->VfDriverVersion));
		md->Configuration = ((UINT64)cper_rand() << 32) |
				    (UINT64)cper_rand();
		md->Pdi = ((UINT64)cper_rand() << 32) | (UINT64)cper_rand();
		md->ArchitectureId = cper_rand();
		// Randomize HardwareInfoType to also exercise the non-PCI
		// reserved-bytes path: 75% PCI (type 0), 25% non-zero.
		md->HardwareInfoType =
			(cper_rand() % 4 == 0) ?
				(UINT8)(1 + (cper_rand() % 255)) :
				0;
		if (md->HardwareInfoType == 0) {
			md->PciInfo.Class = (UINT8)cper_rand();
			md->PciInfo.Subclass = (UINT8)cper_rand();
			md->PciInfo.Rev = (UINT8)cper_rand();
			md->PciInfo.VendorId = 0x10DE; // NVIDIA
			md->PciInfo.DeviceId = (UINT16)cper_rand();
			md->PciInfo.SubsystemVendorId = (UINT16)cper_rand();
			md->PciInfo.SubsystemId = (UINT16)cper_rand();
			md->PciInfo.Bar0Start = ((UINT64)cper_rand() << 32) |
						(UINT64)cper_rand();
			md->PciInfo.Bar0Size = ((UINT64)cper_rand() << 32) |
					       (UINT64)cper_rand();
			md->PciInfo.Bar1Start = ((UINT64)cper_rand() << 32) |
						(UINT64)cper_rand();
			md->PciInfo.Bar1Size = ((UINT64)cper_rand() << 32) |
					       (UINT64)cper_rand();
			md->PciInfo.Bar2Start = ((UINT64)cper_rand() << 32) |
						(UINT64)cper_rand();
			md->PciInfo.Bar2Size = ((UINT64)cper_rand() << 32) |
					       (UINT64)cper_rand();
		} else {
			// Reserved 59 bytes for future hardware info types.
			UINT8 *reserved = (UINT8 *)&md->PciInfo;
			for (size_t k = 0; k < 59; k++) {
				reserved[k] = (UINT8)(cper_rand() & 0xFF);
			}
		}
		break;
	}
	case NVIDIA_CTX_TYPE_GPU_LEGACY_XID: {
		// Spec layout: UINT32 XidCode at offset 0, CHAR8 Message[N <= 236]
		// follows. num_elements is the total DataSize: 4 + message_len.
		if (num_elements >= 4) {
			EFI_NVIDIA_GPU_CTX_LEGACY_XID *xid =
				(EFI_NVIDIA_GPU_CTX_LEGACY_XID *)data;
			xid->XidCode = cper_rand();
			size_t msg_len = num_elements - 4;
			if (msg_len > sizeof(xid->Message)) {
				msg_len = sizeof(xid->Message);
			}
			fill_random_ascii(xid->Message, msg_len);
		}
		break;
	}
	case NVIDIA_CTX_TYPE_GPU_RECOMMENDED_ACTIONS: {
		EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS *ra =
			(EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS *)data;
		ra->Flags = (UINT8)(cper_rand() & 0x07); // only defined bits
		ra->RecoveryAction =
			(UINT16)(cper_rand() % 7); // stay in defined enum range
		ra->DiagnosticFlow = (UINT16)cper_rand();
		break;
	}
	case NVIDIA_CTX_TYPE_GPU_TIMEOUT_DATA: {
		EFI_NVIDIA_GPU_CTX_TIMEOUT_DATA *timeout =
			(EFI_NVIDIA_GPU_CTX_TIMEOUT_DATA *)data;
		timeout->TimeoutNs = ((UINT64)cper_rand() << 32) |
				     (UINT64)cper_rand();
		timeout->ElapsedNs = ((UINT64)cper_rand() << 32) |
				     (UINT64)cper_rand();
		if (num_elements > sizeof(*timeout)) {
			fill_random_ascii(timeout->WaitTarget,
					  num_elements - sizeof(*timeout));
		}
		break;
	}
	}
}

// Generates a single pseudo-random NVIDIA Events error section
size_t generate_section_nvidia_events(void **location,
				      GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	(void)validBitsType;

	// Select a random signature
	int sig_idx =
		cper_rand() % (sizeof(signatures) / sizeof(signatures[0]));

	// Randomly select device type: 0 = CPU, 1 = GPU
	UINT32 deviceType = cper_rand() % 2;

	// Calculate size needed
	size_t event_header_size = sizeof(EFI_NVIDIA_EVENT_HEADER);
	size_t event_info_header_size = sizeof(EFI_NVIDIA_EVENT_INFO_HEADER);
	size_t event_info_data_size =
		(deviceType == 0) ? sizeof(EFI_NVIDIA_CPU_EVENT_INFO) :
				    sizeof(EFI_NVIDIA_GPU_EVENT_INFO_V2);

	// Decide number of contexts (0-5 for variety)
	UINT32 contextCount = cper_rand() % 6;

	// Generate context configurations.
	// Per spec v0.6: "Context size should always be a multiple of 16 bytes for
	// alignment." CtxSize includes the trailing padding so readers can advance
	// by ptr += CtxSize to reach the next context.
	UINT16 ctx_types[5];
	UINT32 ctx_num_elements[5];
	UINT16 ctx_data_fmt_ver[5] = { 0 };    // per-context DataFormatVersion
	size_t context_data_sizes[5] = { 0 };
	size_t context_total_sizes[5] = { 0 }; // header + data, 16-byte aligned
	size_t total_context_size = 0;

	for (UINT32 i = 0; i < contextCount; i++) {
		// On GPU devices, also generate every currently defined common and
		// category GPU context plus initialization metadata. Event-specific
		// 0xAxxx contexts other than metadata remain opaque until their
		// decoding contract is settled.
		if (deviceType == 1 /* GPU */) {
			static const UINT16 gpu_ctx_types[] = {
				NVIDIA_CTX_TYPE_OPAQUE,
				NVIDIA_CTX_TYPE_1,
				NVIDIA_CTX_TYPE_2,
				NVIDIA_CTX_TYPE_3,
				NVIDIA_CTX_TYPE_4,
				NVIDIA_CTX_TYPE_GPU_LEGACY_XID,
				NVIDIA_CTX_TYPE_GPU_RECOMMENDED_ACTIONS,
				NVIDIA_CTX_TYPE_GPU_TIMEOUT_DATA,
				NVIDIA_CTX_TYPE_GPU_INIT_METADATA,
			};
			ctx_types[i] =
				gpu_ctx_types[cper_rand() %
					      (sizeof(gpu_ctx_types) /
					       sizeof(gpu_ctx_types[0]))];
		} else {
			ctx_types[i] = cper_rand() % 5;
		}

		// Number of elements / payload sizing depends on type.
		switch (ctx_types[i]) {
		case NVIDIA_CTX_TYPE_OPAQUE:
			ctx_num_elements[i] =
				16 + (cper_rand() % 49); // 16-64 bytes
			break;
		case NVIDIA_CTX_TYPE_GPU_INIT_METADATA:
		case NVIDIA_CTX_TYPE_GPU_RECOMMENDED_ACTIONS:
			ctx_num_elements[i] = 1; // fixed-size struct
			break;
		case NVIDIA_CTX_TYPE_GPU_LEGACY_XID:
			// 4 bytes XidCode + 1..236 bytes message (including terminator).
			ctx_num_elements[i] = 4 + 1 + (cper_rand() % 236);
			break;
		case NVIDIA_CTX_TYPE_GPU_TIMEOUT_DATA:
			// Two UINT64 values plus a 1..32-byte NUL-terminated target.
			ctx_num_elements[i] =
				sizeof(EFI_NVIDIA_GPU_CTX_TIMEOUT_DATA) + 1 +
				(cper_rand() % 32);
			break;
		default:
			ctx_num_elements[i] =
				2 + (cper_rand() % 5); // 2-6 elements
			break;
		}

		// Per spec, GPU-specific data formats are Version 1.0 (0x0100).
		// Common formats are Version 0.0.
		ctx_data_fmt_ver[i] = (ctx_types[i] & 0x8000) ? (UINT16)0x0100 :
								(UINT16)0;

		context_data_sizes[i] = get_context_data_size(
			ctx_types[i], ctx_num_elements[i]);

		// Context size = header + data, rounded up to 16-byte
		// alignment so the reader can advance with ptr += CtxSize
		size_t raw_size = sizeof(EFI_NVIDIA_EVENT_CTX_HEADER) +
				  context_data_sizes[i];
		context_total_sizes[i] = (raw_size + 15) & ~(size_t)15;
		total_context_size += context_total_sizes[i];
	}

	// Total section size
	size_t total_size = event_header_size + event_info_header_size +
			    event_info_data_size + total_context_size;

	// Allocate section
	UINT8 *section = (UINT8 *)calloc(1, total_size);
	if (!section) {
		return 0;
	}

	UINT8 *current = section;

	// Fill Event Header
	EFI_NVIDIA_EVENT_HEADER *event_header =
		(EFI_NVIDIA_EVENT_HEADER *)current;

	memcpy(event_header->Signature, signatures[sig_idx],
	       sizeof(event_header->Signature));

	event_header->EventVersion = 1;
	event_header->EventContextCount = contextCount;
	event_header->SourceDeviceType = deviceType;
	event_header->Reserved1 = 0;
	event_header->EventType = cper_rand() % 256;
	event_header->EventSubtype = cper_rand() % 256;
	event_header->EventTraceId = ((UINT64)cper_rand() << 32) |
				     (UINT64)cper_rand();

	current += event_header_size;

	// Fill Event Info Header
	EFI_NVIDIA_EVENT_INFO_HEADER *event_info_header =
		(EFI_NVIDIA_EVENT_INFO_HEADER *)current;

	if (deviceType == 0) {
		// CPU: version 0.0
		event_info_header->InfoVersion =
			(EFI_NVIDIA_CPU_EVENT_INFO_MAJ << 8) |
			EFI_NVIDIA_CPU_EVENT_INFO_MIN;
	} else {
		// GPU: generate the current version 2.0 layout.
		event_info_header->InfoVersion =
			(EFI_NVIDIA_GPU_EVENT_INFO_V2_MAJ << 8) |
			EFI_NVIDIA_GPU_EVENT_INFO_V2_MIN;
	}
	// InfoSize = header size + device-specific info size
	event_info_header->InfoSize =
		(UINT8)(event_info_header_size + event_info_data_size);

	cper_print_log("InfoSize: %d", event_info_header->InfoSize);

	current += event_info_header_size;

	// Fill Event Info based on device type
	if (deviceType == 0) {
		// CPU Event Info
		EFI_NVIDIA_CPU_EVENT_INFO *cpu_info =
			(EFI_NVIDIA_CPU_EVENT_INFO *)current;
		cpu_info->SocketNum = cper_rand() % 8;
		cpu_info->Architecture.HidFam = cper_rand();
		cpu_info->Architecture.MajorRev = cper_rand();
		cpu_info->Architecture.ChipId = cper_rand();
		cpu_info->Architecture.MinorRev = cper_rand();
		// The IR records preSiPlatform only as Silicon/PreSilicon, so
		// just the zero/non-zero state survives a round trip.
		cpu_info->Architecture.PreSiPlatform = cper_rand() & 0x1;
		cpu_info->Architecture.ErrorInjection = cper_rand() & 0x1;
		// Reserved bits are left zero by the calloc above.
		cpu_info->Ecid[0] = cper_rand();
		cpu_info->Ecid[1] = cper_rand();
		cpu_info->Ecid[2] = cper_rand();
		cpu_info->Ecid[3] = cper_rand();
		cpu_info->InstanceBase = ((UINT64)cper_rand() << 32) |
					 (UINT64)cper_rand();
	} else {
		// GPU Event Info v2.0 layout.
		EFI_NVIDIA_GPU_EVENT_INFO_V2 *gpu_info =
			(EFI_NVIDIA_GPU_EVENT_INFO_V2 *)current;
		static const UINT8 gpu_originators[] = { 0, 2, 3, 4, 5 };
		gpu_info->EventOriginator =
			gpu_originators[cper_rand() %
					(sizeof(gpu_originators) /
					 sizeof(gpu_originators[0]))];
		gpu_info->ModuleInstance = (UINT8)(cper_rand() % 16);
		gpu_info->ChipletId = (UINT8)(cper_rand() % 4);
		// MIG attribution: ~25% of the time set to 0xFF (N/A), otherwise
		// (gpu_instance << 4) | compute_instance with small values so the
		// schema's "%u:%u" pattern matches comfortably.
		if ((cper_rand() % 4) == 0) {
			gpu_info->MigAttribution = 0xFF;
		} else {
			gpu_info->MigAttribution =
				(UINT8)(((cper_rand() % 8) << 4) |
					(cper_rand() % 8));
		}
		gpu_info->EventScope = (UINT8)(cper_rand() % 8);
		gpu_info->Pdi = ((UINT64)cper_rand() << 32) |
				(UINT64)cper_rand();
	}

	current += event_info_data_size;

	// Fill Event Contexts with various types
	for (UINT32 i = 0; i < contextCount; i++) {
		EFI_NVIDIA_EVENT_CTX_HEADER *ctx_header =
			(EFI_NVIDIA_EVENT_CTX_HEADER *)current;

		// CtxSize includes the 16-byte alignment padding
		ctx_header->CtxSize = (UINT32)context_total_sizes[i];
		ctx_header->CtxVersion = 0;
		ctx_header->Reserved1 = 0;
		ctx_header->DataFormatType = ctx_types[i];
		ctx_header->DataFormatVersion = ctx_data_fmt_ver[i];
		ctx_header->DataSize = (UINT32)context_data_sizes[i];

		current += sizeof(EFI_NVIDIA_EVENT_CTX_HEADER);

		// Fill context data based on type
		fill_context_data(current, ctx_types[i], ctx_num_elements[i]);

		// Skip past data plus zeroed (calloc) alignment padding
		current += context_total_sizes[i] -
			   sizeof(EFI_NVIDIA_EVENT_CTX_HEADER);
	}

	// Set return values
	*location = section;
	return total_size;
}
