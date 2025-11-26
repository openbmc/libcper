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

// Context data format types
#define NVIDIA_CTX_TYPE_OPAQUE 0x0000
#define NVIDIA_CTX_TYPE_1      0x0001
#define NVIDIA_CTX_TYPE_2      0x0002
#define NVIDIA_CTX_TYPE_3      0x0003
#define NVIDIA_CTX_TYPE_4      0x0004

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

// Helper to calculate context data size based on type
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
	default:
		return 0;
	}
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
				    sizeof(EFI_NVIDIA_GPU_EVENT_INFO);

	// Decide number of contexts (0-5 for variety)
	UINT32 contextCount = cper_rand() % 6;

	// Generate context configurations
	UINT16 ctx_types[5];
	UINT32 ctx_num_elements[5];
	size_t context_data_sizes[5] = { 0 };
	size_t context_total_sizes[5] = { 0 }; // header + data (no padding)
	size_t total_context_size = 0;

	for (UINT32 i = 0; i < contextCount; i++) {
		// Randomly select context type (0-4)
		ctx_types[i] = cper_rand() % 5;

		// Number of elements (2-6 for structured, 16-64 bytes for opaque)
		if (ctx_types[i] == NVIDIA_CTX_TYPE_OPAQUE) {
			ctx_num_elements[i] =
				16 + (cper_rand() % 49); // 16-64 bytes
		} else {
			ctx_num_elements[i] =
				2 + (cper_rand() % 5); // 2-6 elements
		}

		context_data_sizes[i] = get_context_data_size(
			ctx_types[i], ctx_num_elements[i]);

		// Context size = header + data (no padding between contexts)
		context_total_sizes[i] = sizeof(EFI_NVIDIA_EVENT_CTX_HEADER) +
					 context_data_sizes[i];
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
	event_header->EventLinkId = ((UINT64)cper_rand() << 32) |
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
		// GPU: version 1.0
		event_info_header->InfoVersion =
			(EFI_NVIDIA_GPU_EVENT_INFO_MAJ << 8) |
			EFI_NVIDIA_GPU_EVENT_INFO_MIN;
	}
	// InfoSize = header size + device-specific info size
	event_info_header->InfoSize =
		(UINT8)(event_info_header_size + event_info_data_size);

	current += event_info_header_size;

	// Fill Event Info based on device type
	if (deviceType == 0) {
		// CPU Event Info
		EFI_NVIDIA_CPU_EVENT_INFO *cpu_info =
			(EFI_NVIDIA_CPU_EVENT_INFO *)current;
		cpu_info->SocketNum = cper_rand() % 8;
		cpu_info->Architecture = cper_rand();
		cpu_info->Ecid[0] = cper_rand();
		cpu_info->Ecid[1] = cper_rand();
		cpu_info->Ecid[2] = cper_rand();
		cpu_info->Ecid[3] = cper_rand();
		cpu_info->InstanceBase = ((UINT64)cper_rand() << 32) |
					 (UINT64)cper_rand();
	} else {
		// GPU Event Info
		EFI_NVIDIA_GPU_EVENT_INFO *gpu_info =
			(EFI_NVIDIA_GPU_EVENT_INFO *)current;
		gpu_info->EventOriginator = cper_rand() % 4;
		gpu_info->SourcePartition = cper_rand() % 16;
		gpu_info->SourceSubPartition = cper_rand() % 8;
		gpu_info->Pdi = ((UINT64)cper_rand() << 32) |
				(UINT64)cper_rand();
	}

	current += event_info_data_size;

	// Fill Event Contexts with various types
	for (UINT32 i = 0; i < contextCount; i++) {
		EFI_NVIDIA_EVENT_CTX_HEADER *ctx_header =
			(EFI_NVIDIA_EVENT_CTX_HEADER *)current;

		// CtxSize = header + data (NOT including padding)
		size_t ctx_size = sizeof(EFI_NVIDIA_EVENT_CTX_HEADER) +
				  context_data_sizes[i];

		ctx_header->CtxSize = (UINT32)ctx_size;
		ctx_header->CtxVersion = 0;
		ctx_header->Reserved1 = 0;
		ctx_header->DataFormatType = ctx_types[i];
		ctx_header->DataFormatVersion = 0;
		ctx_header->DataSize = (UINT32)context_data_sizes[i];

		current += sizeof(EFI_NVIDIA_EVENT_CTX_HEADER);

		// Fill context data based on type
		fill_context_data(current, ctx_types[i], ctx_num_elements[i]);

		current += context_data_sizes[i];
	}

	// Set return values
	*location = section;
	return total_size;
}
