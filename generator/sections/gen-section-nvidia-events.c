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

// Generates a single pseudo-random NVIDIA Events error section using the
// Nvidia Event model.
size_t generate_section_nvidia_events(void **location,
				      GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	(void)validBitsType;

	// Fixed dummy signature to avoid using real signatures
	const char *signature = "DEV-XYZ";

	UINT32 deviceType = 0; // 0 = CPU

	// Calculate size needed (CPU-only)
	size_t event_header_size = sizeof(EFI_NVIDIA_EVENT_HEADER);
	size_t event_info_header_size = sizeof(EFI_NVIDIA_EVENT_INFO_HEADER);
	size_t event_info_size = sizeof(EFI_NVIDIA_CPU_EVENT_INFO);

	// Decide number of contexts (0-2 for variety)
	UINT32 contextCount = cper_rand() % 3;

	// Calculate context sizes (we'll generate TYPE_1 contexts for simplicity)
	size_t context_sizes[2] = { 0, 0 };
	size_t total_context_size = 0;

	for (UINT32 i = 0; i < contextCount; i++) {
		UINT32 numPairs = 2 + (cper_rand() % 3); // 2-4 key-value pairs
		size_t data_size =
			numPairs * sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1);
		context_sizes[i] =
			sizeof(EFI_NVIDIA_EVENT_CTX_HEADER) + data_size;
		total_context_size += context_sizes[i];
	}

	// Total section size
	size_t total_size = event_header_size + event_info_header_size +
			    event_info_size + total_context_size;

	// Allocate section
	UINT8 *section = (UINT8 *)calloc(1, total_size);
	if (!section) {
		return 0;
	}

	UINT8 *current = section;

	// Fill Event Header
	EFI_NVIDIA_EVENT_HEADER *event_header =
		(EFI_NVIDIA_EVENT_HEADER *)current;

	strncpy(event_header->Signature, signature,
		sizeof(event_header->Signature) - 1);
	event_header->Signature[sizeof(event_header->Signature) - 1] = '\0';

	event_header->EventVersion = 1;
	event_header->EventContextCount = contextCount;
	event_header->SourceDeviceType = deviceType;
	event_header->Reserved1 = 0;
	event_header->EventType = cper_rand() % 256;
	event_header->EventSubtype = cper_rand() % 256;
	event_header->EventLinkId = (UINT64)cper_rand() << 32 |
				    (UINT64)cper_rand();

	current += event_header_size;

	// Fill Event Info Header
	EFI_NVIDIA_EVENT_INFO_HEADER *event_info_header =
		(EFI_NVIDIA_EVENT_INFO_HEADER *)current;
	event_info_header->InfoVersion = 0;
	event_info_header->InfoSize = (UINT8)event_info_size;

	current += event_info_header_size;

	// Fill Event Info (CPU-only)
	EFI_NVIDIA_CPU_EVENT_INFO *cpu_info =
		(EFI_NVIDIA_CPU_EVENT_INFO *)current;

	cpu_info->SocketNum = cper_rand() % 8;
	cpu_info->Architecture = cper_rand();
	cpu_info->Ecid[0] = cper_rand();
	cpu_info->Ecid[1] = cper_rand();
	cpu_info->Ecid[2] = cper_rand();
	cpu_info->Ecid[3] = cper_rand();
	cpu_info->InstanceBase = (UINT64)cper_rand() << 32 |
				 (UINT64)cper_rand();

	current += event_info_size;

	// Fill Event Contexts (TYPE_1 for simplicity)
	for (UINT32 i = 0; i < contextCount; i++) {
		EFI_NVIDIA_EVENT_CTX_HEADER *ctx_header =
			(EFI_NVIDIA_EVENT_CTX_HEADER *)current;

		UINT32 data_size =
			context_sizes[i] - sizeof(EFI_NVIDIA_EVENT_CTX_HEADER);
		UINT32 numPairs =
			data_size / sizeof(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1);

		ctx_header->CtxSize = (UINT32)context_sizes[i];
		ctx_header->CtxVersion = 0;
		ctx_header->Reserved1 = 0;
		ctx_header->DataFormatType = NVIDIA_CTX_TYPE_1;
		ctx_header->DataFormatVersion = 0;
		ctx_header->DataSize = data_size;

		current += sizeof(EFI_NVIDIA_EVENT_CTX_HEADER);

		// Fill TYPE_1 data (array of key-value pairs)
		EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1 *type1_pairs =
			(EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1 *)current;

		for (UINT32 j = 0; j < numPairs; j++) {
			type1_pairs[j].Key = (UINT64)cper_rand() << 32 |
					     (UINT64)cper_rand();
			type1_pairs[j].Value = (UINT64)cper_rand() << 32 |
					       (UINT64)cper_rand();
		}

		current += data_size;
	}

	// Set return values
	*location = section;
	return total_size;
}
