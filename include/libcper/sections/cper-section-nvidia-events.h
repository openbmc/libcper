// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#ifndef CPER_SECTION_NVIDIA_EVENTS_H
#define CPER_SECTION_NVIDIA_EVENTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <json.h>
#include <libcper/Cper.h>

// Event Header version (treated as major version)
#define EFI_NVIDIA_EVENT_HEADER_VERSION 1

typedef struct __attribute__((packed)) {
	CHAR8 EventVersion;
	CHAR8 EventContextCount;
	CHAR8 SourceDeviceType;
	CHAR8 Reserved1;
	UINT16 EventType;
	UINT16 EventSubtype;
	UINT64 EventLinkId;
	CHAR8 Signature[16];
} EFI_NVIDIA_EVENT_HEADER;

typedef struct __attribute__((packed)) {
	UINT16 InfoVersion;
	UINT8 InfoSize;
} EFI_NVIDIA_EVENT_INFO_HEADER;

// CPU Event Info structure version
#define EFI_NVIDIA_CPU_EVENT_INFO_MAJ 0
#define EFI_NVIDIA_CPU_EVENT_INFO_MIN 0

typedef struct __attribute__((packed)) {
	UINT8 SocketNum;
	UINT32 Architecture;
	UINT32 Ecid[4];
	UINT64 InstanceBase;
} EFI_NVIDIA_CPU_EVENT_INFO;

// GPU Event Info structure version
#define EFI_NVIDIA_GPU_EVENT_INFO_MAJ 1
#define EFI_NVIDIA_GPU_EVENT_INFO_MIN 0

typedef struct __attribute__((packed)) {
	UINT8 EventOriginator;
	UINT16 SourcePartition;
	UINT16 SourceSubPartition;
	UINT64 Pdi;
} EFI_NVIDIA_GPU_EVENT_INFO;

typedef struct __attribute__((packed)) {
	UINT32 CtxSize;
	UINT16 CtxVersion;
	UINT16 Reserved1;
	UINT16 DataFormatType;
	UINT16 DataFormatVersion;
	UINT32 DataSize;
	UINT8 Data[0];
} EFI_NVIDIA_EVENT_CTX_HEADER;

typedef struct __attribute__((packed)) {
	UINT64 Key;
	UINT64 Value;
} EFI_NVIDIA_EVENT_CTX_DATA_TYPE_1;

typedef struct __attribute__((packed)) {
	UINT32 Key;
	UINT32 Value;
} EFI_NVIDIA_EVENT_CTX_DATA_TYPE_2;

typedef struct __attribute__((packed)) {
	UINT64 Value;
} EFI_NVIDIA_EVENT_CTX_DATA_TYPE_3;

typedef struct __attribute__((packed)) {
	UINT32 Value;
} EFI_NVIDIA_EVENT_CTX_DATA_TYPE_4;

typedef struct __attribute__((packed)) {
	UINT8 Class;
	UINT8 Subclass;
	UINT8 Rev;
	UINT16 VendorId;
	UINT16 DeviceId;
	UINT16 SubsystemVendorId;
	UINT16 SubsystemId;
	UINT64 Bar0Start;
	UINT64 Bar0Size;
	UINT64 Bar1Start;
	UINT64 Bar1Size;
	UINT64 Bar2Start;
	UINT64 Bar2Size;
} EFI_NVIDIA_GPU_CTX_METADATA_PCI_INFO;

typedef struct __attribute__((packed)) {
	CHAR8 DeviceName[48];
	CHAR8 FirmwareVersion[16];
	CHAR8 PfDriverMicrocodeVersion[16];
	CHAR8 PfDriverVersion[16];
	CHAR8 VfDriverVersion[16];
	UINT64 Configuration;
	UINT64 Pdi;
	UINT32 ArchitectureId;
	UINT8 HardwareInfoType;
	union {
		EFI_NVIDIA_GPU_CTX_METADATA_PCI_INFO PciInfo;
		UINT8 Reserved[59];
	};
} EFI_NVIDIA_GPU_CTX_METADATA;

typedef struct __attribute__((packed)) {
	UINT32 XidCode;
	CHAR8 Message[236];
} EFI_NVIDIA_GPU_CTX_LEGACY_XID;

typedef struct __attribute__((packed)) {
	UINT8 Flags;
	UINT8 Reserved1[3];
	UINT16 RecoveryAction;
	UINT16 DiagnosticFlow;
	UINT64 Reserved2; // Padding to 16-byte alignment
} EFI_NVIDIA_GPU_CTX_RECOMMENDED_ACTIONS;

extern EFI_GUID gEfiNvidiaEventErrorSectionGuid;

json_object *cper_section_nvidia_events_to_ir(const UINT8 *section, UINT32 size,
					      char **desc_string);
void ir_section_nvidia_events_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
