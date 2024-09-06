#ifndef CPER_SECTION_CXL_PROTOCOL_H
#define CPER_SECTION_CXL_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include "../edk/Cper.h"

#define CXL_PROTOCOL_ERROR_VALID_BITFIELD_NAMES                                \
	(const char *[])                                                       \
	{                                                                      \
		"cxlAgentTypeValid", "cxlAgentAddressValid", "deviceIDValid",  \
			"deviceSerialValid", "capabilityStructureValid",       \
			"cxlDVSECValid", "cxlErrorLogValid"                    \
	}
#define CXL_PROTOCOL_ERROR_AGENT_TYPES_KEYS                                    \
	(int[])                                                                \
	{                                                                      \
		0, 1                                                           \
	}
#define CXL_PROTOCOL_ERROR_AGENT_TYPES_VALUES                                  \
	(const char *[])                                                       \
	{                                                                      \
		"CXL 1.1 Device", "CXL 1.1 Host Downstream Port"               \
	}
#define CXL_PROTOCOL_ERROR_DEVICE_AGENT		      0
#define CXL_PROTOCOL_ERROR_HOST_DOWNSTREAM_PORT_AGENT 1

///
/// CXL Protocol Error Section
///
typedef struct {
	UINT64 VendorId : 16;
	UINT64 DeviceId : 16;
	UINT64 SubsystemVendorId : 16;
	UINT64 SubsystemDeviceId : 16;
	UINT64 ClassCode : 16;
	UINT64 Reserved1 : 3;
	UINT64 SlotNumber : 13;
	UINT64 Reserved2 : 32;
} EFI_CXL_DEVICE_ID;

typedef struct {
	UINT64 FunctionNumber : 8;
	UINT64 DeviceNumber : 8;
	UINT64 BusNumber : 8;
	UINT64 SegmentNumber : 16;
	UINT64 Reserved : 24;
} EFI_CXL_DEVICE_AGENT_ADDRESS;

typedef union {
	EFI_CXL_DEVICE_AGENT_ADDRESS
	DeviceAddress; //Active when the agent is a CXL1.1 device in CxlAgentType.
	UINT64 PortRcrbBaseAddress; //Active when the agent is a CXL1.1 host downstream port in CxlAgentType.
} EFI_CXL_AGENT_ADDRESS;

typedef struct {
	UINT64 ValidBits;
	UINT64 CxlAgentType;
	EFI_CXL_AGENT_ADDRESS CxlAgentAddress;
	EFI_CXL_DEVICE_ID DeviceId;
	UINT64 DeviceSerial;
	EFI_PCIE_ERROR_DATA_CAPABILITY CapabilityStructure;
	UINT16 CxlDvsecLength;
	UINT16 CxlErrorLogLength;
	UINT32 Reserved;
} __attribute__((packed, aligned(1))) EFI_CXL_PROTOCOL_ERROR_DATA;

json_object *cper_section_cxl_protocol_to_ir(void *section);
void ir_section_cxl_protocol_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
