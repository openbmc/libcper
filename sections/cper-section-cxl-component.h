#ifndef CPER_SECTION_CXL_COMPONENT_H
#define CPER_SECTION_CXL_COMPONENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include "../edk/Cper.h"

#define CXL_COMPONENT_ERROR_VALID_BITFIELD_NAMES                               \
	(const char *[])                                                       \
	{                                                                      \
		"deviceIDValid", "deviceSerialValid",                          \
			"cxlComponentEventLogValid"                            \
	}

///
/// CXL Generic Component Error Section
///
typedef struct {
	UINT64 VendorId : 16;
	UINT64 DeviceId : 16;
	UINT64 FunctionNumber : 8;
	UINT64 DeviceNumber : 8;
	UINT64 BusNumber : 8;
	UINT64 SegmentNumber : 16;
	UINT64 Resv1 : 3;
	UINT64 SlotNumber : 13;
	UINT64 Resv2 : 8;
} __attribute__((packed, aligned(1))) EFI_CXL_DEVICE_ID_INFO;

typedef struct {
	UINT32 Length;
	UINT64 ValidBits;
	EFI_CXL_DEVICE_ID_INFO DeviceId;
	UINT64 DeviceSerial;
} __attribute__((packed, aligned(1))) EFI_CXL_COMPONENT_EVENT_HEADER;

json_object *cper_section_cxl_component_to_ir(void *section);
void ir_section_cxl_component_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
