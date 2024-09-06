#ifndef CPER_SECTION_PCI_DEV_H
#define CPER_SECTION_PCI_DEV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include "../edk/Cper.h"

#define PCI_DEV_ERROR_VALID_BITFIELD_NAMES                                     \
	(const char *[])                                                       \
	{                                                                      \
		"errorStatusValid", "idInfoValid", "memoryNumberValid",        \
			"ioNumberValid", "registerDataPairsValid"              \
	}

///
/// PCI/PCI-X Device Error Section
///
typedef struct {
	UINT64 VendorId : 16;
	UINT64 DeviceId : 16;
	UINT64 ClassCode : 24;
	UINT64 FunctionNumber : 8;
	UINT64 DeviceNumber : 8;
	UINT64 BusNumber : 8;
	UINT64 SegmentNumber : 8;
	UINT64 Reserved : 40;
} EFI_PCI_PCIX_DEVICE_ID_INFO;

typedef struct {
	UINT64 ValidFields;
	EFI_GENERIC_ERROR_STATUS ErrorStatus;
	EFI_PCI_PCIX_DEVICE_ID_INFO IdInfo;
	UINT32 MemoryNumber;
	UINT32 IoNumber;
} __attribute__((packed, aligned(1))) EFI_PCI_PCIX_DEVICE_ERROR_DATA;

json_object *cper_section_pci_dev_to_ir(void *section);
void ir_section_pci_dev_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
