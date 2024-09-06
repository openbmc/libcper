#ifndef CPER_SECTION_DMAR_VTD_H
#define CPER_SECTION_DMAR_VTD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include "../edk/Cper.h"

#define VTD_FAULT_RECORD_TYPES_KEYS                                            \
	(int[])                                                                \
	{                                                                      \
		0, 1                                                           \
	}
#define VTD_FAULT_RECORD_TYPES_VALUES                                          \
	(const char *[])                                                       \
	{                                                                      \
		"Write Request", "Read/AtomicOp Request"                       \
	}

typedef struct {
	UINT64 Resv1 : 12;
	UINT64 FaultInformation : 52;
	UINT64 SourceIdentifier : 16;
	UINT64 Resv2 : 13;
	UINT64 PrivelegeModeRequested : 1;
	UINT64 ExecutePermissionRequested : 1;
	UINT64 PasidPresent : 1;
	UINT64 FaultReason : 8;
	UINT64 PasidValue : 20;
	UINT64 AddressType : 2;
	UINT64 Type : 1;
	UINT64 Resv3 : 1;
} EFI_VTD_FAULT_RECORD;

json_object *cper_section_dmar_vtd_to_ir(void *section);
void ir_section_dmar_vtd_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
