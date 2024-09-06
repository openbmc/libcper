#ifndef CPER_SECTION_IPF_H
#define CPER_SECTION_IPF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include "../edk/Cper.h"

#define IPF_MOD_ERROR_VALID_BITFIELD_NAMES                                     \
	(const char *[])                                                       \
	{                                                                      \
		"checkInfoValid", "requestorIdentifierValid",                  \
			"responderIdentifierValid", "targetIdentifierValid",   \
			"preciseIPValid"                                       \
	}
#define IPF_PSI_STATIC_INFO_VALID_BITFIELD_NAMES                               \
	(const char *[])                                                       \
	{                                                                      \
		"minstateValid", "brValid", "crValid", "arValid", "rrValid",   \
			"frValid"                                              \
	}

///
/// IPF Error Record Section
/// Defined as according to B.2.3 of the ItaniumTM Processor Family System Abstraction Layer (SAL) Specification.
///
typedef struct {
	UINT64 ProcErrorMapValid : 1;
	UINT64 ProcStateParameterValid : 1;
	UINT64 ProcCrLidValid : 1;
	UINT64 PsiStaticStructValid : 1;
	UINT64 CacheCheckNum : 4;
	UINT64 TlbCheckNum : 4;
	UINT64 BusCheckNum : 4;
	UINT64 RegFileCheckNum : 4;
	UINT64 MsCheckNum : 4;
	UINT64 CpuIdInfoValid : 1;
	UINT64 Reserved : 39;
} EPI_IPF_ERROR_VALID_BITS;

typedef struct {
	EPI_IPF_ERROR_VALID_BITS ValidBits;
	UINT64 ProcErrorMap;
	UINT64 ProcStateParameter;
	UINT64 ProcCrLid;
} EFI_IPF_ERROR_INFO_HEADER;

typedef struct {
	UINT64 ValidBits;
	UINT64 ModCheckInfo;
	UINT64 ModTargetId;
	UINT64 ModRequestorId; //NOTE: The Intel Itanium specification contains a typo which makes the order
	UINT64 ModResponderId; // of these two fields undefined. This is a best guess and could be wrong.
	UINT64 ModPreciseIp;
} EFI_IPF_MOD_ERROR_INFO;

typedef struct {
	UINT8 CpuIdInfo[40];
	UINT8 Reserved1[8];
} EFI_IPF_CPU_INFO;

typedef struct {
	UINT64 ValidBits;
	UINT8 MinimalSaveStateInfo[1024];
	UINT64 Brs[8];
	UINT64 Crs[128];
	UINT64 Ars[128];
	UINT64 Rrs[8];
	UINT64 Frs[256];
} EFI_IPF_PSI_STATIC;

json_object *cper_section_ipf_to_ir(void *section);

#ifdef __cplusplus
}
#endif

#endif
