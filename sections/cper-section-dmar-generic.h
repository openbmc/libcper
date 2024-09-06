#ifndef CPER_SECTION_DMAR_GENERIC_H
#define CPER_SECTION_DMAR_GENERIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include "../edk/Cper.h"

#define DMAR_GENERIC_ERROR_FAULT_REASON_TYPES_KEYS                             \
	(int[])                                                                \
	{                                                                      \
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB          \
	}
#define DMAR_GENERIC_ERROR_FAULT_REASON_TYPES_VALUES                           \
	(const char *[])                                                       \
	{                                                                      \
		"DMT Entry Missing", "DMT Entry Invalid", "DMT Access Error",  \
			"DMT Reserved Bit Invalid",                            \
			"DMA Address Out of Bounds", "Invalid Read/Write",     \
			"Invalid Device Request", "ATT Access Error",          \
			"ATT Reserved Bit Invalid", "Illegal Command",         \
			"Command Buffer Access Error"                          \
	}
#define DMAR_GENERIC_ERROR_FAULT_REASON_TYPES_DESCRIPTIONS                                                   \
	(const char *[])                                                                                     \
	{                                                                                                    \
		"Domain mapping table entry is not present.",                                                \
			"Invalid domain mapping table entry.",                                               \
			"DMAr unit's attempt to access the domain mapping table resulted in an error.",      \
			"Reserved bit set to non-zero value in the domain mapping table.",                   \
			"DMA request to access an address beyond the device address width.",                 \
			"Invalid read or write access.",                                                     \
			"Invalid device request.",                                                           \
			"DMAr unit's attempt to access the address translation table resulted in an error.", \
			"Reserved bit set to non-zero value in the address translation table.",              \
			"Illegal command error.",                                                            \
			"DMAr unit's attempt to access the command buffer resulted in an error."             \
	}
#define DMAR_GENERIC_ERROR_ACCESS_TYPES_KEYS                                   \
	(int[])                                                                \
	{                                                                      \
		0x0, 0x1                                                       \
	}
#define DMAR_GENERIC_ERROR_ACCESS_TYPES_VALUES                                 \
	(const char *[])                                                       \
	{                                                                      \
		"DMA Write", "DMA Read"                                        \
	}
#define DMAR_GENERIC_ERROR_ADDRESS_TYPES_KEYS                                  \
	(int[])                                                                \
	{                                                                      \
		0x0, 0x1                                                       \
	}
#define DMAR_GENERIC_ERROR_ADDRESS_TYPES_VALUES                                \
	(const char *[])                                                       \
	{                                                                      \
		"Untranslated Request", "Translation Request"                  \
	}
#define DMAR_GENERIC_ERROR_ARCH_TYPES_KEYS                                     \
	(int[])                                                                \
	{                                                                      \
		0x0, 0x1                                                       \
	}
#define DMAR_GENERIC_ERROR_ARCH_TYPES_VALUES                                   \
	(const char *[])                                                       \
	{                                                                      \
		"VT-d", "IOMMU"                                                \
	}

json_object *cper_section_dmar_generic_to_ir(void *section);
void ir_section_dmar_generic_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
