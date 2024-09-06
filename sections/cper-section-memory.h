#ifndef CPER_SECTION_MEMORY_H
#define CPER_SECTION_MEMORY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include "../edk/Cper.h"

#define MEMORY_ERROR_VALID_BITFIELD_NAMES                                      \
	(const char *[])                                                       \
	{                                                                      \
		"errorStatusValid", "physicalAddressValid",                    \
			"physicalAddressMaskValid", "nodeValid", "cardValid",  \
			"moduleValid", "bankValid", "deviceValid", "rowValid", \
			"columnValid", "bitPositionValid",                     \
			"platformRequestorIDValid",                            \
			"platformResponderIDValid",                            \
			"memoryPlatformTargetValid", "memoryErrorTypeValid",   \
			"rankNumberValid", "cardHandleValid",                  \
			"moduleHandleValid", "extendedRowBitsValid",           \
			"bankGroupValid", "bankAddressValid",                  \
			"chipIdentificationValid"                              \
	}
#define MEMORY_ERROR_TYPES_KEYS                                                \
	(int[])                                                                \
	{                                                                      \
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15           \
	}
#define MEMORY_ERROR_TYPES_VALUES                                              \
	(const char *[])                                                       \
	{                                                                      \
		"Unknown", "No Error", "Single-bit ECC", "Multi-bit ECC",      \
			"Single-symbol ChipKill ECC",                          \
			"Multi-symbol ChipKill ECC", "Master Abort",           \
			"Target Abort", "Parity Error", "Watchdog Timeout",    \
			"Invalid Address", "Mirror Broken", "Memory Sparing",  \
			"Scrub Corrected Error", "Scrub Uncorrected Error",    \
			"Physical Memory Map-out Event"                        \
	}
#define MEMORY_ERROR_2_VALID_BITFIELD_NAMES                                    \
	(const char *[])                                                       \
	{                                                                      \
		"errorStatusValid", "physicalAddressValid",                    \
			"physicalAddressMaskValid", "nodeValid", "cardValid",  \
			"moduleValid", "bankValid", "deviceValid", "rowValid", \
			"columnValid", "rankValid", "bitPositionValid",        \
			"chipIDValid", "memoryErrorTypeValid", "statusValid",  \
			"requestorIDValid", "responderIDValid",                \
			"targetIDValid", "cardHandleValid",                    \
			"moduleHandleValid", "bankGroupValid",                 \
			"bankAddressValid"                                     \
	}

json_object *cper_section_platform_memory_to_ir(void *section);
json_object *cper_section_platform_memory2_to_ir(void *section);
void ir_section_memory_to_cper(json_object *section, FILE *out);
void ir_section_memory2_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
