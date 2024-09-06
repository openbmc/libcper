#ifndef CPER_SECTION_GENERIC_H
#define CPER_SECTION_GENERIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include "../edk/Cper.h"

#define GENERIC_PROC_TYPES_KEYS                                                \
	(int[])                                                                \
	{                                                                      \
		0, 1, 2                                                        \
	}
#define GENERIC_PROC_TYPES_VALUES                                              \
	(const char *[])                                                       \
	{                                                                      \
		"IA32/X64", "IA64", "ARM"                                      \
	}
#define GENERIC_ISA_TYPES_KEYS                                                 \
	(int[])                                                                \
	{                                                                      \
		0, 1, 2, 3, 4                                                  \
	}
#define GENERIC_ISA_TYPES_VALUES                                               \
	(const char *[])                                                       \
	{                                                                      \
		"IA32", "IA64", "X64", "ARM A32/T32", "ARM A64"                \
	}
#define GENERIC_ERROR_TYPES_KEYS                                               \
	(int[])                                                                \
	{                                                                      \
		0, 1, 2, 4, 8                                                  \
	}
#define GENERIC_ERROR_TYPES_VALUES                                             \
	(const char *[])                                                       \
	{                                                                      \
		"Unknown", "Cache Error", "TLB Error", "Bus Error",            \
			"Micro-Architectural Error"                            \
	}
#define GENERIC_OPERATION_TYPES_KEYS                                           \
	(int[])                                                                \
	{                                                                      \
		0, 1, 2, 3                                                     \
	}
#define GENERIC_OPERATION_TYPES_VALUES                                         \
	(const char *[])                                                       \
	{                                                                      \
		"Unknown or Generic", "Data Read", "Data Write",               \
			"Instruction Execution"                                \
	}
#define GENERIC_VALIDATION_BITFIELD_NAMES                                      \
	(const char *[])                                                       \
	{                                                                      \
		"processorTypeValid", "processorISAValid",                     \
			"processorErrorTypeValid", "operationValid",           \
			"flagsValid", "levelValid", "cpuVersionValid",         \
			"cpuBrandInfoValid", "cpuIDValid",                     \
			"targetAddressValid", "requestorIDValid",              \
			"responderIDValid", "instructionIPValid"               \
	}
#define GENERIC_FLAGS_BITFIELD_NAMES                                           \
	(const char *[])                                                       \
	{                                                                      \
		"restartable", "preciseIP", "overflow", "corrected"            \
	}

json_object *cper_section_generic_to_ir(void *section);
void ir_section_generic_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
