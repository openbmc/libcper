#ifndef CPER_SECTION_ARM_H
#define CPER_SECTION_ARM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <json.h>
#include <libcper/Cper.h>

#define ARM_SOCK_MASK 0xFF00000000

#define ARM_ERROR_VALID_BITFIELD_NAMES                                         \
	(const char *[]){ "mpidrValid", "errorAffinityLevelValid",             \
			  "runningStateValid", "vendorSpecificInfoValid" }
#define ARM_ERROR_INFO_ENTRY_VALID_BITFIELD_NAMES                              \
	(const char *[]){ "multipleErrorValid", "flagsValid",                  \
			  "errorInformationValid", "virtualFaultAddressValid", \
			  "physicalFaultAddressValid" }
#define ARM_ERROR_INFO_ENTRY_FLAGS_NAMES                                       \
	(const char *[]){ "firstErrorCaptured", "lastErrorCaptured",           \
			  "propagated", "overflow" }
#define ARM_CACHE_TLB_ERROR_VALID_BITFIELD_NAMES                               \
	(const char *[]){                                                      \
		"transactionTypeValid", "operationValid",                      \
		"levelValid",		"processorContextCorruptValid",        \
		"correctedValid",	"precisePCValid",                      \
		"restartablePCValid"                                           \
	}
#define ARM_BUS_ERROR_VALID_BITFIELD_NAMES                                     \
	(const char *[]){ "transactionTypeValid",                              \
			  "operationValid",                                    \
			  "levelValid",                                        \
			  "processorContextCorruptValid",                      \
			  "correctedValid",                                    \
			  "precisePCValid",                                    \
			  "restartablePCValid",                                \
			  "participationTypeValid",                            \
			  "timedOutValid",                                     \
			  "addressSpaceValid",                                 \
			  "memoryAttributesValid",                             \
			  "accessModeValid" }
#define ARM_ERROR_TRANSACTION_TYPES_KEYS (int[]){ 0, 1, 2 }
#define ARM_ERROR_TRANSACTION_TYPES_VALUES                                     \
	(const char *[]){ "Instruction", "Data Access", "Generic" }
#define ARM_ERROR_INFO_ENTRY_INFO_TYPES_KEYS (int[]){ 1, 2, 4, 8 }
#define ARM_ERROR_INFO_ENTRY_INFO_TYPES_VALUES                                 \
	(const char *[]){ "Cache Error", "TLB Error", "Bus Error",             \
			  "Micro-Architectural Error" }
#define ARM_CACHE_BUS_OPERATION_TYPES_KEYS                                     \
	(int[]){ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }
#define ARM_CACHE_BUS_OPERATION_TYPES_VALUES                                    \
	(const char *[]){ "Generic Error", "Generic Read", "Generic Write",     \
			  "Data Read",	   "Data Write",   "Instruction Fetch", \
			  "Prefetch",	   "Eviction",	   "Snooping",          \
			  "Snooped",	   "Management" }
#define ARM_TLB_OPERATION_TYPES_KEYS (int[]){ 0, 1, 2, 3, 4, 5, 6, 7, 8 }
#define ARM_TLB_OPERATION_TYPES_VALUES                                         \
	(const char *[]){ "Generic Error",                                     \
			  "Generic Read",                                      \
			  "Generic Write",                                     \
			  "Data Read",                                         \
			  "Data Write",                                        \
			  "Instruction Fetch",                                 \
			  "Prefetch",                                          \
			  "Local Management Operation",                        \
			  "External Management Operation" }
#define ARM_BUS_PARTICIPATION_TYPES_KEYS (int[]){ 0, 1, 2, 3 }
#define ARM_BUS_PARTICIPATION_TYPES_VALUES                                     \
	(const char *[]){ "Local Processor Originated Request",                \
			  "Local Processor Responded to Request",              \
			  "Local Processor Observed", "Generic" }
#define ARM_BUS_ADDRESS_SPACE_TYPES_KEYS (int[]){ 0, 1, 3 }
#define ARM_BUS_ADDRESS_SPACE_TYPES_VALUES                                     \
	(const char *[]){ "External Memory Access", "Internal Memory Access",  \
			  "Device Memory Access" }
#define ARM_PROCESSOR_INFO_REGISTER_CONTEXT_TYPES_KEYS                         \
	(int[]){ 0, 1, 2, 3, 4, 5, 6, 7, 8 }

#define ARM_PROCESSOR_INFO_REGISTER_CONTEXT_TYPES_VALUES                       \
	(const char *[]){ "AArch32 General Purpose Registers",                 \
			  "AArch32 EL1 Context Registers",                     \
			  "AArch32 EL2 Context Registers",                     \
			  "AArch32 Secure Context Registers",                  \
			  "AArch64 General Purpose Registers",                 \
			  "AArch64 EL1 Context Registers",                     \
			  "AArch64 EL2 Context Registers",                     \
			  "AArch64 EL3 Context Registers",                     \
			  "Miscellaneous System Register Structure" }

#define ARM_PROCESSOR_INFO_REGISTER_CONTEXT_TYPES_COUNT 9

#define ARM_AARCH32_GPR_NAMES                                                  \
	(const char *[]){ "r0",	 "r1",	   "r2",     "r3",    "r4",  "r5",     \
			  "r6",	 "r7",	   "r8",     "r9",    "r10", "r11",    \
			  "r12", "r13_sp", "r14_lr", "r15_pc" }
#define ARM_AARCH32_EL1_REGISTER_NAMES                                         \
	(const char *[]){ "dfar",     "dfsr",	  "ifar",     "isr",           \
			  "mair0",    "mair1",	  "midr",     "mpidr",         \
			  "nmrr",     "prrr",	  "sctlr_ns", "spsr",          \
			  "spsr_abt", "spsr_fiq", "spsr_irq", "spsr_svc",      \
			  "spsr_und", "tpidrprw", "tpidruro", "tpidrurw",      \
			  "ttbcr",    "ttbr0",	  "ttbr1",    "dacr" }
#define ARM_AARCH32_EL2_REGISTER_NAMES                                         \
	(const char *[]){ "elr_hyp",  "hamair0", "hamair1", "hcr",             \
			  "hcr2",     "hdfar",	 "hifar",   "hpfar",           \
			  "hsr",      "htcr",	 "htpidr",  "httbr",           \
			  "spsr_hyp", "vtcr",	 "vttbr",   "dacr32_el2" }
#define ARM_AARCH32_SECURE_REGISTER_NAMES                                      \
	(const char *[]){ "sctlr_s", "spsr_mon" }
#define ARM_AARCH64_GPR_NAMES                                                  \
	(const char *[]){ "x0",	 "x1",	"x2",  "x3",  "x4",  "x5",  "x6",      \
			  "x7",	 "x8",	"x9",  "x10", "x11", "x12", "x13",     \
			  "x14", "x15", "x16", "x17", "x18", "x19", "x20",     \
			  "x21", "x22", "x23", "x24", "x25", "x26", "x27",     \
			  "x28", "x29", "x30", "sp" }
#define ARM_AARCH64_EL1_REGISTER_NAMES                                         \
	(const char *[]){                                                      \
		"elr_el1",   "esr_el1",	  "far_el1",	 "isr_el1",            \
		"mair_el1",  "midr_el1",  "mpidr_el1",	 "sctlr_el1",          \
		"sp_el0",    "sp_el1",	  "spsr_el1",	 "tcr_el1",            \
		"tpidr_el0", "tpidr_el1", "tpidrro_el0", "ttbr0_el1",          \
		"ttbr1_el1"                                                    \
	}
#define ARM_AARCH64_EL2_REGISTER_NAMES                                         \
	(const char *[]){ "elr_el2",   "esr_el2",   "far_el2",	"hacr_el2",    \
			  "hcr_el2",   "hpfar_el2", "mair_el2", "sctlr_el2",   \
			  "sp_el2",    "spsr_el2",  "tcr_el2",	"tpidr_el2",   \
			  "ttbr0_el2", "vtcr_el2",  "vttbr_el2" }
#define ARM_AARCH64_EL3_REGISTER_NAMES                                         \
	(const char *[]){ "elr_el3",   "esr_el3",  "far_el3",  "mair_el3",     \
			  "sctlr_el3", "sp_el3",   "spsr_el3", "tcr_el3",      \
			  "tpidr_el3", "ttbr0_el3" }

json_object *cper_section_arm_to_ir(const UINT8 *section, UINT32 size,
				    char **desc_string);
void ir_section_arm_to_cper(json_object *section, FILE *out);

/* ARM RAS section handlers */
json_object *cper_section_arm_ras_to_ir(const UINT8 *section, UINT32 size,
					char **desc_string);
void ir_section_arm_ras_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
