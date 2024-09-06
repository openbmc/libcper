#ifndef CPER_SECTION_ARM_H
#define CPER_SECTION_ARM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include "../edk/Cper.h"

#define ARM_ERROR_VALID_BITFIELD_NAMES                                         \
	(const char *[])                                                       \
	{                                                                      \
		"mpidrValid", "errorAffinityLevelValid", "runningStateValid",  \
			"vendorSpecificInfoValid"                              \
	}
#define ARM_ERROR_INFO_ENTRY_VALID_BITFIELD_NAMES                              \
	(const char *[])                                                       \
	{                                                                      \
		"multipleErrorValid", "flagsValid", "errorInformationValid",   \
			"virtualFaultAddressValid",                            \
			"physicalFaultAddressValid"                            \
	}
#define ARM_ERROR_INFO_ENTRY_FLAGS_NAMES                                       \
	(const char *[])                                                       \
	{                                                                      \
		"firstErrorCaptured", "lastErrorCaptured", "propagated",       \
			"overflow"                                             \
	}
#define ARM_CACHE_TLB_ERROR_VALID_BITFIELD_NAMES                               \
	(const char *[])                                                       \
	{                                                                      \
		"transactionTypeValid", "operationValid", "levelValid",        \
			"processorContextCorruptValid", "correctedValid",      \
			"precisePCValid", "restartablePCValid"                 \
	}
#define ARM_BUS_ERROR_VALID_BITFIELD_NAMES                                     \
	(const char *[])                                                       \
	{                                                                      \
		"transactionTypeValid", "operationValid", "levelValid",        \
			"processorContextCorruptValid", "correctedValid",      \
			"precisePCValid", "restartablePCValid",                \
			"participationTypeValid", "timedOutValid",             \
			"addressSpaceValid", "memoryAttributesValid",          \
			"accessModeValid"                                      \
	}
#define ARM_ERROR_TRANSACTION_TYPES_KEYS                                       \
	(int[])                                                                \
	{                                                                      \
		0, 1, 2                                                        \
	}
#define ARM_ERROR_TRANSACTION_TYPES_VALUES                                     \
	(const char *[])                                                       \
	{                                                                      \
		"Instruction", "Data Access", "Generic"                        \
	}
#define ARM_ERROR_INFO_ENTRY_INFO_TYPES_KEYS                                   \
	(int[])                                                                \
	{                                                                      \
		0, 1, 2, 3                                                     \
	}
#define ARM_ERROR_INFO_ENTRY_INFO_TYPES_VALUES                                 \
	(const char *[])                                                       \
	{                                                                      \
		"Cache Error", "TLB Error", "Bus Error",                       \
			"Micro-Architectural Error"                            \
	}
#define ARM_CACHE_BUS_OPERATION_TYPES_KEYS                                     \
	(int[])                                                                \
	{                                                                      \
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10                               \
	}
#define ARM_CACHE_BUS_OPERATION_TYPES_VALUES                                   \
	(const char *[])                                                       \
	{                                                                      \
		"Generic Error", "Generic Read", "Generic Write", "Data Read", \
			"Data Write", "Instruction Fetch", "Prefetch",         \
			"Eviction", "Snooping", "Snooped", "Management"        \
	}
#define ARM_TLB_OPERATION_TYPES_KEYS                                           \
	(int[])                                                                \
	{                                                                      \
		0, 1, 2, 3, 4, 5, 6, 7, 8                                      \
	}
#define ARM_TLB_OPERATION_TYPES_VALUES                                         \
	(const char *[])                                                       \
	{                                                                      \
		"Generic Error", "Generic Read", "Generic Write", "Data Read", \
			"Data Write", "Instruction Fetch", "Prefetch",         \
			"Local Management Operation",                          \
			"External Management Operation"                        \
	}
#define ARM_BUS_PARTICIPATION_TYPES_KEYS                                       \
	(int[])                                                                \
	{                                                                      \
		0, 1, 2, 3                                                     \
	}
#define ARM_BUS_PARTICIPATION_TYPES_VALUES                                     \
	(const char *[])                                                       \
	{                                                                      \
		"Local Processor Originated Request",                          \
			"Local Processor Responded to Request",                \
			"Local Processor Observed", "Generic"                  \
	}
#define ARM_BUS_ADDRESS_SPACE_TYPES_KEYS                                       \
	(int[])                                                                \
	{                                                                      \
		0, 1, 3                                                        \
	}
#define ARM_BUS_ADDRESS_SPACE_TYPES_VALUES                                     \
	(const char *[])                                                       \
	{                                                                      \
		"External Memory Access", "Internal Memory Access",            \
			"Device Memory Access"                                 \
	}
#define ARM_PROCESSOR_INFO_REGISTER_CONTEXT_TYPES_KEYS                         \
	(int[])                                                                \
	{                                                                      \
		0, 1, 2, 3, 4, 5, 6, 7, 8                                      \
	}
#define ARM_PROCESSOR_INFO_REGISTER_CONTEXT_TYPES_VALUES                       \
	(const char *[])                                                       \
	{                                                                      \
		"AArch32 General Purpose Registers",                           \
			"AArch32 EL1 Context Registers",                       \
			"AArch32 EL2 Context Registers",                       \
			"AArch32 Secure Context Registers",                    \
			"AArch64 General Purpose Registers",                   \
			"AArch64 EL1 Context Registers",                       \
			"AArch64 EL2 Context Registers",                       \
			"AArch64 EL3 Context Registers",                       \
			"Miscellaneous System Register Structure"              \
	}
#define ARM_AARCH32_GPR_NAMES                                                  \
	(const char *[])                                                       \
	{                                                                      \
		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",    \
			"r10", "r11", "r12", "r13_sp", "r14_lr", "r15_pc"      \
	}
#define ARM_AARCH32_EL1_REGISTER_NAMES                                         \
	(const char *[])                                                       \
	{                                                                      \
		"dfar", "dfsr", "ifar", "isr", "mair0", "mair1", "midr",       \
			"mpidr", "nmrr", "prrr", "sctlr_ns", "spsr",           \
			"spsr_abt", "spsr_fiq", "spsr_irq", "spsr_svc",        \
			"spsr_und", "tpidrprw", "tpidruro", "tpidrurw",        \
			"ttbcr", "ttbr0", "ttbr1", "dacr"                      \
	}
#define ARM_AARCH32_EL2_REGISTER_NAMES                                         \
	(const char *[])                                                       \
	{                                                                      \
		"elr_hyp", "hamair0", "hamair1", "hcr", "hcr2", "hdfar",       \
			"hifar", "hpfar", "hsr", "htcr", "htpidr", "httbr",    \
			"spsr_hyp", "vtcr", "vttbr", "dacr32_el2"              \
	}
#define ARM_AARCH32_SECURE_REGISTER_NAMES                                      \
	(const char *[])                                                       \
	{                                                                      \
		"sctlr_s", "spsr_mon"                                          \
	}
#define ARM_AARCH64_GPR_NAMES                                                  \
	(const char *[])                                                       \
	{                                                                      \
		"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",    \
			"x10", "x11", "x12", "x13", "x14", "x15", "x16",       \
			"x17", "x18", "x19", "x20", "x21", "x22", "x23",       \
			"x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp"  \
	}
#define ARM_AARCH64_EL1_REGISTER_NAMES                                         \
	(const char *[])                                                       \
	{                                                                      \
		"elr_el1", "esr_el1", "far_el1", "isr_el1", "mair_el1",        \
			"midr_el1", "mpidr_el1", "sctlr_el1", "sp_el0",        \
			"sp_el1", "spsr_el1", "tcr_el1", "tpidr_el0",          \
			"tpidr_el1", "tpidrro_el0", "ttbr0_el1", "ttbr1_el1"   \
	}
#define ARM_AARCH64_EL2_REGISTER_NAMES                                         \
	(const char *[])                                                       \
	{                                                                      \
		"elr_el2", "esr_el2", "far_el2", "hacr_el2", "hcr_el2",        \
			"hpfar_el2", "mair_el2", "sctlr_el2", "sp_el2",        \
			"spsr_el2", "tcr_el2", "tpidr_el2", "ttbr0_el2",       \
			"vtcr_el2", "vttbr_el2"                                \
	}
#define ARM_AARCH64_EL3_REGISTER_NAMES                                         \
	(const char *[])                                                       \
	{                                                                      \
		"elr_el3", "esr_el3", "far_el3", "mair_el3", "sctlr_el3",      \
			"sp_el3", "spsr_el3", "tcr_el3", "tpidr_el3",          \
			"ttbr0_el3"                                            \
	}

///
/// ARM Processor Error Record
///
typedef struct {
	UINT32 ValidFields;
	UINT16 ErrInfoNum;
	UINT16 ContextInfoNum;
	UINT32 SectionLength;
	UINT32 ErrorAffinityLevel;
	UINT64 MPIDR_EL1;
	UINT64 MIDR_EL1;
	UINT32 RunningState;
	UINT32 PsciState;
} __attribute__((packed, aligned(1))) EFI_ARM_ERROR_RECORD;

///
/// ARM Processor Error Information Structure
///
#define ARM_ERROR_INFORMATION_TYPE_CACHE     0
#define ARM_ERROR_INFORMATION_TYPE_TLB	     1
#define ARM_ERROR_INFORMATION_TYPE_BUS	     2
#define ARM_ERROR_INFORMATION_TYPE_MICROARCH 3

typedef struct {
	UINT64 ValidationBits : 16;
	UINT64 TransactionType : 2;
	UINT64 Operation : 4;
	UINT64 Level : 3;
	UINT64 ProcessorContextCorrupt : 1;
	UINT64 Corrected : 1;
	UINT64 PrecisePC : 1;
	UINT64 RestartablePC : 1;
	UINT64 Reserved : 34;
} EFI_ARM_CACHE_ERROR_STRUCTURE;

typedef struct {
	UINT64 ValidationBits : 16;
	UINT64 TransactionType : 2;
	UINT64 Operation : 4;
	UINT64 Level : 3;
	UINT64 ProcessorContextCorrupt : 1;
	UINT64 Corrected : 1;
	UINT64 PrecisePC : 1;
	UINT64 RestartablePC : 1;
	UINT64 Reserved : 34;
} EFI_ARM_TLB_ERROR_STRUCTURE;

typedef struct {
	UINT64 ValidationBits : 16;
	UINT64 TransactionType : 2;
	UINT64 Operation : 4;
	UINT64 Level : 3;
	UINT64 ProcessorContextCorrupt : 1;
	UINT64 Corrected : 1;
	UINT64 PrecisePC : 1;
	UINT64 RestartablePC : 1;
	UINT64 ParticipationType : 2;
	UINT64 TimeOut : 1;
	UINT64 AddressSpace : 2;
	UINT64 MemoryAddressAttributes : 8;
	UINT64 AccessMode : 1;
	UINT64 Reserved : 19;
} EFI_ARM_BUS_ERROR_STRUCTURE;

typedef union {
	UINT64 Value;
	EFI_ARM_CACHE_ERROR_STRUCTURE CacheError;
	EFI_ARM_TLB_ERROR_STRUCTURE TlbError;
	EFI_ARM_BUS_ERROR_STRUCTURE BusError;
} EFI_ARM_ERROR_INFORMATION_STRUCTURE;

typedef struct {
	UINT8 Version;
	UINT8 Length;
	UINT16 ValidationBits;
	UINT8 Type;
	UINT16 MultipleError;
	UINT8 Flags;
	EFI_ARM_ERROR_INFORMATION_STRUCTURE ErrorInformation;
	UINT64 VirtualFaultAddress;
	UINT64 PhysicalFaultAddress;
} __attribute__((packed, aligned(1))) EFI_ARM_ERROR_INFORMATION_ENTRY;

///
/// ARM Processor Context Information Structure
///
typedef struct {
	UINT16 Version;
	UINT16 RegisterContextType;
	UINT32 RegisterArraySize;
} __attribute__((packed, aligned(1))) EFI_ARM_CONTEXT_INFORMATION_HEADER;

///
/// ARM Processor Context Register Types
///
#define EFI_ARM_CONTEXT_TYPE_AARCH32_GPR    0
#define EFI_ARM_CONTEXT_TYPE_AARCH32_EL1    1
#define EFI_ARM_CONTEXT_TYPE_AARCH32_EL2    2
#define EFI_ARM_CONTEXT_TYPE_AARCH32_SECURE 3
#define EFI_ARM_CONTEXT_TYPE_AARCH64_GPR    4
#define EFI_ARM_CONTEXT_TYPE_AARCH64_EL1    5
#define EFI_ARM_CONTEXT_TYPE_AARCH64_EL2    6
#define EFI_ARM_CONTEXT_TYPE_AARCH64_EL3    7
#define EFI_ARM_CONTEXT_TYPE_MISC	    8

typedef struct {
	UINT32 R0;
	UINT32 R1;
	UINT32 R2;
	UINT32 R3;
	UINT32 R4;
	UINT32 R5;
	UINT32 R6;
	UINT32 R7;
	UINT32 R8;
	UINT32 R9;
	UINT32 R10;
	UINT32 R11;
	UINT32 R12;
	UINT32 R13_sp;
	UINT32 R14_lr;
	UINT32 R15_pc;
} EFI_ARM_V8_AARCH32_GPR;

typedef struct {
	UINT32 Dfar;
	UINT32 Dfsr;
	UINT32 Ifar;
	UINT32 Isr;
	UINT32 Mair0;
	UINT32 Mair1;
	UINT32 Midr;
	UINT32 Mpidr;
	UINT32 Nmrr;
	UINT32 Prrr;
	UINT32 Sctlr_Ns;
	UINT32 Spsr;
	UINT32 Spsr_Abt;
	UINT32 Spsr_Fiq;
	UINT32 Spsr_Irq;
	UINT32 Spsr_Svc;
	UINT32 Spsr_Und;
	UINT32 Tpidrprw;
	UINT32 Tpidruro;
	UINT32 Tpidrurw;
	UINT32 Ttbcr;
	UINT32 Ttbr0;
	UINT32 Ttbr1;
	UINT32 Dacr;
} EFI_ARM_AARCH32_EL1_CONTEXT_REGISTERS;

typedef struct {
	UINT32 Elr_Hyp;
	UINT32 Hamair0;
	UINT32 Hamair1;
	UINT32 Hcr;
	UINT32 Hcr2;
	UINT32 Hdfar;
	UINT32 Hifar;
	UINT32 Hpfar;
	UINT32 Hsr;
	UINT32 Htcr;
	UINT32 Htpidr;
	UINT32 Httbr;
	UINT32 Spsr_Hyp;
	UINT32 Vtcr;
	UINT32 Vttbr;
	UINT32 Dacr32_El2;
} EFI_ARM_AARCH32_EL2_CONTEXT_REGISTERS;

typedef struct {
	UINT32 Sctlr_S;
	UINT32 Spsr_Mon;
} EFI_ARM_AARCH32_SECURE_CONTEXT_REGISTERS;

typedef struct {
	UINT64 X0;
	UINT64 X1;
	UINT64 X2;
	UINT64 X3;
	UINT64 X4;
	UINT64 X5;
	UINT64 X6;
	UINT64 X7;
	UINT64 X8;
	UINT64 X9;
	UINT64 X10;
	UINT64 X11;
	UINT64 X12;
	UINT64 X13;
	UINT64 X14;
	UINT64 X15;
	UINT64 X16;
	UINT64 X17;
	UINT64 X18;
	UINT64 X19;
	UINT64 X20;
	UINT64 X21;
	UINT64 X22;
	UINT64 X23;
	UINT64 X24;
	UINT64 X25;
	UINT64 X26;
	UINT64 X27;
	UINT64 X28;
	UINT64 X29;
	UINT64 X30;
	UINT64 Sp;
} EFI_ARM_V8_AARCH64_GPR;

typedef struct {
	UINT64 Elr_El1;
	UINT64 Esr_El1;
	UINT64 Far_El1;
	UINT64 Isr_El1;
	UINT64 Mair_El1;
	UINT64 Midr_El1;
	UINT64 Mpidr_El1;
	UINT64 Sctlr_El1;
	UINT64 Sp_El0;
	UINT64 Sp_El1;
	UINT64 Spsr_El1;
	UINT64 Tcr_El1;
	UINT64 Tpidr_El0;
	UINT64 Tpidr_El1;
	UINT64 Tpidrro_El0;
	UINT64 Ttbr0_El1;
	UINT64 Ttbr1_El1;
} EFI_ARM_AARCH64_EL1_CONTEXT_REGISTERS;

typedef struct {
	UINT64 Elr_El2;
	UINT64 Esr_El2;
	UINT64 Far_El2;
	UINT64 Hacr_El2;
	UINT64 Hcr_El2;
	UINT64 Hpfar_El2;
	UINT64 Mair_El2;
	UINT64 Sctlr_El2;
	UINT64 Sp_El2;
	UINT64 Spsr_El2;
	UINT64 Tcr_El2;
	UINT64 Tpidr_El2;
	UINT64 Ttbr0_El2;
	UINT64 Vtcr_El2;
	UINT64 Vttbr_El2;
} EFI_ARM_AARCH64_EL2_CONTEXT_REGISTERS;

typedef struct {
	UINT64 Elr_El3;
	UINT64 Esr_El3;
	UINT64 Far_El3;
	UINT64 Mair_El3;
	UINT64 Sctlr_El3;
	UINT64 Sp_El3;
	UINT64 Spsr_El3;
	UINT64 Tcr_El3;
	UINT64 Tpidr_El3;
	UINT64 Ttbr0_El3;
} EFI_ARM_AARCH64_EL3_CONTEXT_REGISTERS;

typedef struct {
	UINT64 MrsOp2 : 3;
	UINT64 MrsCrm : 4;
	UINT64 MrsCrn : 4;
	UINT64 MrsOp1 : 3;
	UINT64 MrsO0 : 1;
	UINT64 Value : 64;
} EFI_ARM_MISC_CONTEXT_REGISTER;

json_object *cper_section_arm_to_ir(void *section);
void ir_section_arm_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
