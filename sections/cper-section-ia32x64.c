/**
 * Describes functions for converting IA32/x64 CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <json.h>
#include "libbase64.h"
#include "../edk/Cper.h"
#include "../cper-utils.h"
#include "cper-section-ia32x64.h"

//Private pre-definitions.
json_object *cper_ia32x64_processor_error_info_to_ir(
	EFI_IA32_X64_PROCESS_ERROR_INFO *error_info);
json_object *cper_ia32x64_cache_tlb_check_to_ir(
	EFI_IA32_X64_CACHE_CHECK_INFO *cache_tlb_check);
json_object *
cper_ia32x64_bus_check_to_ir(EFI_IA32_X64_BUS_CHECK_INFO *bus_check);
json_object *cper_ia32x64_ms_check_to_ir(EFI_IA32_X64_MS_CHECK_INFO *ms_check);
json_object *cper_ia32x64_processor_context_info_to_ir(
	EFI_IA32_X64_PROCESSOR_CONTEXT_INFO *context_info, void **cur_pos);
json_object *
cper_ia32x64_register_32bit_to_ir(EFI_CONTEXT_IA32_REGISTER_STATE *registers);
json_object *
cper_ia32x64_register_64bit_to_ir(EFI_CONTEXT_X64_REGISTER_STATE *registers);
void ir_ia32x64_error_info_to_cper(json_object *error_info, FILE *out);
void ir_ia32x64_context_info_to_cper(json_object *context_info, FILE *out);
void ir_ia32x64_cache_tlb_check_error_to_cper(
	json_object *check_info,
	EFI_IA32_X64_CACHE_CHECK_INFO *check_info_cper);
void ir_ia32x64_bus_check_error_to_cper(
	json_object *check_info, EFI_IA32_X64_BUS_CHECK_INFO *check_info_cper);
void ir_ia32x64_ms_check_error_to_cper(
	json_object *check_info, EFI_IA32_X64_MS_CHECK_INFO *check_info_cper);
void ir_ia32x64_ia32_registers_to_cper(json_object *registers, FILE *out);
void ir_ia32x64_x64_registers_to_cper(json_object *registers, FILE *out);

//////////////////
/// CPER TO IR ///
//////////////////

//Converts the IA32/x64 error section described in the given descriptor into intermediate format.
json_object *cper_section_ia32x64_to_ir(void *section)
{
	EFI_IA32_X64_PROCESSOR_ERROR_RECORD *record =
		(EFI_IA32_X64_PROCESSOR_ERROR_RECORD *)section;
	json_object *record_ir = json_object_new_object();

	//Validation bits.
	json_object *validationBits = json_object_new_object();
	json_object_object_add(validationBits, "localAPICIDValid",
			       json_object_new_boolean(record->ValidFields &
						       0x1));
	json_object_object_add(
		validationBits, "cpuIDInfoValid",
		json_object_new_boolean((record->ValidFields >> 1) & 0x1));
	int processor_error_info_num = (record->ValidFields >> 2) & 0x3F;
	json_object_object_add(validationBits, "processorErrorInfoNum",
			       json_object_new_int(processor_error_info_num));
	int processor_context_info_num = (record->ValidFields >> 8) & 0x3F;
	json_object_object_add(validationBits, "processorContextInfoNum",
			       json_object_new_int(processor_context_info_num));
	json_object_object_add(record_ir, "validationBits", validationBits);

	//APIC ID.
	json_object_object_add(record_ir, "localAPICID",
			       json_object_new_uint64(record->ApicId));

	//CPUID information.
	json_object *cpuid_info_ir = json_object_new_object();
	EFI_IA32_X64_CPU_ID *cpuid_info =
		(EFI_IA32_X64_CPU_ID *)record->CpuIdInfo;
	json_object_object_add(cpuid_info_ir, "eax",
			       json_object_new_uint64(cpuid_info->Eax));
	json_object_object_add(cpuid_info_ir, "ebx",
			       json_object_new_uint64(cpuid_info->Ebx));
	json_object_object_add(cpuid_info_ir, "ecx",
			       json_object_new_uint64(cpuid_info->Ecx));
	json_object_object_add(cpuid_info_ir, "edx",
			       json_object_new_uint64(cpuid_info->Edx));
	json_object_object_add(record_ir, "cpuidInfo", cpuid_info_ir);

	//Processor error information, of the amount described above.
	EFI_IA32_X64_PROCESS_ERROR_INFO *current_error_info =
		(EFI_IA32_X64_PROCESS_ERROR_INFO *)(record + 1);
	json_object *error_info_array = json_object_new_array();
	for (int i = 0; i < processor_error_info_num; i++) {
		json_object_array_add(error_info_array,
				      cper_ia32x64_processor_error_info_to_ir(
					      current_error_info));
		current_error_info++;
	}
	json_object_object_add(record_ir, "processorErrorInfo",
			       error_info_array);

	//Processor context information, of the amount described above.
	EFI_IA32_X64_PROCESSOR_CONTEXT_INFO *current_context_info =
		(EFI_IA32_X64_PROCESSOR_CONTEXT_INFO *)current_error_info;
	void *cur_pos = (void *)current_context_info;
	json_object *context_info_array = json_object_new_array();
	for (int i = 0; i < processor_context_info_num; i++) {
		json_object_array_add(context_info_array,
				      cper_ia32x64_processor_context_info_to_ir(
					      current_context_info, &cur_pos));
		current_context_info =
			(EFI_IA32_X64_PROCESSOR_CONTEXT_INFO *)cur_pos;
		//The context array is a non-fixed size, pointer is shifted within the above function.
	}
	json_object_object_add(record_ir, "processorContextInfo",
			       context_info_array);

	return record_ir;
}

//Converts a single IA32/x64 processor error info block into JSON IR format.
json_object *cper_ia32x64_processor_error_info_to_ir(
	EFI_IA32_X64_PROCESS_ERROR_INFO *error_info)
{
	json_object *error_info_ir = json_object_new_object();

	//Error structure type (as GUID).
	char error_type[GUID_STRING_LENGTH];
	guid_to_string(error_type, &error_info->ErrorType);
	json_object *type = json_object_new_object();
	json_object_object_add(type, "guid",
			       json_object_new_string(error_type));

	//Get the error structure type as a readable string.
	const char *readable_type = "Unknown";
	if (guid_equal(&error_info->ErrorType,
		       &gEfiIa32x64ErrorTypeCacheCheckGuid)) {
		readable_type = "Cache Check Error";
	} else if (guid_equal(&error_info->ErrorType,
			      &gEfiIa32x64ErrorTypeTlbCheckGuid)) {
		readable_type = "TLB Check Error";
	} else if (guid_equal(&error_info->ErrorType,
			      &gEfiIa32x64ErrorTypeBusCheckGuid)) {
		readable_type = "Bus Check Error";
	} else if (guid_equal(&error_info->ErrorType,
			      &gEfiIa32x64ErrorTypeMsCheckGuid)) {
		readable_type = "MS Check Error";
	}
	json_object_object_add(type, "name",
			       json_object_new_string(readable_type));
	json_object_object_add(error_info_ir, "type", type);

	//Validation bits.
	json_object *validation =
		bitfield_to_ir(error_info->ValidFields, 5,
			       IA32X64_PROCESSOR_ERROR_VALID_BITFIELD_NAMES);
	json_object_object_add(error_info_ir, "validationBits", validation);

	//Add the check information on a per-structure basis.
	//Cache and TLB check information are identical, so can be equated.
	json_object *check_information = NULL;
	if (guid_equal(&error_info->ErrorType,
		       &gEfiIa32x64ErrorTypeCacheCheckGuid) ||
	    guid_equal(&error_info->ErrorType,
		       &gEfiIa32x64ErrorTypeTlbCheckGuid)) {
		check_information = cper_ia32x64_cache_tlb_check_to_ir(
			(EFI_IA32_X64_CACHE_CHECK_INFO *)&error_info->CheckInfo);
	} else if (guid_equal(&error_info->ErrorType,
			      &gEfiIa32x64ErrorTypeBusCheckGuid)) {
		check_information = cper_ia32x64_bus_check_to_ir(
			(EFI_IA32_X64_BUS_CHECK_INFO *)&error_info->CheckInfo);
	} else if (guid_equal(&error_info->ErrorType,
			      &gEfiIa32x64ErrorTypeMsCheckGuid)) {
		check_information = cper_ia32x64_ms_check_to_ir(
			(EFI_IA32_X64_MS_CHECK_INFO *)&error_info->CheckInfo);
	} else {
		//Unknown check information.
		printf("WARN: Invalid/unknown check information GUID found in IA32/x64 CPER section. Ignoring.\n");
	}
	json_object_object_add(error_info_ir, "checkInfo", check_information);

	//Target, requestor, and responder identifiers.
	json_object_object_add(error_info_ir, "targetAddressID",
			       json_object_new_uint64(error_info->TargetId));
	json_object_object_add(error_info_ir, "requestorID",
			       json_object_new_uint64(error_info->RequestorId));
	json_object_object_add(error_info_ir, "responderID",
			       json_object_new_uint64(error_info->ResponderId));
	json_object_object_add(
		error_info_ir, "instructionPointer",
		json_object_new_uint64(error_info->InstructionIP));

	return error_info_ir;
}

//Converts a single IA32/x64 cache or TLB check check info block into JSON IR format.
json_object *cper_ia32x64_cache_tlb_check_to_ir(
	EFI_IA32_X64_CACHE_CHECK_INFO *cache_tlb_check)
{
	json_object *cache_tlb_check_ir = json_object_new_object();

	//Validation bits.
	json_object *validation =
		bitfield_to_ir(cache_tlb_check->ValidFields, 8,
			       IA32X64_CHECK_INFO_VALID_BITFIELD_NAMES);
	json_object_object_add(cache_tlb_check_ir, "validationBits",
			       validation);

	//Transaction type.
	json_object *transaction_type = integer_to_readable_pair(
		cache_tlb_check->TransactionType, 3,
		IA32X64_CHECK_INFO_TRANSACTION_TYPES_KEYS,
		IA32X64_CHECK_INFO_TRANSACTION_TYPES_VALUES,
		"Unknown (Reserved)");
	json_object_object_add(cache_tlb_check_ir, "transactionType",
			       transaction_type);

	//Operation.
	json_object *operation = integer_to_readable_pair(
		cache_tlb_check->Operation, 9,
		IA32X64_CHECK_INFO_OPERATION_TYPES_KEYS,
		IA32X64_CHECK_INFO_OPERATION_TYPES_VALUES,
		"Unknown (Reserved)");
	json_object_object_add(cache_tlb_check_ir, "operation", operation);

	//Affected cache/TLB level.
	json_object_object_add(cache_tlb_check_ir, "level",
			       json_object_new_uint64(cache_tlb_check->Level));

	//Miscellaneous boolean fields.
	json_object_object_add(
		cache_tlb_check_ir, "processorContextCorrupt",
		json_object_new_boolean(cache_tlb_check->ContextCorrupt));
	json_object_object_add(
		cache_tlb_check_ir, "uncorrected",
		json_object_new_boolean(cache_tlb_check->ErrorUncorrected));
	json_object_object_add(
		cache_tlb_check_ir, "preciseIP",
		json_object_new_boolean(cache_tlb_check->PreciseIp));
	json_object_object_add(
		cache_tlb_check_ir, "restartableIP",
		json_object_new_boolean(cache_tlb_check->RestartableIp));
	json_object_object_add(
		cache_tlb_check_ir, "overflow",
		json_object_new_boolean(cache_tlb_check->Overflow));

	return cache_tlb_check_ir;
}

//Converts a single IA32/x64 bus check check info block into JSON IR format.
json_object *
cper_ia32x64_bus_check_to_ir(EFI_IA32_X64_BUS_CHECK_INFO *bus_check)
{
	json_object *bus_check_ir = json_object_new_object();

	//Validation bits.
	json_object *validation =
		bitfield_to_ir(bus_check->ValidFields, 11,
			       IA32X64_CHECK_INFO_VALID_BITFIELD_NAMES);
	json_object_object_add(bus_check_ir, "validationBits", validation);

	//Transaction type.
	json_object *transaction_type = integer_to_readable_pair(
		bus_check->TransactionType, 3,
		IA32X64_CHECK_INFO_TRANSACTION_TYPES_KEYS,
		IA32X64_CHECK_INFO_TRANSACTION_TYPES_VALUES,
		"Unknown (Reserved)");
	json_object_object_add(bus_check_ir, "transactionType",
			       transaction_type);

	//Operation.
	json_object *operation = integer_to_readable_pair(
		bus_check->Operation, 9,
		IA32X64_CHECK_INFO_OPERATION_TYPES_KEYS,
		IA32X64_CHECK_INFO_OPERATION_TYPES_VALUES,
		"Unknown (Reserved)");
	json_object_object_add(bus_check_ir, "operation", operation);

	//Affected bus level.
	json_object_object_add(bus_check_ir, "level",
			       json_object_new_uint64(bus_check->Level));

	//Miscellaneous boolean fields.
	json_object_object_add(
		bus_check_ir, "processorContextCorrupt",
		json_object_new_boolean(bus_check->ContextCorrupt));
	json_object_object_add(
		bus_check_ir, "uncorrected",
		json_object_new_boolean(bus_check->ErrorUncorrected));
	json_object_object_add(bus_check_ir, "preciseIP",
			       json_object_new_boolean(bus_check->PreciseIp));
	json_object_object_add(
		bus_check_ir, "restartableIP",
		json_object_new_boolean(bus_check->RestartableIp));
	json_object_object_add(bus_check_ir, "overflow",
			       json_object_new_boolean(bus_check->Overflow));
	json_object_object_add(bus_check_ir, "timedOut",
			       json_object_new_boolean(bus_check->TimeOut));

	//Participation type.
	json_object *participation_type = integer_to_readable_pair(
		bus_check->ParticipationType, 4,
		IA32X64_BUS_CHECK_INFO_PARTICIPATION_TYPES_KEYS,
		IA32X64_BUS_CHECK_INFO_PARTICIPATION_TYPES_VALUES, "Unknown");
	json_object_object_add(bus_check_ir, "participationType",
			       participation_type);

	//Address space.
	json_object *address_space = integer_to_readable_pair(
		bus_check->AddressSpace, 4,
		IA32X64_BUS_CHECK_INFO_ADDRESS_SPACE_TYPES_KEYS,
		IA32X64_BUS_CHECK_INFO_ADDRESS_SPACE_TYPES_VALUES, "Unknown");
	json_object_object_add(bus_check_ir, "addressSpace", address_space);

	return bus_check_ir;
}

//Converts a single IA32/x64 MS check check info block into JSON IR format.
json_object *cper_ia32x64_ms_check_to_ir(EFI_IA32_X64_MS_CHECK_INFO *ms_check)
{
	json_object *ms_check_ir = json_object_new_object();

	//Validation bits.
	json_object *validation = bitfield_to_ir(
		ms_check->ValidFields, 6,
		IA32X64_CHECK_INFO_MS_CHECK_VALID_BITFIELD_NAMES);
	json_object_object_add(ms_check_ir, "validationBits", validation);

	//Error type (operation that caused the error).
	json_object *error_type = integer_to_readable_pair(
		ms_check->ErrorType, 4, IA32X64_MS_CHECK_INFO_ERROR_TYPES_KEYS,
		IA32X64_MS_CHECK_INFO_ERROR_TYPES_VALUES,
		"Unknown (Processor Specific)");
	json_object_object_add(ms_check_ir, "errorType", error_type);

	//Miscellaneous fields.
	json_object_object_add(
		ms_check_ir, "processorContextCorrupt",
		json_object_new_boolean(ms_check->ContextCorrupt));
	json_object_object_add(
		ms_check_ir, "uncorrected",
		json_object_new_boolean(ms_check->ErrorUncorrected));
	json_object_object_add(ms_check_ir, "preciseIP",
			       json_object_new_boolean(ms_check->PreciseIp));
	json_object_object_add(
		ms_check_ir, "restartableIP",
		json_object_new_boolean(ms_check->RestartableIp));
	json_object_object_add(ms_check_ir, "overflow",
			       json_object_new_boolean(ms_check->Overflow));

	return ms_check_ir;
}

//Converts a single IA32/x64 processor context info entry into JSON IR format.
json_object *cper_ia32x64_processor_context_info_to_ir(
	EFI_IA32_X64_PROCESSOR_CONTEXT_INFO *context_info, void **cur_pos)
{
	json_object *context_info_ir = json_object_new_object();

	//Register context type.
	json_object *context_type = integer_to_readable_pair(
		context_info->RegisterType, 8,
		IA32X64_REGISTER_CONTEXT_TYPES_KEYS,
		IA32X64_REGISTER_CONTEXT_TYPES_VALUES, "Unknown (Reserved)");
	json_object_object_add(context_info_ir, "registerContextType",
			       context_type);

	//Register array size, MSR and MM address.
	json_object_object_add(context_info_ir, "registerArraySize",
			       json_object_new_uint64(context_info->ArraySize));
	json_object_object_add(
		context_info_ir, "msrAddress",
		json_object_new_uint64(context_info->MsrAddress));
	json_object_object_add(
		context_info_ir, "mmRegisterAddress",
		json_object_new_uint64(context_info->MmRegisterAddress));

	//Register array.
	json_object *register_array = NULL;
	if (context_info->RegisterType == EFI_REG_CONTEXT_TYPE_IA32) {
		EFI_CONTEXT_IA32_REGISTER_STATE *register_state =
			(EFI_CONTEXT_IA32_REGISTER_STATE *)(context_info + 1);
		register_array =
			cper_ia32x64_register_32bit_to_ir(register_state);
		*cur_pos = (void *)(register_state + 1);
	} else if (context_info->RegisterType == EFI_REG_CONTEXT_TYPE_X64) {
		EFI_CONTEXT_X64_REGISTER_STATE *register_state =
			(EFI_CONTEXT_X64_REGISTER_STATE *)(context_info + 1);
		register_array =
			cper_ia32x64_register_64bit_to_ir(register_state);
		*cur_pos = (void *)(register_state + 1);
	} else {
		//No parseable data, just dump as base64 and shift the head to the next item.
		*cur_pos = (void *)(context_info + 1);

		char *encoded = malloc(2 * context_info->ArraySize);
		size_t encoded_len = 0;
		if (!encoded) {
			printf("Failed to allocate encode output buffer. \n");
		} else {
			base64_encode((const char *)*cur_pos,
				      context_info->ArraySize, encoded,
				      &encoded_len, 0);

			register_array = json_object_new_object();
			json_object_object_add(register_array, "data",
					       json_object_new_string_len(
						       encoded, encoded_len));
			free(encoded);
		}

		*cur_pos =
			(void *)(((char *)*cur_pos) + context_info->ArraySize);
	}
	json_object_object_add(context_info_ir, "registerArray",
			       register_array);

	return context_info_ir;
}

//Converts a single CPER IA32 register state into JSON IR format.
json_object *
cper_ia32x64_register_32bit_to_ir(EFI_CONTEXT_IA32_REGISTER_STATE *registers)
{
	json_object *ia32_registers = json_object_new_object();
	json_object_object_add(ia32_registers, "eax",
			       json_object_new_uint64(registers->Eax));
	json_object_object_add(ia32_registers, "ebx",
			       json_object_new_uint64(registers->Ebx));
	json_object_object_add(ia32_registers, "ecx",
			       json_object_new_uint64(registers->Ecx));
	json_object_object_add(ia32_registers, "edx",
			       json_object_new_uint64(registers->Edx));
	json_object_object_add(ia32_registers, "esi",
			       json_object_new_uint64(registers->Esi));
	json_object_object_add(ia32_registers, "edi",
			       json_object_new_uint64(registers->Edi));
	json_object_object_add(ia32_registers, "ebp",
			       json_object_new_uint64(registers->Ebp));
	json_object_object_add(ia32_registers, "esp",
			       json_object_new_uint64(registers->Esp));
	json_object_object_add(ia32_registers, "cs",
			       json_object_new_uint64(registers->Cs));
	json_object_object_add(ia32_registers, "ds",
			       json_object_new_uint64(registers->Ds));
	json_object_object_add(ia32_registers, "ss",
			       json_object_new_uint64(registers->Ss));
	json_object_object_add(ia32_registers, "es",
			       json_object_new_uint64(registers->Es));
	json_object_object_add(ia32_registers, "fs",
			       json_object_new_uint64(registers->Fs));
	json_object_object_add(ia32_registers, "gs",
			       json_object_new_uint64(registers->Gs));
	json_object_object_add(ia32_registers, "eflags",
			       json_object_new_uint64(registers->Eflags));
	json_object_object_add(ia32_registers, "eip",
			       json_object_new_uint64(registers->Eip));
	json_object_object_add(ia32_registers, "cr0",
			       json_object_new_uint64(registers->Cr0));
	json_object_object_add(ia32_registers, "cr1",
			       json_object_new_uint64(registers->Cr1));
	json_object_object_add(ia32_registers, "cr2",
			       json_object_new_uint64(registers->Cr2));
	json_object_object_add(ia32_registers, "cr3",
			       json_object_new_uint64(registers->Cr3));
	json_object_object_add(ia32_registers, "cr4",
			       json_object_new_uint64(registers->Cr4));
	json_object_object_add(
		ia32_registers, "gdtr",
		json_object_new_uint64(registers->Gdtr[0] +
				       ((UINT64)registers->Gdtr[1] << 32)));
	json_object_object_add(
		ia32_registers, "idtr",
		json_object_new_uint64(registers->Idtr[0] +
				       ((UINT64)registers->Idtr[1] << 32)));
	json_object_object_add(ia32_registers, "ldtr",
			       json_object_new_uint64(registers->Ldtr));
	json_object_object_add(ia32_registers, "tr",
			       json_object_new_uint64(registers->Tr));

	return ia32_registers;
}

//Converts a single CPER x64 register state into JSON IR format.
json_object *
cper_ia32x64_register_64bit_to_ir(EFI_CONTEXT_X64_REGISTER_STATE *registers)
{
	json_object *x64_registers = json_object_new_object();
	json_object_object_add(x64_registers, "rax",
			       json_object_new_uint64(registers->Rax));
	json_object_object_add(x64_registers, "rbx",
			       json_object_new_uint64(registers->Rbx));
	json_object_object_add(x64_registers, "rcx",
			       json_object_new_uint64(registers->Rcx));
	json_object_object_add(x64_registers, "rdx",
			       json_object_new_uint64(registers->Rdx));
	json_object_object_add(x64_registers, "rsi",
			       json_object_new_uint64(registers->Rsi));
	json_object_object_add(x64_registers, "rdi",
			       json_object_new_uint64(registers->Rdi));
	json_object_object_add(x64_registers, "rbp",
			       json_object_new_uint64(registers->Rbp));
	json_object_object_add(x64_registers, "rsp",
			       json_object_new_uint64(registers->Rsp));
	json_object_object_add(x64_registers, "r8",
			       json_object_new_uint64(registers->R8));
	json_object_object_add(x64_registers, "r9",
			       json_object_new_uint64(registers->R9));
	json_object_object_add(x64_registers, "r10",
			       json_object_new_uint64(registers->R10));
	json_object_object_add(x64_registers, "r11",
			       json_object_new_uint64(registers->R11));
	json_object_object_add(x64_registers, "r12",
			       json_object_new_uint64(registers->R12));
	json_object_object_add(x64_registers, "r13",
			       json_object_new_uint64(registers->R13));
	json_object_object_add(x64_registers, "r14",
			       json_object_new_uint64(registers->R14));
	json_object_object_add(x64_registers, "r15",
			       json_object_new_uint64(registers->R15));
	json_object_object_add(x64_registers, "cs",
			       json_object_new_int(registers->Cs));
	json_object_object_add(x64_registers, "ds",
			       json_object_new_int(registers->Ds));
	json_object_object_add(x64_registers, "ss",
			       json_object_new_int(registers->Ss));
	json_object_object_add(x64_registers, "es",
			       json_object_new_int(registers->Es));
	json_object_object_add(x64_registers, "fs",
			       json_object_new_int(registers->Fs));
	json_object_object_add(x64_registers, "gs",
			       json_object_new_int(registers->Gs));
	json_object_object_add(x64_registers, "rflags",
			       json_object_new_uint64(registers->Rflags));
	json_object_object_add(x64_registers, "eip",
			       json_object_new_uint64(registers->Rip));
	json_object_object_add(x64_registers, "cr0",
			       json_object_new_uint64(registers->Cr0));
	json_object_object_add(x64_registers, "cr1",
			       json_object_new_uint64(registers->Cr1));
	json_object_object_add(x64_registers, "cr2",
			       json_object_new_uint64(registers->Cr2));
	json_object_object_add(x64_registers, "cr3",
			       json_object_new_uint64(registers->Cr3));
	json_object_object_add(x64_registers, "cr4",
			       json_object_new_uint64(registers->Cr4));
	json_object_object_add(x64_registers, "cr8",
			       json_object_new_uint64(registers->Cr8));
	json_object_object_add(x64_registers, "gdtr_0",
			       json_object_new_uint64(registers->Gdtr[0]));
	json_object_object_add(x64_registers, "gdtr_1",
			       json_object_new_uint64(registers->Gdtr[1]));
	json_object_object_add(x64_registers, "idtr_0",
			       json_object_new_uint64(registers->Idtr[0]));
	json_object_object_add(x64_registers, "idtr_1",
			       json_object_new_uint64(registers->Idtr[1]));
	json_object_object_add(x64_registers, "ldtr",
			       json_object_new_int(registers->Ldtr));
	json_object_object_add(x64_registers, "tr",
			       json_object_new_int(registers->Tr));

	return x64_registers;
}

//////////////////
/// IR TO CPER ///
//////////////////

//Converts a single IA32/x64 CPER-JSON section into CPER binary, outputting to the provided stream.
void ir_section_ia32x64_to_cper(json_object *section, FILE *out)
{
	EFI_IA32_X64_PROCESSOR_ERROR_RECORD *section_cper =
		(EFI_IA32_X64_PROCESSOR_ERROR_RECORD *)calloc(
			1, sizeof(EFI_IA32_X64_PROCESSOR_ERROR_RECORD));

	//Validation bits.
	json_object *validation =
		json_object_object_get(section, "validationBits");
	section_cper->ValidFields = 0x0;
	section_cper->ValidFields |= json_object_get_boolean(
		json_object_object_get(validation, "localAPICIDValid"));
	section_cper->ValidFields |=
		json_object_get_boolean(
			json_object_object_get(validation, "cpuIDInfoValid"))
		<< 1;
	int proc_error_info_num =
		json_object_get_int(json_object_object_get(
			validation, "processorErrorInfoNum")) &
		0x3F;
	int proc_ctx_info_num =
		json_object_get_int(json_object_object_get(
			validation, "processorContextInfoNum")) &
		0x3F;
	section_cper->ValidFields |= proc_error_info_num << 2;
	section_cper->ValidFields |= proc_ctx_info_num << 8;

	//Local APIC ID.
	section_cper->ApicId = json_object_get_uint64(
		json_object_object_get(section, "localAPICID"));

	//CPUID info.
	json_object *cpuid_info = json_object_object_get(section, "cpuidInfo");
	EFI_IA32_X64_CPU_ID *cpuid_info_cper =
		(EFI_IA32_X64_CPU_ID *)section_cper->CpuIdInfo;
	cpuid_info_cper->Eax = json_object_get_uint64(
		json_object_object_get(cpuid_info, "eax"));
	cpuid_info_cper->Ebx = json_object_get_uint64(
		json_object_object_get(cpuid_info, "ebx"));
	cpuid_info_cper->Ecx = json_object_get_uint64(
		json_object_object_get(cpuid_info, "ecx"));
	cpuid_info_cper->Edx = json_object_get_uint64(
		json_object_object_get(cpuid_info, "edx"));

	//Flush the header to file before dealing w/ info sections.
	fwrite(section_cper, sizeof(EFI_IA32_X64_PROCESSOR_ERROR_RECORD), 1,
	       out);
	fflush(out);
	free(section_cper);

	//Iterate and deal with sections.
	json_object *error_info =
		json_object_object_get(section, "processorErrorInfo");
	json_object *context_info =
		json_object_object_get(section, "processorContextInfo");
	for (int i = 0; i < proc_error_info_num; i++) {
		ir_ia32x64_error_info_to_cper(
			json_object_array_get_idx(error_info, i), out);
	}
	for (int i = 0; i < proc_ctx_info_num; i++) {
		ir_ia32x64_context_info_to_cper(
			json_object_array_get_idx(context_info, i), out);
	}
}

//Converts a single CPER-JSON IA32/x64 error information structure into CPER binary, outputting to the
//provided stream.
void ir_ia32x64_error_info_to_cper(json_object *error_info, FILE *out)
{
	EFI_IA32_X64_PROCESS_ERROR_INFO *error_info_cper =
		(EFI_IA32_X64_PROCESS_ERROR_INFO *)calloc(
			1, sizeof(EFI_IA32_X64_PROCESS_ERROR_INFO));

	//Error structure type.
	json_object *type = json_object_object_get(error_info, "type");
	string_to_guid(
		&error_info_cper->ErrorType,
		json_object_get_string(json_object_object_get(type, "guid")));

	//Validation bits.
	error_info_cper->ValidFields = ir_to_bitfield(
		json_object_object_get(error_info, "validationBits"), 5,
		IA32X64_PROCESSOR_ERROR_VALID_BITFIELD_NAMES);

	//Check information, parsed based on the error type.
	json_object *check_info =
		json_object_object_get(error_info, "checkInfo");
	if (guid_equal(&error_info_cper->ErrorType,
		       &gEfiIa32x64ErrorTypeCacheCheckGuid) ||
	    guid_equal(&error_info_cper->ErrorType,
		       &gEfiIa32x64ErrorTypeTlbCheckGuid)) {
		ir_ia32x64_cache_tlb_check_error_to_cper(
			check_info,
			(EFI_IA32_X64_CACHE_CHECK_INFO *)&error_info_cper
				->CheckInfo);
	} else if (guid_equal(&error_info_cper->ErrorType,
			      &gEfiIa32x64ErrorTypeBusCheckGuid)) {
		ir_ia32x64_bus_check_error_to_cper(
			check_info,
			(EFI_IA32_X64_BUS_CHECK_INFO *)&error_info_cper
				->CheckInfo);
	} else if (guid_equal(&error_info_cper->ErrorType,
			      &gEfiIa32x64ErrorTypeMsCheckGuid)) {
		ir_ia32x64_ms_check_error_to_cper(
			check_info,
			(EFI_IA32_X64_MS_CHECK_INFO *)&error_info_cper
				->CheckInfo);
	}

	//Miscellaneous numeric fields.
	error_info_cper->TargetId = json_object_get_uint64(
		json_object_object_get(error_info, "targetAddressID"));
	error_info_cper->RequestorId = json_object_get_uint64(
		json_object_object_get(error_info, "requestorID"));
	error_info_cper->ResponderId = json_object_get_uint64(
		json_object_object_get(error_info, "responderID"));
	error_info_cper->InstructionIP = json_object_get_uint64(
		json_object_object_get(error_info, "instructionPointer"));

	//Write out to stream, then free resources.
	fwrite(error_info_cper, sizeof(EFI_IA32_X64_PROCESS_ERROR_INFO), 1,
	       out);
	fflush(out);
	free(error_info_cper);
}

//Converts a single CPER-JSON IA32/x64 cache/TLB check error info structure to CPER binary.
void ir_ia32x64_cache_tlb_check_error_to_cper(
	json_object *check_info, EFI_IA32_X64_CACHE_CHECK_INFO *check_info_cper)
{
	//Validation bits.
	check_info_cper->ValidFields = ir_to_bitfield(
		json_object_object_get(check_info, "validationBits"), 8,
		IA32X64_CHECK_INFO_VALID_BITFIELD_NAMES);

	//Transaction type, operation.
	check_info_cper->TransactionType = readable_pair_to_integer(
		json_object_object_get(check_info, "transactionType"));
	check_info_cper->Operation = readable_pair_to_integer(
		json_object_object_get(check_info, "operation"));

	//Miscellaneous raw value fields.
	check_info_cper->Level = json_object_get_uint64(
		json_object_object_get(check_info, "level"));
	check_info_cper->ContextCorrupt = json_object_get_boolean(
		json_object_object_get(check_info, "processorContextCorrupt"));
	check_info_cper->ErrorUncorrected = json_object_get_boolean(
		json_object_object_get(check_info, "uncorrected"));
	check_info_cper->PreciseIp = json_object_get_boolean(
		json_object_object_get(check_info, "preciseIP"));
	check_info_cper->RestartableIp = json_object_get_boolean(
		json_object_object_get(check_info, "restartableIP"));
	check_info_cper->Overflow = json_object_get_boolean(
		json_object_object_get(check_info, "overflow"));
}

//Converts a single CPER-JSON IA32/x64 bus error info structure to CPER binary.
void ir_ia32x64_bus_check_error_to_cper(
	json_object *check_info, EFI_IA32_X64_BUS_CHECK_INFO *check_info_cper)
{
	//Validation bits.
	check_info_cper->ValidFields = ir_to_bitfield(
		json_object_object_get(check_info, "validationBits"), 11,
		IA32X64_CHECK_INFO_VALID_BITFIELD_NAMES);

	//Readable pair fields.
	check_info_cper->TransactionType = readable_pair_to_integer(
		json_object_object_get(check_info, "transactionType"));
	check_info_cper->Operation = readable_pair_to_integer(
		json_object_object_get(check_info, "operation"));
	check_info_cper->ParticipationType = readable_pair_to_integer(
		json_object_object_get(check_info, "participationType"));
	check_info_cper->AddressSpace = readable_pair_to_integer(
		json_object_object_get(check_info, "addressSpace"));

	//Miscellaneous raw value fields.
	check_info_cper->Level = json_object_get_uint64(
		json_object_object_get(check_info, "level"));
	check_info_cper->ContextCorrupt = json_object_get_boolean(
		json_object_object_get(check_info, "processorContextCorrupt"));
	check_info_cper->ErrorUncorrected = json_object_get_boolean(
		json_object_object_get(check_info, "uncorrected"));
	check_info_cper->PreciseIp = json_object_get_boolean(
		json_object_object_get(check_info, "preciseIP"));
	check_info_cper->RestartableIp = json_object_get_boolean(
		json_object_object_get(check_info, "restartableIP"));
	check_info_cper->Overflow = json_object_get_boolean(
		json_object_object_get(check_info, "overflow"));
	check_info_cper->TimeOut = json_object_get_boolean(
		json_object_object_get(check_info, "timedOut"));
}

//Converts a single CPER-JSON IA32/x64 MS error info structure to CPER binary.
void ir_ia32x64_ms_check_error_to_cper(
	json_object *check_info, EFI_IA32_X64_MS_CHECK_INFO *check_info_cper)
{
	//Validation bits.
	check_info_cper->ValidFields = ir_to_bitfield(
		json_object_object_get(check_info, "validationBits"), 6,
		IA32X64_CHECK_INFO_MS_CHECK_VALID_BITFIELD_NAMES);

	//Type of MS check error.
	check_info_cper->ErrorType = readable_pair_to_integer(
		json_object_object_get(check_info, "errorType"));

	//Miscellaneous raw value fields.
	check_info_cper->ContextCorrupt = json_object_get_boolean(
		json_object_object_get(check_info, "processorContextCorrupt"));
	check_info_cper->ErrorUncorrected = json_object_get_boolean(
		json_object_object_get(check_info, "uncorrected"));
	check_info_cper->PreciseIp = json_object_get_boolean(
		json_object_object_get(check_info, "preciseIP"));
	check_info_cper->RestartableIp = json_object_get_boolean(
		json_object_object_get(check_info, "restartableIP"));
	check_info_cper->Overflow = json_object_get_boolean(
		json_object_object_get(check_info, "overflow"));
}

//Converts a single CPER-JSON IA32/x64 context information structure into CPER binary, outputting to the
//provided stream.
void ir_ia32x64_context_info_to_cper(json_object *context_info, FILE *out)
{
	EFI_IA32_X64_PROCESSOR_CONTEXT_INFO *context_info_cper =
		(EFI_IA32_X64_PROCESSOR_CONTEXT_INFO *)calloc(
			1, sizeof(EFI_IA32_X64_PROCESSOR_CONTEXT_INFO));

	//Register context type.
	context_info_cper->RegisterType = (UINT16)readable_pair_to_integer(
		json_object_object_get(context_info, "registerContextType"));

	//Miscellaneous numeric fields.
	context_info_cper->ArraySize = (UINT16)json_object_get_uint64(
		json_object_object_get(context_info, "registerArraySize"));
	context_info_cper->MsrAddress = (UINT32)json_object_get_uint64(
		json_object_object_get(context_info, "msrAddress"));
	context_info_cper->MmRegisterAddress = json_object_get_uint64(
		json_object_object_get(context_info, "mmRegisterAddress"));

	//Flush header to stream.
	fwrite(context_info_cper, sizeof(EFI_IA32_X64_PROCESSOR_CONTEXT_INFO),
	       1, out);
	fflush(out);

	//Handle the register array, depending on type provided.
	json_object *register_array =
		json_object_object_get(context_info, "registerArray");
	if (context_info_cper->RegisterType == EFI_REG_CONTEXT_TYPE_IA32) {
		ir_ia32x64_ia32_registers_to_cper(register_array, out);
	} else if (context_info_cper->RegisterType ==
		   EFI_REG_CONTEXT_TYPE_X64) {
		ir_ia32x64_x64_registers_to_cper(register_array, out);
	} else {
		//Unknown/structure is not defined.
		json_object *encoded =
			json_object_object_get(register_array, "data");
		char *decoded = malloc(json_object_get_string_len(encoded));
		size_t decoded_len = 0;
		if (!decoded) {
			printf("Failed to allocate decode output buffer. \n");
		} else {
			base64_decode(json_object_get_string(encoded),
				      json_object_get_string_len(encoded),
				      decoded, &decoded_len, 0);
			fwrite(decoded, decoded_len, 1, out);
			fflush(out);
			free(decoded);
		}
	}

	//Free remaining resources.
	free(context_info_cper);
}

//Converts a single CPER-JSON IA32 register array into CPER binary, outputting to the given stream.
void ir_ia32x64_ia32_registers_to_cper(json_object *registers, FILE *out)
{
	EFI_CONTEXT_IA32_REGISTER_STATE register_state;
	register_state.Eax = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "eax"));
	register_state.Ebx = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "ebx"));
	register_state.Ecx = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "ecx"));
	register_state.Edx = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "edx"));
	register_state.Esi = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "esi"));
	register_state.Edi = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "edi"));
	register_state.Ebp = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "ebp"));
	register_state.Esp = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "esp"));
	register_state.Cs = (UINT16)json_object_get_uint64(
		json_object_object_get(registers, "cs"));
	register_state.Ds = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "ds"));
	register_state.Ss = (UINT16)json_object_get_uint64(
		json_object_object_get(registers, "ss"));
	register_state.Es = (UINT16)json_object_get_uint64(
		json_object_object_get(registers, "es"));
	register_state.Fs = (UINT16)json_object_get_uint64(
		json_object_object_get(registers, "fs"));
	register_state.Gs = (UINT16)json_object_get_uint64(
		json_object_object_get(registers, "gs"));
	register_state.Eflags = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "eflags"));
	register_state.Eip = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "eip"));
	register_state.Cr0 = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "cr0"));
	register_state.Cr1 = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "cr1"));
	register_state.Cr2 = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "cr2"));
	register_state.Cr3 = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "cr3"));
	register_state.Cr4 = (UINT32)json_object_get_uint64(
		json_object_object_get(registers, "cr4"));

	//64-bit registers are split into two 32-bit parts.
	UINT64 gdtr = json_object_get_uint64(
		json_object_object_get(registers, "gdtr"));
	register_state.Gdtr[0] = gdtr & 0xFFFFFFFF;
	register_state.Gdtr[1] = gdtr >> 32;
	UINT64 idtr = json_object_get_uint64(
		json_object_object_get(registers, "idtr"));
	register_state.Idtr[0] = idtr & 0xFFFFFFFF;
	register_state.Idtr[1] = idtr >> 32;

	//16-bit registers.
	register_state.Ldtr = (UINT16)json_object_get_uint64(
		json_object_object_get(registers, "ldtr"));
	register_state.Tr = (UINT16)json_object_get_uint64(
		json_object_object_get(registers, "tr"));

	//Write out to stream.
	fwrite(&register_state, sizeof(EFI_CONTEXT_IA32_REGISTER_STATE), 1,
	       out);
	fflush(out);
}

//Converts a single CPER-JSON x64 register array into CPER binary, outputting to the given stream.
void ir_ia32x64_x64_registers_to_cper(json_object *registers, FILE *out)
{
	EFI_CONTEXT_X64_REGISTER_STATE register_state;
	register_state.Rax = json_object_get_uint64(
		json_object_object_get(registers, "rax"));
	register_state.Rbx = json_object_get_uint64(
		json_object_object_get(registers, "rbx"));
	register_state.Rcx = json_object_get_uint64(
		json_object_object_get(registers, "rcx"));
	register_state.Rdx = json_object_get_uint64(
		json_object_object_get(registers, "rdx"));
	register_state.Rsi = json_object_get_uint64(
		json_object_object_get(registers, "rsi"));
	register_state.Rdi = json_object_get_uint64(
		json_object_object_get(registers, "rdi"));
	register_state.Rbp = json_object_get_uint64(
		json_object_object_get(registers, "rbp"));
	register_state.Rsp = json_object_get_uint64(
		json_object_object_get(registers, "rsp"));
	register_state.R8 =
		json_object_get_uint64(json_object_object_get(registers, "r8"));
	register_state.R9 =
		json_object_get_uint64(json_object_object_get(registers, "r9"));
	register_state.R10 = json_object_get_uint64(
		json_object_object_get(registers, "r10"));
	register_state.R11 = json_object_get_uint64(
		json_object_object_get(registers, "r11"));
	register_state.R12 = json_object_get_uint64(
		json_object_object_get(registers, "r12"));
	register_state.R13 = json_object_get_uint64(
		json_object_object_get(registers, "r13"));
	register_state.R14 = json_object_get_uint64(
		json_object_object_get(registers, "r14"));
	register_state.R15 = json_object_get_uint64(
		json_object_object_get(registers, "r15"));
	register_state.Cs = (UINT16)json_object_get_int(
		json_object_object_get(registers, "cs"));
	register_state.Ds = (UINT16)json_object_get_int(
		json_object_object_get(registers, "ds"));
	register_state.Ss = (UINT16)json_object_get_int(
		json_object_object_get(registers, "ss"));
	register_state.Es = (UINT16)json_object_get_int(
		json_object_object_get(registers, "es"));
	register_state.Fs = (UINT16)json_object_get_int(
		json_object_object_get(registers, "fs"));
	register_state.Gs = (UINT16)json_object_get_int(
		json_object_object_get(registers, "gs"));
	register_state.Resv1 = 0;
	register_state.Rflags = json_object_get_uint64(
		json_object_object_get(registers, "rflags"));
	register_state.Rip = json_object_get_uint64(
		json_object_object_get(registers, "eip"));
	register_state.Cr0 = json_object_get_uint64(
		json_object_object_get(registers, "cr0"));
	register_state.Cr1 = json_object_get_uint64(
		json_object_object_get(registers, "cr1"));
	register_state.Cr2 = json_object_get_uint64(
		json_object_object_get(registers, "cr2"));
	register_state.Cr3 = json_object_get_uint64(
		json_object_object_get(registers, "cr3"));
	register_state.Cr4 = json_object_get_uint64(
		json_object_object_get(registers, "cr4"));
	register_state.Cr8 = json_object_get_uint64(
		json_object_object_get(registers, "cr8"));
	register_state.Gdtr[0] = json_object_get_uint64(
		json_object_object_get(registers, "gdtr_0"));
	register_state.Gdtr[1] = json_object_get_uint64(
		json_object_object_get(registers, "gdtr_1"));
	register_state.Idtr[0] = json_object_get_uint64(
		json_object_object_get(registers, "idtr_0"));
	register_state.Idtr[1] = json_object_get_uint64(
		json_object_object_get(registers, "idtr_1"));
	register_state.Ldtr = (UINT16)json_object_get_int(
		json_object_object_get(registers, "ldtr"));
	register_state.Tr = (UINT16)json_object_get_int(
		json_object_object_get(registers, "tr"));

	//Write out to stream.
	fwrite(&register_state, sizeof(EFI_CONTEXT_X64_REGISTER_STATE), 1, out);
	fflush(out);
}
