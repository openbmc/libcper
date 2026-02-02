/**
 * Describes functions for converting IA32/x64 CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <json.h>
#include <libcper/base64.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-ia32x64.h>
#include <libcper/log.h>
#include <string.h>

//Private pre-definitions.
json_object *cper_ia32x64_processor_error_info_to_ir(
	EFI_IA32_X64_PROCESS_ERROR_INFO *error_info);
json_object *cper_ia32x64_cache_tlb_check_to_ir(
	EFI_IA32_X64_CACHE_CHECK_INFO *cache_tlb_check);
json_object *
cper_ia32x64_bus_check_to_ir(EFI_IA32_X64_BUS_CHECK_INFO *bus_check);
json_object *cper_ia32x64_ms_check_to_ir(EFI_IA32_X64_MS_CHECK_INFO *ms_check);
json_object *cper_ia32x64_processor_context_info_to_ir(
	EFI_IA32_X64_PROCESSOR_CONTEXT_INFO *context_info, void **cur_pos,
	UINT32 *remaining_size);
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
json_object *cper_section_ia32x64_to_ir(const UINT8 *section, UINT32 size,
					char **desc_string)
{
	int outstr_len = 0;

	*desc_string = NULL;
	if (size < sizeof(EFI_IA32_X64_PROCESSOR_ERROR_RECORD)) {
		cper_print_log("Error: IA32/x64 section too small\n");
		return NULL;
	}

	*desc_string = calloc(1, SECTION_DESC_STRING_SIZE);
	if (*desc_string == NULL) {
		cper_print_log(
			"Error: Failed to allocate IA32/x64 desc string\n");
		return NULL;
	}
	outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
			      "An IA32/x64 Processor Error occurred");
	if (outstr_len < 0) {
		cper_print_log(
			"Error: Could not write to IA32/x64 description string\n");
	} else if (outstr_len > SECTION_DESC_STRING_SIZE) {
		cper_print_log(
			"Error: IA32/x64 description string truncated\n");
	}
	EFI_IA32_X64_PROCESSOR_ERROR_RECORD *record =
		(EFI_IA32_X64_PROCESSOR_ERROR_RECORD *)section;
	UINT32 remaining_size =
		size - sizeof(EFI_IA32_X64_PROCESSOR_ERROR_RECORD);
	json_object *record_ir = json_object_new_object();

	//Validation bits.
	//validation bits contain information
	//about processorErrorInfoNum and processorContextInfoNum.
	//Ensure this is decoded properly in IR->CPER
	int processor_error_info_num = (record->ValidFields >> 2) & 0x3F;
	add_int(record_ir, "processorErrorInfoNum", processor_error_info_num);
	int processor_context_info_num = (record->ValidFields >> 8) & 0x3F;
	add_int(record_ir, "processorContextInfoNum",
		processor_context_info_num);

	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = record->ValidFields };

	//APIC ID.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		add_uint(record_ir, "localAPICID", record->ApicId);
	}

	//CPUID information.
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		json_object *cpuid_info_ir = json_object_new_object();
		EFI_IA32_X64_CPU_ID *cpuid_info =
			(EFI_IA32_X64_CPU_ID *)record->CpuIdInfo;
		add_uint(cpuid_info_ir, "eax", cpuid_info->Eax);
		add_uint(cpuid_info_ir, "ebx", cpuid_info->Ebx);
		add_uint(cpuid_info_ir, "ecx", cpuid_info->Ecx);
		add_uint(cpuid_info_ir, "edx", cpuid_info->Edx);
		json_object_object_add(record_ir, "cpuidInfo", cpuid_info_ir);
	}

	//Processor error information, of the amount described above.
	EFI_IA32_X64_PROCESS_ERROR_INFO *current_error_info =
		(EFI_IA32_X64_PROCESS_ERROR_INFO *)(record + 1);
	json_object *error_info_array = json_object_new_array();
	if (remaining_size < (processor_error_info_num *
			      sizeof(EFI_IA32_X64_PROCESS_ERROR_INFO))) {
		json_object_put(error_info_array);
		json_object_put(record_ir);
		free(*desc_string);
		*desc_string = NULL;
		cper_print_log(
			"Invalid CPER file: Invalid processor error info num.\n");
		return NULL;
	}

	for (int i = 0; i < processor_error_info_num; i++) {
		json_object_array_add(error_info_array,
				      cper_ia32x64_processor_error_info_to_ir(
					      current_error_info));
		current_error_info++;
	}
	remaining_size -= processor_error_info_num *
			  sizeof(EFI_IA32_X64_PROCESS_ERROR_INFO);

	json_object_object_add(record_ir, "processorErrorInfo",
			       error_info_array);

	//Processor context information, of the amount described above.
	if (remaining_size < (processor_context_info_num *
			      sizeof(EFI_IA32_X64_PROCESSOR_CONTEXT_INFO))) {
		json_object_put(record_ir);
		free(*desc_string);
		*desc_string = NULL;
		cper_print_log(
			"Invalid CPER file: Invalid processor context info num.\n");
		return NULL;
	}
	EFI_IA32_X64_PROCESSOR_CONTEXT_INFO *current_context_info =
		(EFI_IA32_X64_PROCESSOR_CONTEXT_INFO *)current_error_info;
	void *cur_pos = (void *)current_context_info;
	json_object *context_info_array = json_object_new_array();
	for (int i = 0; i < processor_context_info_num; i++) {
		json_object *context_info =
			cper_ia32x64_processor_context_info_to_ir(
				current_context_info, &cur_pos,
				&remaining_size);
		json_object_array_add(context_info_array, context_info);
		current_context_info =
			(EFI_IA32_X64_PROCESSOR_CONTEXT_INFO *)cur_pos;

		//The context array is a non-fixed size, pointer is shifted within the above function.
	}

	json_object_object_add(record_ir, "processorContextInfo",
			       context_info_array);

	return record_ir;
}

EFI_GUID *gEfiIa32x64ErrorTypeGuids[] = {
	&gEfiIa32x64ErrorTypeCacheCheckGuid,
	&gEfiIa32x64ErrorTypeTlbCheckGuid,
	&gEfiIa32x64ErrorTypeBusCheckGuid,
	&gEfiIa32x64ErrorTypeMsCheckGuid,
};

//Converts a single IA32/x64 processor error info block into JSON IR format.
json_object *cper_ia32x64_processor_error_info_to_ir(
	EFI_IA32_X64_PROCESS_ERROR_INFO *error_info)
{
	json_object *error_info_ir = json_object_new_object();
	json_object *type = json_object_new_object();

	//Error structure type (as GUID).
	add_guid(type, "guid", &error_info->ErrorType);

	//Get the error structure type as a readable string.
	const char *readable_type = "Unknown";

	const char *readable_names[] = {
		"Cache Check Error",
		"TLB Check Error",
		"Bus Check Error",
		"MS Check Error",
	};

	int index = select_guid_from_list(
		&error_info->ErrorType, gEfiIa32x64ErrorTypeGuids,
		sizeof(gEfiIa32x64ErrorTypeGuids) / sizeof(EFI_GUID *));

	if (index < (int)(sizeof(readable_names) / sizeof(char *))) {
		readable_type = readable_names[index];
	}

	json_object_object_add(type, "name",
			       json_object_new_string(readable_type));
	json_object_object_add(error_info_ir, "type", type);

	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = error_info->ValidFields };

	//Add the check information on a per-structure basis.
	//Cache and TLB check information are identical, so can be equated.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *check_information = NULL;

		switch (index) {
		case 0:
		case 1:
			check_information = cper_ia32x64_cache_tlb_check_to_ir(
				(EFI_IA32_X64_CACHE_CHECK_INFO *)&error_info
					->CheckInfo);
			break;
		case 2:
			check_information = cper_ia32x64_bus_check_to_ir(
				(EFI_IA32_X64_BUS_CHECK_INFO *)&error_info
					->CheckInfo);
			break;
		case 3:
			check_information = cper_ia32x64_ms_check_to_ir(
				(EFI_IA32_X64_MS_CHECK_INFO *)&error_info
					->CheckInfo);
			break;
		default:
			//Unknown check information.
			cper_print_log(
				"WARN: Invalid/unknown check information GUID found in IA32/x64 CPER section. Ignoring.\n");
			break;
		}
		if (check_information != NULL) {
			json_object_object_add(error_info_ir, "checkInfo",
					       check_information);
		}
	}

	//Target, requestor, and responder identifiers.
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		add_uint(error_info_ir, "targetAddressID",
			 error_info->TargetId);
	}
	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		add_uint(error_info_ir, "requestorID", error_info->RequestorId);
	}
	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		add_uint(error_info_ir, "responderID", error_info->ResponderId);
	}
	if (isvalid_prop_to_ir(&ui64Type, 4)) {
		add_uint(error_info_ir, "instructionPointer",
			 error_info->InstructionIP);
	}

	return error_info_ir;
}

//Converts a single IA32/x64 cache or TLB check check info block into JSON IR format.
json_object *cper_ia32x64_cache_tlb_check_to_ir(
	EFI_IA32_X64_CACHE_CHECK_INFO *cache_tlb_check)
{
	json_object *cache_tlb_check_ir = json_object_new_object();

	//Validation bits.
	ValidationTypes ui64Type = {
		UINT_64T, .value.ui64 = cache_tlb_check->ValidFields
	};

	//Transaction type.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *transaction_type = integer_to_readable_pair(
			cache_tlb_check->TransactionType, 3,
			IA32X64_CHECK_INFO_TRANSACTION_TYPES_KEYS,
			IA32X64_CHECK_INFO_TRANSACTION_TYPES_VALUES,
			"Unknown (Reserved)");
		json_object_object_add(cache_tlb_check_ir, "transactionType",
				       transaction_type);
	}

	//Operation.
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		json_object *operation = integer_to_readable_pair(
			cache_tlb_check->Operation, 9,
			IA32X64_CHECK_INFO_OPERATION_TYPES_KEYS,
			IA32X64_CHECK_INFO_OPERATION_TYPES_VALUES,
			"Unknown (Reserved)");
		json_object_object_add(cache_tlb_check_ir, "operation",
				       operation);
	}

	//Affected cache/TLB level.
	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		add_uint(cache_tlb_check_ir, "level", cache_tlb_check->Level);
	}

	//Miscellaneous boolean fields.
	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		json_object_object_add(
			cache_tlb_check_ir, "processorContextCorrupt",
			json_object_new_boolean(
				cache_tlb_check->ContextCorrupt));
	}
	if (isvalid_prop_to_ir(&ui64Type, 4)) {
		json_object_object_add(
			cache_tlb_check_ir, "uncorrected",
			json_object_new_boolean(
				cache_tlb_check->ErrorUncorrected));
	}
	if (isvalid_prop_to_ir(&ui64Type, 5)) {
		json_object_object_add(
			cache_tlb_check_ir, "preciseIP",
			json_object_new_boolean(cache_tlb_check->PreciseIp));
	}
	if (isvalid_prop_to_ir(&ui64Type, 6)) {
		json_object_object_add(cache_tlb_check_ir, "restartableIP",
				       json_object_new_boolean(
					       cache_tlb_check->RestartableIp));
	}
	if (isvalid_prop_to_ir(&ui64Type, 7)) {
		json_object_object_add(
			cache_tlb_check_ir, "overflow",
			json_object_new_boolean(cache_tlb_check->Overflow));
	}

	return cache_tlb_check_ir;
}

//Converts a single IA32/x64 bus check check info block into JSON IR format.
json_object *
cper_ia32x64_bus_check_to_ir(EFI_IA32_X64_BUS_CHECK_INFO *bus_check)
{
	json_object *bus_check_ir = json_object_new_object();

	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = bus_check->ValidFields };

	//Transaction type.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *transaction_type = integer_to_readable_pair(
			bus_check->TransactionType, 3,
			IA32X64_CHECK_INFO_TRANSACTION_TYPES_KEYS,
			IA32X64_CHECK_INFO_TRANSACTION_TYPES_VALUES,
			"Unknown (Reserved)");
		json_object_object_add(bus_check_ir, "transactionType",
				       transaction_type);
	}

	//Operation.
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		json_object *operation = integer_to_readable_pair(
			bus_check->Operation, 9,
			IA32X64_CHECK_INFO_OPERATION_TYPES_KEYS,
			IA32X64_CHECK_INFO_OPERATION_TYPES_VALUES,
			"Unknown (Reserved)");
		json_object_object_add(bus_check_ir, "operation", operation);
	}

	//Affected bus level.
	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		add_uint(bus_check_ir, "level", bus_check->Level);
	}

	//Miscellaneous boolean fields.
	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		json_object_object_add(
			bus_check_ir, "processorContextCorrupt",
			json_object_new_boolean(bus_check->ContextCorrupt));
	}
	if (isvalid_prop_to_ir(&ui64Type, 4)) {
		json_object_object_add(
			bus_check_ir, "uncorrected",
			json_object_new_boolean(bus_check->ErrorUncorrected));
	}
	if (isvalid_prop_to_ir(&ui64Type, 5)) {
		json_object_object_add(
			bus_check_ir, "preciseIP",
			json_object_new_boolean(bus_check->PreciseIp));
	}
	if (isvalid_prop_to_ir(&ui64Type, 6)) {
		json_object_object_add(
			bus_check_ir, "restartableIP",
			json_object_new_boolean(bus_check->RestartableIp));
	}
	if (isvalid_prop_to_ir(&ui64Type, 7)) {
		json_object_object_add(
			bus_check_ir, "overflow",
			json_object_new_boolean(bus_check->Overflow));
	}
	if (isvalid_prop_to_ir(&ui64Type, 9)) {
		json_object_object_add(
			bus_check_ir, "timedOut",
			json_object_new_boolean(bus_check->TimeOut));
	}

	//Participation type.
	if (isvalid_prop_to_ir(&ui64Type, 8)) {
		json_object *participation_type = integer_to_readable_pair(
			bus_check->ParticipationType, 4,
			IA32X64_BUS_CHECK_INFO_PARTICIPATION_TYPES_KEYS,
			IA32X64_BUS_CHECK_INFO_PARTICIPATION_TYPES_VALUES,
			"Unknown");
		json_object_object_add(bus_check_ir, "participationType",
				       participation_type);
	}

	//Address space.
	if (isvalid_prop_to_ir(&ui64Type, 10)) {
		json_object *address_space = integer_to_readable_pair(
			bus_check->AddressSpace, 4,
			IA32X64_BUS_CHECK_INFO_ADDRESS_SPACE_TYPES_KEYS,
			IA32X64_BUS_CHECK_INFO_ADDRESS_SPACE_TYPES_VALUES,
			"Unknown");
		json_object_object_add(bus_check_ir, "addressSpace",
				       address_space);
	}

	return bus_check_ir;
}

//Converts a single IA32/x64 MS check check info block into JSON IR format.
json_object *cper_ia32x64_ms_check_to_ir(EFI_IA32_X64_MS_CHECK_INFO *ms_check)
{
	json_object *ms_check_ir = json_object_new_object();
	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = ms_check->ValidFields };
	//Validation bits.
	//Error type (operation that caused the error).
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *error_type = integer_to_readable_pair(
			ms_check->ErrorType, 4,
			IA32X64_MS_CHECK_INFO_ERROR_TYPES_KEYS,
			IA32X64_MS_CHECK_INFO_ERROR_TYPES_VALUES,
			"Unknown (Processor Specific)");
		json_object_object_add(ms_check_ir, "errorType", error_type);
	}

	//Miscellaneous fields.
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		json_object_object_add(
			ms_check_ir, "processorContextCorrupt",
			json_object_new_boolean(ms_check->ContextCorrupt));
	}
	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		json_object_object_add(
			ms_check_ir, "uncorrected",
			json_object_new_boolean(ms_check->ErrorUncorrected));
	}
	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		json_object_object_add(
			ms_check_ir, "preciseIP",
			json_object_new_boolean(ms_check->PreciseIp));
	}
	if (isvalid_prop_to_ir(&ui64Type, 4)) {
		json_object_object_add(
			ms_check_ir, "restartableIP",
			json_object_new_boolean(ms_check->RestartableIp));
	}
	if (isvalid_prop_to_ir(&ui64Type, 5)) {
		json_object_object_add(
			ms_check_ir, "overflow",
			json_object_new_boolean(ms_check->Overflow));
	}

	return ms_check_ir;
}

//Converts a single IA32/x64 processor context info entry into JSON IR format.
json_object *cper_ia32x64_processor_context_info_to_ir(
	EFI_IA32_X64_PROCESSOR_CONTEXT_INFO *context_info, void **cur_pos,
	UINT32 *remaining_size)
{
	if (*remaining_size < sizeof(EFI_IA32_X64_PROCESSOR_CONTEXT_INFO)) {
		return NULL;
	}
	*remaining_size -= sizeof(EFI_IA32_X64_PROCESSOR_CONTEXT_INFO);
	json_object *context_info_ir = json_object_new_object();

	//Register context type.
	json_object *context_type = integer_to_readable_pair(
		context_info->RegisterType, IA32X64_REGISTER_CONTEXT_TYPES_SIZE,
		IA32X64_REGISTER_CONTEXT_TYPES_KEYS,
		IA32X64_REGISTER_CONTEXT_TYPES_VALUES, "Unknown (Reserved)");
	json_object_object_add(context_info_ir, "registerContextType",
			       context_type);

	//Register array size, MSR and MM address.
	add_uint(context_info_ir, "registerArraySize", context_info->ArraySize);
	add_uint(context_info_ir, "msrAddress", context_info->MsrAddress);
	add_uint(context_info_ir, "mmRegisterAddress",
		 context_info->MmRegisterAddress);

	//Register array.
	json_object *register_array = NULL;
	if (context_info->RegisterType == EFI_REG_CONTEXT_TYPE_IA32) {
		if (*remaining_size < sizeof(EFI_CONTEXT_IA32_REGISTER_STATE)) {
			return context_info_ir;
		}
		EFI_CONTEXT_IA32_REGISTER_STATE *register_state =
			(EFI_CONTEXT_IA32_REGISTER_STATE *)(context_info + 1);
		register_array =
			cper_ia32x64_register_32bit_to_ir(register_state);
		*cur_pos = (void *)(register_state + 1);
		*remaining_size -= sizeof(EFI_CONTEXT_IA32_REGISTER_STATE);
	} else if (context_info->RegisterType == EFI_REG_CONTEXT_TYPE_X64) {
		if (*remaining_size < sizeof(EFI_CONTEXT_X64_REGISTER_STATE)) {
			return context_info_ir;
		}
		EFI_CONTEXT_X64_REGISTER_STATE *register_state =
			(EFI_CONTEXT_X64_REGISTER_STATE *)(context_info + 1);
		register_array =
			cper_ia32x64_register_64bit_to_ir(register_state);
		*cur_pos = (void *)(register_state + 1);
		*remaining_size -= sizeof(EFI_CONTEXT_X64_REGISTER_STATE);
	} else {
		//No parseable data, just dump as base64 and shift the head to the next item.
		*cur_pos = (void *)(context_info + 1);
		if (*remaining_size < context_info->ArraySize) {
			return context_info_ir;
		}
		int32_t encoded_len = 0;
		char *encoded = base64_encode((UINT8 *)*cur_pos,
					      context_info->ArraySize,
					      &encoded_len);
		if (encoded == NULL) {
			cper_print_log(
				"Failed to allocate encode output buffer. \n");
		} else {
			register_array = json_object_new_object();
			json_object_object_add(register_array, "data",
					       json_object_new_string_len(
						       encoded, encoded_len));
			free(encoded);
		}

		*cur_pos =
			(void *)(((char *)*cur_pos) + context_info->ArraySize);
		*remaining_size -= context_info->ArraySize;
	}
	if (register_array != NULL) {
		json_object_object_add(context_info_ir, "registerArray",
				       register_array);
	}

	return context_info_ir;
}

//Converts a single CPER IA32 register state into JSON IR format.
json_object *
cper_ia32x64_register_32bit_to_ir(EFI_CONTEXT_IA32_REGISTER_STATE *registers)
{
	json_object *ia32_registers = json_object_new_object();
	add_uint(ia32_registers, "eax", registers->Eax);
	add_uint(ia32_registers, "ebx", registers->Ebx);
	add_uint(ia32_registers, "ecx", registers->Ecx);
	add_uint(ia32_registers, "edx", registers->Edx);
	add_uint(ia32_registers, "esi", registers->Esi);
	add_uint(ia32_registers, "edi", registers->Edi);
	add_uint(ia32_registers, "ebp", registers->Ebp);
	add_uint(ia32_registers, "esp", registers->Esp);
	add_uint(ia32_registers, "cs", registers->Cs);
	add_uint(ia32_registers, "ds", registers->Ds);
	add_uint(ia32_registers, "ss", registers->Ss);
	add_uint(ia32_registers, "es", registers->Es);
	add_uint(ia32_registers, "fs", registers->Fs);
	add_uint(ia32_registers, "gs", registers->Gs);
	add_uint(ia32_registers, "eflags", registers->Eflags);
	add_uint(ia32_registers, "eip", registers->Eip);
	add_uint(ia32_registers, "cr0", registers->Cr0);
	add_uint(ia32_registers, "cr1", registers->Cr1);
	add_uint(ia32_registers, "cr2", registers->Cr2);
	add_uint(ia32_registers, "cr3", registers->Cr3);
	add_uint(ia32_registers, "cr4", registers->Cr4);
	add_uint(ia32_registers, "gdtr",
		 registers->Gdtr[0] + ((UINT64)registers->Gdtr[1] << 32));
	add_uint(ia32_registers, "idtr",
		 registers->Idtr[0] + ((UINT64)registers->Idtr[1] << 32));
	add_uint(ia32_registers, "ldtr", registers->Ldtr);
	add_uint(ia32_registers, "tr", registers->Tr);

	return ia32_registers;
}

//Converts a single CPER x64 register state into JSON IR format.
json_object *
cper_ia32x64_register_64bit_to_ir(EFI_CONTEXT_X64_REGISTER_STATE *registers)
{
	json_object *x64_registers = json_object_new_object();
	add_uint(x64_registers, "rax", registers->Rax);
	add_uint(x64_registers, "rbx", registers->Rbx);
	add_uint(x64_registers, "rcx", registers->Rcx);
	add_uint(x64_registers, "rdx", registers->Rdx);
	add_uint(x64_registers, "rsi", registers->Rsi);
	add_uint(x64_registers, "rdi", registers->Rdi);
	add_uint(x64_registers, "rbp", registers->Rbp);
	add_uint(x64_registers, "rsp", registers->Rsp);
	add_uint(x64_registers, "r8", registers->R8);
	add_uint(x64_registers, "r9", registers->R9);
	add_uint(x64_registers, "r10", registers->R10);
	add_uint(x64_registers, "r11", registers->R11);
	add_uint(x64_registers, "r12", registers->R12);
	add_uint(x64_registers, "r13", registers->R13);
	add_uint(x64_registers, "r14", registers->R14);
	add_uint(x64_registers, "r15", registers->R15);
	add_int(x64_registers, "cs", registers->Cs);
	add_int(x64_registers, "ds", registers->Ds);
	add_int(x64_registers, "ss", registers->Ss);
	add_int(x64_registers, "es", registers->Es);
	add_int(x64_registers, "fs", registers->Fs);
	add_int(x64_registers, "gs", registers->Gs);
	add_uint(x64_registers, "rflags", registers->Rflags);
	add_uint(x64_registers, "eip", registers->Rip);
	add_uint(x64_registers, "cr0", registers->Cr0);
	add_uint(x64_registers, "cr1", registers->Cr1);
	add_uint(x64_registers, "cr2", registers->Cr2);
	add_uint(x64_registers, "cr3", registers->Cr3);
	add_uint(x64_registers, "cr4", registers->Cr4);
	add_uint(x64_registers, "cr8", registers->Cr8);
	add_uint(x64_registers, "gdtr_0", registers->Gdtr[0]);
	add_uint(x64_registers, "gdtr_1", registers->Gdtr[1]);
	add_uint(x64_registers, "idtr_0", registers->Idtr[0]);
	add_uint(x64_registers, "idtr_1", registers->Idtr[1]);
	add_int(x64_registers, "ldtr", registers->Ldtr);
	add_int(x64_registers, "tr", registers->Tr);

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

	uint64_t valid = 0x0;

	int proc_error_info_num = json_object_get_int(json_object_object_get(
					  section, "processorErrorInfoNum")) &
				  0x3F;
	int proc_ctx_info_num = json_object_get_int(json_object_object_get(
					section, "processorContextInfoNum")) &
				0x3F;
	valid |= proc_error_info_num << 2;
	valid |= proc_ctx_info_num << 8;

	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = valid };
	struct json_object *obj = NULL;

	//Local APIC ID.
	if (json_object_object_get_ex(section, "localAPICID", &obj)) {
		section_cper->ApicId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 0);
	}

	//CPUID info.
	if (json_object_object_get_ex(section, "cpuidInfo", &obj)) {
		json_object *cpuid_info = obj;
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
		add_to_valid_bitfield(&ui64Type, 1);
	}
	section_cper->ValidFields = ui64Type.value.ui64;

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
	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;

	//Check information, parsed based on the error type.
	if (json_object_object_get_ex(error_info, "checkInfo", &obj)) {
		json_object *check_info = obj;

		int index = select_guid_from_list(
			&error_info_cper->ErrorType, gEfiIa32x64ErrorTypeGuids,
			sizeof(gEfiIa32x64ErrorTypeGuids) / sizeof(EFI_GUID *));

		switch (index) {
		case 0:
		case 1:
			ir_ia32x64_cache_tlb_check_error_to_cper(
				check_info,
				(EFI_IA32_X64_CACHE_CHECK_INFO
					 *)&error_info_cper->CheckInfo);
			break;
		case 2:
			ir_ia32x64_bus_check_error_to_cper(
				check_info,
				(EFI_IA32_X64_BUS_CHECK_INFO *)&error_info_cper
					->CheckInfo);
			break;
		case 3:
			ir_ia32x64_ms_check_error_to_cper(
				check_info,
				(EFI_IA32_X64_MS_CHECK_INFO *)&error_info_cper
					->CheckInfo);
			break;
		default:
			//Unknown check information.
			cper_print_log(
				"WARN: Invalid/unknown check information GUID found in IA32/x64 CPER section. Ignoring.\n");
			break;
		}
		add_to_valid_bitfield(&ui64Type, 0);
	}

	//Miscellaneous numeric fields.
	if (json_object_object_get_ex(error_info, "targetAddressID", &obj)) {
		error_info_cper->TargetId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 1);
	}
	if (json_object_object_get_ex(error_info, "requestorID", &obj)) {
		error_info_cper->RequestorId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 2);
	}
	if (json_object_object_get_ex(error_info, "responderID", &obj)) {
		error_info_cper->ResponderId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 3);
	}
	if (json_object_object_get_ex(error_info, "instructionPointer", &obj)) {
		error_info_cper->InstructionIP = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 4);
	}

	error_info_cper->ValidFields = ui64Type.value.ui64;
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
	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;

	//Transaction type, operation.
	if (json_object_object_get_ex(check_info, "transactionType", &obj)) {
		check_info_cper->TransactionType =
			readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 0);
	}
	if (json_object_object_get_ex(check_info, "operation", &obj)) {
		check_info_cper->Operation = readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 1);
	}

	//Miscellaneous raw value fields.
	if (json_object_object_get_ex(check_info, "level", &obj)) {
		check_info_cper->Level = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 2);
	}
	if (json_object_object_get_ex(check_info, "processorContextCorrupt",
				      &obj)) {
		check_info_cper->ContextCorrupt = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 3);
	}
	if (json_object_object_get_ex(check_info, "uncorrected", &obj)) {
		check_info_cper->ErrorUncorrected =
			json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 4);
	}
	if (json_object_object_get_ex(check_info, "preciseIP", &obj)) {
		check_info_cper->PreciseIp = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 5);
	}
	if (json_object_object_get_ex(check_info, "restartableIP", &obj)) {
		check_info_cper->RestartableIp = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 6);
	}
	if (json_object_object_get_ex(check_info, "overflow", &obj)) {
		check_info_cper->Overflow = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 7);
	}
	check_info_cper->ValidFields = ui64Type.value.ui64;
}

//Converts a single CPER-JSON IA32/x64 bus error info structure to CPER binary.
void ir_ia32x64_bus_check_error_to_cper(
	json_object *check_info, EFI_IA32_X64_BUS_CHECK_INFO *check_info_cper)
{
	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;

	//Readable pair fields.
	if (json_object_object_get_ex(check_info, "transactionType", &obj)) {
		check_info_cper->TransactionType =
			readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 0);
	}
	if (json_object_object_get_ex(check_info, "operation", &obj)) {
		check_info_cper->Operation = readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 1);
	}
	if (json_object_object_get_ex(check_info, "participationType", &obj)) {
		check_info_cper->ParticipationType =
			readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 8);
	}

	if (json_object_object_get_ex(check_info, "addressSpace", &obj)) {
		check_info_cper->AddressSpace = readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 10);
	}

	//Miscellaneous raw value fields.
	if (json_object_object_get_ex(check_info, "level", &obj)) {
		check_info_cper->Level = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 2);
	}
	if (json_object_object_get_ex(check_info, "processorContextCorrupt",
				      &obj)) {
		check_info_cper->ContextCorrupt = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 3);
	}
	if (json_object_object_get_ex(check_info, "uncorrected", &obj)) {
		check_info_cper->ErrorUncorrected =
			json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 4);
	}
	if (json_object_object_get_ex(check_info, "preciseIP", &obj)) {
		check_info_cper->PreciseIp = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 5);
	}
	if (json_object_object_get_ex(check_info, "restartableIP", &obj)) {
		check_info_cper->RestartableIp = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 6);
	}
	if (json_object_object_get_ex(check_info, "overflow", &obj)) {
		check_info_cper->Overflow = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 7);
	}
	if (json_object_object_get_ex(check_info, "timedOut", &obj)) {
		check_info_cper->TimeOut = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 9);
	}
	check_info_cper->ValidFields = ui64Type.value.ui64;
}

//Converts a single CPER-JSON IA32/x64 MS error info structure to CPER binary.
void ir_ia32x64_ms_check_error_to_cper(
	json_object *check_info, EFI_IA32_X64_MS_CHECK_INFO *check_info_cper)
{
	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;

	//Type of MS check error.
	if (json_object_object_get_ex(check_info, "errorType", &obj)) {
		check_info_cper->ErrorType = readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 0);
	}

	//Miscellaneous raw value fields.
	if (json_object_object_get_ex(check_info, "processorContextCorrupt",
				      &obj)) {
		check_info_cper->ContextCorrupt = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 1);
	}
	if (json_object_object_get_ex(check_info, "uncorrected", &obj)) {
		check_info_cper->ErrorUncorrected =
			json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 2);
	}
	if (json_object_object_get_ex(check_info, "preciseIP", &obj)) {
		check_info_cper->PreciseIp = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 3);
	}
	if (json_object_object_get_ex(check_info, "restartableIP", &obj)) {
		check_info_cper->RestartableIp = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 4);
	}
	if (json_object_object_get_ex(check_info, "overflow", &obj)) {
		check_info_cper->Overflow = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 5);
	}
	check_info_cper->ValidFields = ui64Type.value.ui64;
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
		int32_t decoded_len = 0;
		const char *j_string = json_object_get_string(encoded);
		int j_size = json_object_get_string_len(encoded);
		UINT8 *decoded = base64_decode(j_string, j_size, &decoded_len);
		if (decoded == NULL) {
			cper_print_log(
				"Failed to allocate decode output buffer. \n");
		} else {
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
