/**
 * Describes functions for converting ARM CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <json.h>
#include "libbase64.h"
#include "../edk/Cper.h"
#include "../cper-utils.h"
#include "cper-section-arm.h"

//Private pre-definitions.
json_object *
cper_arm_error_info_to_ir(EFI_ARM_ERROR_INFORMATION_ENTRY *error_info);
json_object *
cper_arm_processor_context_to_ir(EFI_ARM_CONTEXT_INFORMATION_HEADER *header,
				 void **cur_pos);
json_object *
cper_arm_cache_tlb_error_to_ir(EFI_ARM_CACHE_ERROR_STRUCTURE *cache_tlb_error,
			       EFI_ARM_ERROR_INFORMATION_ENTRY *error_info);
json_object *cper_arm_bus_error_to_ir(EFI_ARM_BUS_ERROR_STRUCTURE *bus_error);
json_object *cper_arm_misc_register_array_to_ir(
	EFI_ARM_MISC_CONTEXT_REGISTER *misc_register);
void ir_arm_error_info_to_cper(json_object *error_info, FILE *out);
void ir_arm_context_info_to_cper(json_object *context_info, FILE *out);
void ir_arm_error_cache_tlb_info_to_cper(
	json_object *error_information,
	EFI_ARM_CACHE_ERROR_STRUCTURE *error_info_cper);
void ir_arm_error_bus_info_to_cper(json_object *error_information,
				   EFI_ARM_BUS_ERROR_STRUCTURE *error_info_cper);
void ir_arm_aarch32_gpr_to_cper(json_object *registers, FILE *out);
void ir_arm_aarch32_el1_to_cper(json_object *registers, FILE *out);
void ir_arm_aarch32_el2_to_cper(json_object *registers, FILE *out);
void ir_arm_aarch32_secure_to_cper(json_object *registers, FILE *out);
void ir_arm_aarch64_gpr_to_cper(json_object *registers, FILE *out);
void ir_arm_aarch64_el1_to_cper(json_object *registers, FILE *out);
void ir_arm_aarch64_el2_to_cper(json_object *registers, FILE *out);
void ir_arm_aarch64_el3_to_cper(json_object *registers, FILE *out);
void ir_arm_misc_registers_to_cper(json_object *registers, FILE *out);
void ir_arm_unknown_register_to_cper(json_object *registers, FILE *out);

//Converts the given processor-generic CPER section into JSON IR.
json_object *cper_section_arm_to_ir(void *section)
{
	EFI_ARM_ERROR_RECORD *record = (EFI_ARM_ERROR_RECORD *)section;
	json_object *section_ir = json_object_new_object();

	//Validation bits.
	json_object *validation = bitfield_to_ir(
		record->ValidFields, 4, ARM_ERROR_VALID_BITFIELD_NAMES);
	json_object_object_add(section_ir, "validationBits", validation);

	//Number of error info and context info structures, and length.
	json_object_object_add(section_ir, "errorInfoNum",
			       json_object_new_int(record->ErrInfoNum));
	json_object_object_add(section_ir, "contextInfoNum",
			       json_object_new_int(record->ContextInfoNum));
	json_object_object_add(section_ir, "sectionLength",
			       json_object_new_uint64(record->SectionLength));

	//Error affinity.
	json_object *error_affinity = json_object_new_object();
	json_object_object_add(error_affinity, "value",
			       json_object_new_int(record->ErrorAffinityLevel));
	json_object_object_add(
		error_affinity, "type",
		json_object_new_string(record->ErrorAffinityLevel < 4 ?
					       "Vendor Defined" :
					       "Reserved"));
	json_object_object_add(section_ir, "errorAffinity", error_affinity);

	//Processor ID (MPIDR_EL1) and chip ID (MIDR_EL1).
	json_object_object_add(section_ir, "mpidrEl1",
			       json_object_new_uint64(record->MPIDR_EL1));
	json_object_object_add(section_ir, "midrEl1",
			       json_object_new_uint64(record->MIDR_EL1));

	//Whether the processor is running, and the state of it if so.
	json_object_object_add(section_ir, "running",
			       json_object_new_boolean(record->RunningState &
						       0x1));
	if (!(record->RunningState >> 31)) {
		//Bit 32 of running state is on, so PSCI state information is included.
		//This can't be made human readable, as it is unknown whether this will be the pre-PSCI 1.0 format
		//or the newer Extended StateID format.
		json_object_object_add(
			section_ir, "psciState",
			json_object_new_uint64(record->PsciState));
	}

	//Processor error structures.
	json_object *error_info_array = json_object_new_array();
	EFI_ARM_ERROR_INFORMATION_ENTRY *cur_error =
		(EFI_ARM_ERROR_INFORMATION_ENTRY *)(record + 1);
	for (int i = 0; i < record->ErrInfoNum; i++) {
		json_object_array_add(error_info_array,
				      cper_arm_error_info_to_ir(cur_error));
		cur_error++;
	}
	json_object_object_add(section_ir, "errorInfo", error_info_array);

	//Processor context structures.
	//The current position is moved within the processing, as it is a dynamic size structure.
	uint8_t *cur_pos = (uint8_t *)cur_error;
	json_object *context_info_array = json_object_new_array();
	for (int i = 0; i < record->ContextInfoNum; i++) {
		EFI_ARM_CONTEXT_INFORMATION_HEADER *header =
			(EFI_ARM_CONTEXT_INFORMATION_HEADER *)cur_pos;
		json_object *processor_context =
			cper_arm_processor_context_to_ir(header,
							 (void **)&cur_pos);
		json_object_array_add(context_info_array, processor_context);
	}
	json_object_object_add(section_ir, "contextInfo", context_info_array);

	//Is there any vendor-specific information following?
	if (cur_pos < (uint8_t *)section + record->SectionLength) {
		json_object *vendor_specific = json_object_new_object();
		size_t input_size =
			(uint8_t *)section + record->SectionLength - cur_pos;
		char *encoded = malloc(2 * input_size);
		size_t encoded_len = 0;
		if (!encoded) {
			printf("Failed to allocate encode output buffer. \n");
		} else {
			base64_encode((const char *)cur_pos, input_size,
				      encoded, &encoded_len, 0);
			json_object_object_add(vendor_specific, "data",
					       json_object_new_string_len(
						       encoded, encoded_len));
			free(encoded);

			json_object_object_add(section_ir, "vendorSpecificInfo",
					       vendor_specific);
		}
	}

	return section_ir;
}

//Converts a single ARM Process Error Information structure into JSON IR.
json_object *
cper_arm_error_info_to_ir(EFI_ARM_ERROR_INFORMATION_ENTRY *error_info)
{
	json_object *error_info_ir = json_object_new_object();

	//Version, length.
	json_object_object_add(error_info_ir, "version",
			       json_object_new_int(error_info->Version));
	json_object_object_add(error_info_ir, "length",
			       json_object_new_int(error_info->Length));

	//Validation bitfield.
	json_object *validation =
		bitfield_to_ir(error_info->ValidationBits, 5,
			       ARM_ERROR_INFO_ENTRY_VALID_BITFIELD_NAMES);
	json_object_object_add(error_info_ir, "validationBits", validation);

	//The type of error information in this log.
	json_object *error_type = integer_to_readable_pair(
		error_info->Type, 4, ARM_ERROR_INFO_ENTRY_INFO_TYPES_KEYS,
		ARM_ERROR_INFO_ENTRY_INFO_TYPES_VALUES, "Unknown (Reserved)");
	json_object_object_add(error_info_ir, "errorType", error_type);

	//Multiple error count.
	json_object *multiple_error = json_object_new_object();
	json_object_object_add(multiple_error, "value",
			       json_object_new_int(error_info->MultipleError));
	json_object_object_add(
		multiple_error, "type",
		json_object_new_string(error_info->MultipleError < 1 ?
					       "Single Error" :
					       "Multiple Errors"));
	json_object_object_add(error_info_ir, "multipleError", multiple_error);

	//Flags.
	json_object *flags = bitfield_to_ir(error_info->Flags, 4,
					    ARM_ERROR_INFO_ENTRY_FLAGS_NAMES);
	json_object_object_add(error_info_ir, "flags", flags);

	//Error information, split by type.
	json_object *error_subinfo = NULL;
	switch (error_info->Type) {
	case ARM_ERROR_INFORMATION_TYPE_CACHE: //Cache
	case ARM_ERROR_INFORMATION_TYPE_TLB:   //TLB
		error_subinfo = cper_arm_cache_tlb_error_to_ir(
			(EFI_ARM_CACHE_ERROR_STRUCTURE *)&error_info
				->ErrorInformation,
			error_info);
		break;
	case ARM_ERROR_INFORMATION_TYPE_BUS: //Bus
		error_subinfo = cper_arm_bus_error_to_ir(
			(EFI_ARM_BUS_ERROR_STRUCTURE *)&error_info
				->ErrorInformation);
		break;

	default:
		//Unknown/microarch, so can't be made readable. Simply dump as a uint64 data object.
		error_subinfo = json_object_new_object();
		json_object_object_add(
			error_subinfo, "data",
			json_object_new_uint64(
				error_info->ErrorInformation.Value));
		break;
	}
	json_object_object_add(error_info_ir, "errorInformation",
			       error_subinfo);

	//Virtual fault address, physical fault address.
	json_object_object_add(
		error_info_ir, "virtualFaultAddress",
		json_object_new_uint64(error_info->VirtualFaultAddress));
	json_object_object_add(
		error_info_ir, "physicalFaultAddress",
		json_object_new_uint64(error_info->PhysicalFaultAddress));

	return error_info_ir;
}

//Converts a single ARM cache/TLB error information structure into JSON IR format.
json_object *
cper_arm_cache_tlb_error_to_ir(EFI_ARM_CACHE_ERROR_STRUCTURE *cache_tlb_error,
			       EFI_ARM_ERROR_INFORMATION_ENTRY *error_info)
{
	json_object *cache_tlb_error_ir = json_object_new_object();

	//Validation bitfield.
	json_object *validation =
		bitfield_to_ir(cache_tlb_error->ValidationBits, 7,
			       ARM_CACHE_TLB_ERROR_VALID_BITFIELD_NAMES);
	json_object_object_add(cache_tlb_error_ir, "validationBits",
			       validation);

	//Transaction type.
	json_object *transaction_type = integer_to_readable_pair(
		cache_tlb_error->TransactionType, 3,
		ARM_ERROR_TRANSACTION_TYPES_KEYS,
		ARM_ERROR_TRANSACTION_TYPES_VALUES, "Unknown (Reserved)");
	json_object_object_add(cache_tlb_error_ir, "transactionType",
			       transaction_type);

	//Operation.
	json_object *operation;
	if (error_info->Type == 0) {
		//Cache operation.
		operation = integer_to_readable_pair(
			cache_tlb_error->Operation, 11,
			ARM_CACHE_BUS_OPERATION_TYPES_KEYS,
			ARM_CACHE_BUS_OPERATION_TYPES_VALUES,
			"Unknown (Reserved)");
	} else {
		//TLB operation.
		operation = integer_to_readable_pair(
			cache_tlb_error->Operation, 9,
			ARM_TLB_OPERATION_TYPES_KEYS,
			ARM_TLB_OPERATION_TYPES_VALUES, "Unknown (Reserved)");
	}
	json_object_object_add(cache_tlb_error_ir, "operation", operation);

	//Miscellaneous remaining fields.
	json_object_object_add(cache_tlb_error_ir, "level",
			       json_object_new_int(cache_tlb_error->Level));
	json_object_object_add(
		cache_tlb_error_ir, "processorContextCorrupt",
		json_object_new_boolean(
			cache_tlb_error->ProcessorContextCorrupt));
	json_object_object_add(
		cache_tlb_error_ir, "corrected",
		json_object_new_boolean(cache_tlb_error->Corrected));
	json_object_object_add(
		cache_tlb_error_ir, "precisePC",
		json_object_new_boolean(cache_tlb_error->PrecisePC));
	json_object_object_add(
		cache_tlb_error_ir, "restartablePC",
		json_object_new_boolean(cache_tlb_error->RestartablePC));
	return cache_tlb_error_ir;
}

//Converts a single ARM bus error information structure into JSON IR format.
json_object *cper_arm_bus_error_to_ir(EFI_ARM_BUS_ERROR_STRUCTURE *bus_error)
{
	json_object *bus_error_ir = json_object_new_object();

	//Validation bits.
	json_object *validation =
		bitfield_to_ir(bus_error->ValidationBits, 12,
			       ARM_BUS_ERROR_VALID_BITFIELD_NAMES);
	json_object_object_add(bus_error_ir, "validationBits", validation);

	//Transaction type.
	json_object *transaction_type = integer_to_readable_pair(
		bus_error->TransactionType, 3, ARM_ERROR_TRANSACTION_TYPES_KEYS,
		ARM_ERROR_TRANSACTION_TYPES_VALUES, "Unknown (Reserved)");
	json_object_object_add(bus_error_ir, "transactionType",
			       transaction_type);

	//Operation.
	json_object *operation = integer_to_readable_pair(
		bus_error->Operation, 7, ARM_CACHE_BUS_OPERATION_TYPES_KEYS,
		ARM_CACHE_BUS_OPERATION_TYPES_VALUES, "Unknown (Reserved)");
	json_object_object_add(bus_error_ir, "operation", operation);

	//Affinity level of bus error, + miscellaneous fields.
	json_object_object_add(bus_error_ir, "level",
			       json_object_new_int(bus_error->Level));
	json_object_object_add(
		bus_error_ir, "processorContextCorrupt",
		json_object_new_boolean(bus_error->ProcessorContextCorrupt));
	json_object_object_add(bus_error_ir, "corrected",
			       json_object_new_boolean(bus_error->Corrected));
	json_object_object_add(bus_error_ir, "precisePC",
			       json_object_new_boolean(bus_error->PrecisePC));
	json_object_object_add(
		bus_error_ir, "restartablePC",
		json_object_new_boolean(bus_error->RestartablePC));
	json_object_object_add(bus_error_ir, "timedOut",
			       json_object_new_boolean(bus_error->TimeOut));

	//Participation type.
	json_object *participation_type = integer_to_readable_pair(
		bus_error->ParticipationType, 4,
		ARM_BUS_PARTICIPATION_TYPES_KEYS,
		ARM_BUS_PARTICIPATION_TYPES_VALUES, "Unknown");
	json_object_object_add(bus_error_ir, "participationType",
			       participation_type);

	//Address space.
	json_object *address_space = integer_to_readable_pair(
		bus_error->AddressSpace, 3, ARM_BUS_ADDRESS_SPACE_TYPES_KEYS,
		ARM_BUS_ADDRESS_SPACE_TYPES_VALUES, "Unknown");
	json_object_object_add(bus_error_ir, "addressSpace", address_space);

	//Memory access attributes.
	//todo: find the specification of these in the ARM ARM
	json_object_object_add(
		bus_error_ir, "memoryAttributes",
		json_object_new_int(bus_error->MemoryAddressAttributes));

	//Access Mode
	json_object *access_mode = json_object_new_object();
	json_object_object_add(access_mode, "value",
			       json_object_new_int(bus_error->AccessMode));
	json_object_object_add(
		access_mode, "name",
		json_object_new_string(bus_error->AccessMode == 0 ? "Secure" :
								    "Normal"));
	json_object_object_add(bus_error_ir, "accessMode", access_mode);

	return bus_error_ir;
}

//Converts a single ARM processor context block into JSON IR.
json_object *
cper_arm_processor_context_to_ir(EFI_ARM_CONTEXT_INFORMATION_HEADER *header,
				 void **cur_pos)
{
	json_object *context_ir = json_object_new_object();

	//Version.
	json_object_object_add(context_ir, "version",
			       json_object_new_int(header->Version));

	//Add the context type.
	json_object *context_type = integer_to_readable_pair(
		header->RegisterContextType, 9,
		ARM_PROCESSOR_INFO_REGISTER_CONTEXT_TYPES_KEYS,
		ARM_PROCESSOR_INFO_REGISTER_CONTEXT_TYPES_VALUES,
		"Unknown (Reserved)");
	json_object_object_add(context_ir, "registerContextType", context_type);

	//Register array size (bytes).
	json_object_object_add(
		context_ir, "registerArraySize",
		json_object_new_uint64(header->RegisterArraySize));

	//The register array itself.
	*cur_pos = (void *)(header + 1);
	json_object *register_array = NULL;
	switch (header->RegisterContextType) {
	case EFI_ARM_CONTEXT_TYPE_AARCH32_GPR:
		register_array = uniform_struct_to_ir(
			(UINT32 *)cur_pos,
			sizeof(EFI_ARM_V8_AARCH32_GPR) / sizeof(UINT32),
			ARM_AARCH32_GPR_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH32_EL1:
		register_array = uniform_struct_to_ir(
			(UINT32 *)cur_pos,
			sizeof(EFI_ARM_AARCH32_EL1_CONTEXT_REGISTERS) /
				sizeof(UINT32),
			ARM_AARCH32_EL1_REGISTER_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH32_EL2:
		register_array = uniform_struct_to_ir(
			(UINT32 *)cur_pos,
			sizeof(EFI_ARM_AARCH32_EL2_CONTEXT_REGISTERS) /
				sizeof(UINT32),
			ARM_AARCH32_EL2_REGISTER_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH32_SECURE:
		register_array = uniform_struct_to_ir(
			(UINT32 *)cur_pos,
			sizeof(EFI_ARM_AARCH32_SECURE_CONTEXT_REGISTERS) /
				sizeof(UINT32),
			ARM_AARCH32_SECURE_REGISTER_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH64_GPR:
		register_array = uniform_struct64_to_ir(
			(UINT64 *)cur_pos,
			sizeof(EFI_ARM_V8_AARCH64_GPR) / sizeof(UINT64),
			ARM_AARCH64_GPR_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH64_EL1:
		register_array = uniform_struct64_to_ir(
			(UINT64 *)cur_pos,
			sizeof(EFI_ARM_AARCH64_EL1_CONTEXT_REGISTERS) /
				sizeof(UINT64),
			ARM_AARCH64_EL1_REGISTER_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH64_EL2:
		register_array = uniform_struct64_to_ir(
			(UINT64 *)cur_pos,
			sizeof(EFI_ARM_AARCH64_EL2_CONTEXT_REGISTERS) /
				sizeof(UINT64),
			ARM_AARCH64_EL2_REGISTER_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH64_EL3:
		register_array = uniform_struct64_to_ir(
			(UINT64 *)cur_pos,
			sizeof(EFI_ARM_AARCH64_EL3_CONTEXT_REGISTERS) /
				sizeof(UINT64),
			ARM_AARCH64_EL3_REGISTER_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_MISC:
		register_array = cper_arm_misc_register_array_to_ir(
			(EFI_ARM_MISC_CONTEXT_REGISTER *)cur_pos);
		break;
	default:
		//Unknown register array type, add as base64 data instead.
		register_array = json_object_new_object();
		char *encoded = malloc(2 * header->RegisterArraySize);
		size_t encoded_len = 0;
		if (!encoded) {
			printf("Failed to allocate encode output buffer. \n");
		} else {
			base64_encode((const char *)cur_pos,
				      header->RegisterArraySize, encoded,
				      &encoded_len, 0);
			json_object_object_add(register_array, "data",
					       json_object_new_string_len(
						       encoded, encoded_len));
			free(encoded);
		}
		break;
	}
	json_object_object_add(context_ir, "registerArray", register_array);

	//Set the current position to after the processor context structure.
	*cur_pos = (UINT8 *)(*cur_pos) + header->RegisterArraySize;

	return context_ir;
}

//Converts a single CPER ARM miscellaneous register array to JSON IR format.
json_object *
cper_arm_misc_register_array_to_ir(EFI_ARM_MISC_CONTEXT_REGISTER *misc_register)
{
	json_object *register_array = json_object_new_object();
	json_object *mrs_encoding = json_object_new_object();
	json_object_object_add(mrs_encoding, "op2",
			       json_object_new_uint64(misc_register->MrsOp2));
	json_object_object_add(mrs_encoding, "crm",
			       json_object_new_uint64(misc_register->MrsCrm));
	json_object_object_add(mrs_encoding, "crn",
			       json_object_new_uint64(misc_register->MrsCrn));
	json_object_object_add(mrs_encoding, "op1",
			       json_object_new_uint64(misc_register->MrsOp1));
	json_object_object_add(mrs_encoding, "o0",
			       json_object_new_uint64(misc_register->MrsO0));
	json_object_object_add(register_array, "mrsEncoding", mrs_encoding);
	json_object_object_add(register_array, "value",
			       json_object_new_uint64(misc_register->Value));

	return register_array;
}

//Converts a single CPER-JSON ARM error section into CPER binary, outputting to the given stream.
void ir_section_arm_to_cper(json_object *section, FILE *out)
{
	EFI_ARM_ERROR_RECORD *section_cper =
		(EFI_ARM_ERROR_RECORD *)calloc(1, sizeof(EFI_ARM_ERROR_RECORD));

	//Validation bits.
	section_cper->ValidFields = ir_to_bitfield(
		json_object_object_get(section, "validationBits"), 4,
		ARM_ERROR_VALID_BITFIELD_NAMES);

	//Count of error/context info structures.
	section_cper->ErrInfoNum = json_object_get_int(
		json_object_object_get(section, "errorInfoNum"));
	section_cper->ContextInfoNum = json_object_get_int(
		json_object_object_get(section, "contextInfoNum"));

	//Miscellaneous raw value fields.
	section_cper->SectionLength = json_object_get_uint64(
		json_object_object_get(section, "sectionLength"));
	section_cper->ErrorAffinityLevel = readable_pair_to_integer(
		json_object_object_get(section, "errorAffinity"));
	section_cper->MPIDR_EL1 = json_object_get_uint64(
		json_object_object_get(section, "mpidrEl1"));
	section_cper->MIDR_EL1 = json_object_get_uint64(
		json_object_object_get(section, "midrEl1"));
	section_cper->RunningState = json_object_get_boolean(
		json_object_object_get(section, "running"));

	//Optional PSCI state.
	json_object *psci_state = json_object_object_get(section, "psciState");
	if (psci_state != NULL) {
		section_cper->PsciState = json_object_get_uint64(psci_state);
	}

	//Flush header to stream.
	fwrite(section_cper, sizeof(EFI_ARM_ERROR_RECORD), 1, out);
	fflush(out);

	//Error info structure array.
	json_object *error_info = json_object_object_get(section, "errorInfo");
	for (int i = 0; i < section_cper->ErrInfoNum; i++) {
		ir_arm_error_info_to_cper(
			json_object_array_get_idx(error_info, i), out);
	}

	//Context info structure array.
	json_object *context_info =
		json_object_object_get(section, "contextInfo");
	for (int i = 0; i < section_cper->ContextInfoNum; i++) {
		ir_arm_context_info_to_cper(
			json_object_array_get_idx(context_info, i), out);
	}

	//Vendor specific error info.
	json_object *vendor_specific_info =
		json_object_object_get(section, "vendorSpecificInfo");
	if (vendor_specific_info != NULL) {
		json_object *vendor_info_string =
			json_object_object_get(vendor_specific_info, "data");
		int vendor_specific_len =
			json_object_get_string_len(vendor_info_string);
		char *decoded = malloc(vendor_specific_len);
		size_t decoded_len = 0;
		if (!decoded) {
			printf("Failed to allocate decode output buffer. \n");
		} else {
			base64_decode(
				json_object_get_string(vendor_info_string),
				vendor_specific_len, decoded, &decoded_len, 0);

			//Write out to file.
			fwrite(decoded, decoded_len, 1, out);
			fflush(out);
			free(decoded);
		}
	}

	//Free remaining resources.
	free(section_cper);
}

//Converts a single ARM error information structure into CPER binary, outputting to the given stream.
void ir_arm_error_info_to_cper(json_object *error_info, FILE *out)
{
	EFI_ARM_ERROR_INFORMATION_ENTRY error_info_cper;

	//Version, length.
	error_info_cper.Version = json_object_get_int(
		json_object_object_get(error_info, "version"));
	error_info_cper.Length = json_object_get_int(
		json_object_object_get(error_info, "length"));

	//Validation bits.
	error_info_cper.ValidationBits = ir_to_bitfield(
		json_object_object_get(error_info, "validationBits"), 5,
		ARM_ERROR_INFO_ENTRY_VALID_BITFIELD_NAMES);

	//Type, multiple error.
	error_info_cper.Type = (UINT8)readable_pair_to_integer(
		json_object_object_get(error_info, "type"));
	error_info_cper.MultipleError = (UINT16)readable_pair_to_integer(
		json_object_object_get(error_info, "multipleError"));

	//Flags object.
	error_info_cper.Flags = (UINT8)ir_to_bitfield(
		json_object_object_get(error_info, "flags"), 4,
		ARM_ERROR_INFO_ENTRY_FLAGS_NAMES);

	//Error information.
	json_object *error_info_information =
		json_object_object_get(error_info, "errorInformation");
	switch (error_info_cper.Type) {
	case ARM_ERROR_INFORMATION_TYPE_CACHE:
	case ARM_ERROR_INFORMATION_TYPE_TLB:
		ir_arm_error_cache_tlb_info_to_cper(
			error_info_information,
			&error_info_cper.ErrorInformation.CacheError);
		break;

	case ARM_ERROR_INFORMATION_TYPE_BUS:
		ir_arm_error_bus_info_to_cper(
			error_info_information,
			&error_info_cper.ErrorInformation.BusError);
		break;

	default:
		//Unknown error information type.
		error_info_cper.ErrorInformation.Value = json_object_get_uint64(
			json_object_object_get(error_info_information, "data"));
		break;
	}

	//Virtual/physical fault address.
	error_info_cper.VirtualFaultAddress = json_object_get_uint64(
		json_object_object_get(error_info, "virtualFaultAddress"));
	error_info_cper.PhysicalFaultAddress = json_object_get_uint64(
		json_object_object_get(error_info, "physicalFaultAddress"));

	//Write out to stream.
	fwrite(&error_info_cper, sizeof(EFI_ARM_ERROR_INFORMATION_ENTRY), 1,
	       out);
	fflush(out);
}

//Converts a single ARM cache/TLB error information structure into a CPER structure.
void ir_arm_error_cache_tlb_info_to_cper(
	json_object *error_information,
	EFI_ARM_CACHE_ERROR_STRUCTURE *error_info_cper)
{
	//Validation bits.
	error_info_cper->ValidationBits = ir_to_bitfield(
		json_object_object_get(error_information, "validationBits"), 7,
		ARM_CACHE_TLB_ERROR_VALID_BITFIELD_NAMES);

	//Miscellaneous value fields.
	error_info_cper->TransactionType = readable_pair_to_integer(
		json_object_object_get(error_information, "transactionType"));
	error_info_cper->Operation = readable_pair_to_integer(
		json_object_object_get(error_information, "operation"));
	error_info_cper->Level = json_object_get_uint64(
		json_object_object_get(error_information, "level"));
	error_info_cper->ProcessorContextCorrupt = json_object_get_boolean(
		json_object_object_get(error_information,
				       "processorContextCorrupt"));
	error_info_cper->Corrected = json_object_get_boolean(
		json_object_object_get(error_information, "corrected"));
	error_info_cper->PrecisePC = json_object_get_boolean(
		json_object_object_get(error_information, "precisePC"));
	error_info_cper->RestartablePC = json_object_get_boolean(
		json_object_object_get(error_information, "restartablePC"));
	error_info_cper->Reserved = 0;
}

//Converts a single ARM bus error information structure into a CPER structure.
void ir_arm_error_bus_info_to_cper(json_object *error_information,
				   EFI_ARM_BUS_ERROR_STRUCTURE *error_info_cper)
{
	//Validation bits.
	error_info_cper->ValidationBits = ir_to_bitfield(
		json_object_object_get(error_information, "validationBits"), 7,
		ARM_BUS_ERROR_VALID_BITFIELD_NAMES);

	//Miscellaneous value fields.
	error_info_cper->TransactionType = readable_pair_to_integer(
		json_object_object_get(error_information, "transactionType"));
	error_info_cper->Operation = readable_pair_to_integer(
		json_object_object_get(error_information, "operation"));
	error_info_cper->Level = json_object_get_uint64(
		json_object_object_get(error_information, "level"));
	error_info_cper->ProcessorContextCorrupt = json_object_get_boolean(
		json_object_object_get(error_information,
				       "processorContextCorrupt"));
	error_info_cper->Corrected = json_object_get_boolean(
		json_object_object_get(error_information, "corrected"));
	error_info_cper->PrecisePC = json_object_get_boolean(
		json_object_object_get(error_information, "precisePC"));
	error_info_cper->RestartablePC = json_object_get_boolean(
		json_object_object_get(error_information, "restartablePC"));
	error_info_cper->ParticipationType = readable_pair_to_integer(
		json_object_object_get(error_information, "participationType"));
	error_info_cper->AddressSpace = readable_pair_to_integer(
		json_object_object_get(error_information, "addressSpace"));
	error_info_cper->AccessMode = readable_pair_to_integer(
		json_object_object_get(error_information, "accessMode"));
	error_info_cper->MemoryAddressAttributes = json_object_get_uint64(
		json_object_object_get(error_information, "memoryAttributes"));
	error_info_cper->Reserved = 0;
}

//Converts a single ARM context information structure into CPER binary, outputting to the given stream.
void ir_arm_context_info_to_cper(json_object *context_info, FILE *out)
{
	EFI_ARM_CONTEXT_INFORMATION_HEADER info_header;

	//Version, array size, context type.
	info_header.Version = json_object_get_int(
		json_object_object_get(context_info, "version"));
	info_header.RegisterArraySize = json_object_get_int(
		json_object_object_get(context_info, "registerArraySize"));
	info_header.RegisterContextType = readable_pair_to_integer(
		json_object_object_get(context_info, "registerContextType"));

	//Flush to stream, write the register array itself.
	fwrite(&info_header, sizeof(EFI_ARM_CONTEXT_INFORMATION_HEADER), 1,
	       out);
	fflush(out);

	json_object *register_array =
		json_object_object_get(context_info, "registerArray");
	switch (info_header.RegisterContextType) {
	case EFI_ARM_CONTEXT_TYPE_AARCH32_GPR:
		ir_arm_aarch32_gpr_to_cper(register_array, out);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH32_EL1:
		ir_arm_aarch32_el1_to_cper(register_array, out);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH32_EL2:
		ir_arm_aarch32_el2_to_cper(register_array, out);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH32_SECURE:
		ir_arm_aarch32_secure_to_cper(register_array, out);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH64_GPR:
		ir_arm_aarch64_gpr_to_cper(register_array, out);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH64_EL1:
		ir_arm_aarch64_el1_to_cper(register_array, out);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH64_EL2:
		ir_arm_aarch64_el2_to_cper(register_array, out);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH64_EL3:
		ir_arm_aarch64_el3_to_cper(register_array, out);
		break;
	case EFI_ARM_CONTEXT_TYPE_MISC:
		ir_arm_misc_registers_to_cper(register_array, out);
		break;
	default:
		//Unknown register structure.
		ir_arm_unknown_register_to_cper(register_array, out);
		break;
	}
}

//Converts a single AARCH32 GPR CPER-JSON object to CPER binary, outputting to the given stream.
void ir_arm_aarch32_gpr_to_cper(json_object *registers, FILE *out)
{
	//Get uniform register array.
	EFI_ARM_V8_AARCH32_GPR reg_array;
	ir_to_uniform_struct(registers, (UINT32 *)&reg_array,
			     sizeof(EFI_ARM_V8_AARCH32_GPR) / sizeof(UINT32),
			     ARM_AARCH32_GPR_NAMES);

	//Flush to stream.
	fwrite(&reg_array, sizeof(reg_array), 1, out);
	fflush(out);
}

//Converts a single AARCH32 EL1 register set CPER-JSON object to CPER binary, outputting to the given stream.
void ir_arm_aarch32_el1_to_cper(json_object *registers, FILE *out)
{
	//Get uniform register array.
	EFI_ARM_AARCH32_EL1_CONTEXT_REGISTERS reg_array;
	ir_to_uniform_struct(registers, (UINT32 *)&reg_array,
			     sizeof(EFI_ARM_AARCH32_EL1_CONTEXT_REGISTERS) /
				     sizeof(UINT32),
			     ARM_AARCH32_EL1_REGISTER_NAMES);

	//Flush to stream.
	fwrite(&reg_array, sizeof(reg_array), 1, out);
	fflush(out);
}

//Converts a single AARCH32 EL2 register set CPER-JSON object to CPER binary, outputting to the given stream.
void ir_arm_aarch32_el2_to_cper(json_object *registers, FILE *out)
{
	//Get uniform register array.
	EFI_ARM_AARCH32_EL2_CONTEXT_REGISTERS reg_array;
	ir_to_uniform_struct(registers, (UINT32 *)&reg_array,
			     sizeof(EFI_ARM_AARCH32_EL2_CONTEXT_REGISTERS) /
				     sizeof(UINT32),
			     ARM_AARCH32_EL2_REGISTER_NAMES);

	//Flush to stream.
	fwrite(&reg_array, sizeof(reg_array), 1, out);
	fflush(out);
}

//Converts a single AARCH32 secure register set CPER-JSON object to CPER binary, outputting to the given stream.
void ir_arm_aarch32_secure_to_cper(json_object *registers, FILE *out)
{
	//Get uniform register array.
	EFI_ARM_AARCH32_SECURE_CONTEXT_REGISTERS reg_array;
	ir_to_uniform_struct(registers, (UINT32 *)&reg_array,
			     sizeof(EFI_ARM_AARCH32_SECURE_CONTEXT_REGISTERS) /
				     sizeof(UINT32),
			     ARM_AARCH32_SECURE_REGISTER_NAMES);

	//Flush to stream.
	fwrite(&reg_array, sizeof(reg_array), 1, out);
	fflush(out);
}

//Converts a single AARCH64 GPR CPER-JSON object to CPER binary, outputting to the given stream.
void ir_arm_aarch64_gpr_to_cper(json_object *registers, FILE *out)
{
	//Get uniform register array.
	EFI_ARM_V8_AARCH64_GPR reg_array;
	ir_to_uniform_struct64(registers, (UINT64 *)&reg_array,
			       sizeof(EFI_ARM_V8_AARCH64_GPR) / sizeof(UINT64),
			       ARM_AARCH64_GPR_NAMES);

	//Flush to stream.
	fwrite(&reg_array, sizeof(reg_array), 1, out);
	fflush(out);
}

//Converts a single AARCH64 EL1 register set CPER-JSON object to CPER binary, outputting to the given stream.
void ir_arm_aarch64_el1_to_cper(json_object *registers, FILE *out)
{
	//Get uniform register array.
	EFI_ARM_AARCH64_EL1_CONTEXT_REGISTERS reg_array;
	ir_to_uniform_struct64(registers, (UINT64 *)&reg_array,
			       sizeof(EFI_ARM_AARCH64_EL1_CONTEXT_REGISTERS) /
				       sizeof(UINT64),
			       ARM_AARCH64_EL1_REGISTER_NAMES);

	//Flush to stream.
	fwrite(&reg_array, sizeof(reg_array), 1, out);
	fflush(out);
}

//Converts a single AARCH64 EL2 register set CPER-JSON object to CPER binary, outputting to the given stream.
void ir_arm_aarch64_el2_to_cper(json_object *registers, FILE *out)
{
	//Get uniform register array.
	EFI_ARM_AARCH64_EL2_CONTEXT_REGISTERS reg_array;
	ir_to_uniform_struct64(registers, (UINT64 *)&reg_array,
			       sizeof(EFI_ARM_AARCH64_EL2_CONTEXT_REGISTERS) /
				       sizeof(UINT64),
			       ARM_AARCH64_EL2_REGISTER_NAMES);

	//Flush to stream.
	fwrite(&reg_array, sizeof(reg_array), 1, out);
	fflush(out);
}

//Converts a single AARCH64 EL3 register set CPER-JSON object to CPER binary, outputting to the given stream.
void ir_arm_aarch64_el3_to_cper(json_object *registers, FILE *out)
{
	//Get uniform register array.
	EFI_ARM_AARCH64_EL3_CONTEXT_REGISTERS reg_array;
	ir_to_uniform_struct64(registers, (UINT64 *)&reg_array,
			       sizeof(EFI_ARM_AARCH64_EL3_CONTEXT_REGISTERS) /
				       sizeof(UINT64),
			       ARM_AARCH64_EL3_REGISTER_NAMES);

	//Flush to stream.
	fwrite(&reg_array, sizeof(reg_array), 1, out);
	fflush(out);
}

//Converts a single ARM miscellaneous register set CPER-JSON object to CPER binary, outputting to the given stream.
void ir_arm_misc_registers_to_cper(json_object *registers, FILE *out)
{
	EFI_ARM_MISC_CONTEXT_REGISTER reg_array;

	//MRS encoding information.
	json_object *mrs_encoding =
		json_object_object_get(registers, "mrsEncoding");
	reg_array.MrsOp2 = json_object_get_uint64(
		json_object_object_get(mrs_encoding, "op2"));
	reg_array.MrsCrm = json_object_get_uint64(
		json_object_object_get(mrs_encoding, "crm"));
	reg_array.MrsCrn = json_object_get_uint64(
		json_object_object_get(mrs_encoding, "crn"));
	reg_array.MrsOp1 = json_object_get_uint64(
		json_object_object_get(mrs_encoding, "op1"));
	reg_array.MrsO0 = json_object_get_uint64(
		json_object_object_get(mrs_encoding, "o0"));

	//Actual register value.
	reg_array.Value = json_object_get_uint64(
		json_object_object_get(registers, "value"));

	//Flush to stream.
	fwrite(&reg_array, sizeof(reg_array), 1, out);
	fflush(out);
}

//Converts a single ARM unknown register CPER-JSON object to CPER binary, outputting to the given stream.
void ir_arm_unknown_register_to_cper(json_object *registers, FILE *out)
{
	//Get base64 represented data.
	json_object *encoded = json_object_object_get(registers, "data");
	char *decoded = malloc(json_object_get_string_len(encoded));
	size_t decoded_len = 0;
	if (!decoded) {
		printf("Failed to allocate decode output buffer. \n");
	} else {
		base64_decode(json_object_get_string(encoded),
			      json_object_get_string_len(encoded), decoded,
			      &decoded_len, 0);

		//Flush out to stream.
		fwrite(&decoded, decoded_len, 1, out);
		fflush(out);
		free(decoded);
	}
}
