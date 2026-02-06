/**
 * Describes functions for converting ARM CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <assert.h>
#include <inttypes.h>
#include <json.h>
#include <libcper/base64.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-arm.h>
#include <libcper/log.h>
#include <stdio.h>
#include <string.h>

//Private pre-definitions.
json_object *
cper_arm_error_info_to_ir(EFI_ARM_ERROR_INFORMATION_ENTRY *error_info,
			  char **err_info_desc_i);
json_object *
cper_arm_processor_context_to_ir(EFI_ARM_CONTEXT_INFORMATION_HEADER *header,
				 const UINT8 **cur_pos, UINT32 *remaining_size);
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
json_object *cper_section_arm_to_ir(const UINT8 *section, UINT32 size,
				    char **desc_string)
{
	*desc_string = NULL;
	if (size < sizeof(EFI_ARM_ERROR_RECORD)) {
		cper_print_log("Error: ARM section too small\n");
		return NULL;
	}

	*desc_string = calloc(1, SECTION_DESC_STRING_SIZE);
	if (*desc_string == NULL) {
		cper_print_log("Error: Failed to allocate ARM desc string\n");
		return NULL;
	}
	int outstr_len = 0;
	outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
			      "An ARM Processor Error occurred");
	if (outstr_len < 0) {
		cper_print_log(
			"Error: Could not write to ARM description string\n");
	} else if (outstr_len > SECTION_DESC_STRING_SIZE) {
		cper_print_log("Error: ARM description string truncated: %s\n",
			       *desc_string);
	}

	const UINT8 *cur_pos = section;
	UINT32 remaining_size = size;
	EFI_ARM_ERROR_RECORD *record = (EFI_ARM_ERROR_RECORD *)cur_pos;
	cur_pos += sizeof(EFI_ARM_ERROR_RECORD);
	remaining_size -= sizeof(EFI_ARM_ERROR_RECORD);
	json_object *section_ir = json_object_new_object();

	//Length of ValidationBits from spec
	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = record->ValidFields };

	//Number of error info and context info structures, and length.
	add_int(section_ir, "errorInfoNum", record->ErrInfoNum);
	add_int(section_ir, "contextInfoNum", record->ContextInfoNum);
	add_uint(section_ir, "sectionLength", record->SectionLength);

	//Error affinity.
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		json_object *error_affinity = json_object_new_object();
		add_int(error_affinity, "value", record->ErrorAffinityLevel);

		const char *error_affinity_type = "Reserved";
		if (record->ErrorAffinityLevel < 4) {
			error_affinity_type = "Vendor Defined";
		}

		add_string(error_affinity, "type", error_affinity_type);
		json_object_object_add(section_ir, "errorAffinity",
				       error_affinity);
	}

	//Processor ID (MPIDR_EL1) and chip ID (MIDR_EL1).
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		uint64_t mpidr_eli1 = record->MPIDR_EL1;
		uint64_t sock;
		add_uint(section_ir, "mpidrEl1", mpidr_eli1);

		//Arm Processor socket info dependes on mpidr_eli1
		sock = (mpidr_eli1 & ARM_SOCK_MASK) >> 32;
		add_uint(section_ir, "affinity3", sock);
		char *node_desc_str =
			calloc(1, EFI_ERROR_DESCRIPTION_STRING_LEN);
		outstr_len = snprintf(node_desc_str,
				      EFI_ERROR_DESCRIPTION_STRING_LEN,
				      " on CPU %" PRIu64, sock);
		if (outstr_len < 0) {
			cper_print_log(
				"Error: Could not write to node description string\n");
		} else if (outstr_len > EFI_ERROR_DESCRIPTION_STRING_LEN) {
			cper_print_log(
				"Error: Node description string truncated: %s\n",
				node_desc_str);
		} else {
			if (strlen(node_desc_str) + strlen(*desc_string) <
			    SECTION_DESC_STRING_SIZE) {
				strncat(*desc_string, node_desc_str,
					outstr_len);
			} else {
				cper_print_log(
					"Error: Node description string too long, not added to description string: %s\n",
					node_desc_str);
			}
		}
		free(node_desc_str);
	}

	add_uint(section_ir, "midrEl1", record->MIDR_EL1);

	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		//Whether the processor is running, and the state of it if so.
		add_bool(section_ir, "running", record->RunningState & 0x1);
	}
	if (!(record->RunningState >> 31)) {
		//Bit 32 of running state is on, so PSCI state information is included.
		//This can't be made human readable, as it is unknown whether this will be the pre-PSCI 1.0 format
		//or the newer Extended StateID format.
		add_uint(section_ir, "psciState", record->PsciState);
	}

	//Processor error structures.
	json_object *error_info_array = json_object_new_array();
	EFI_ARM_ERROR_INFORMATION_ENTRY *cur_error =
		(EFI_ARM_ERROR_INFORMATION_ENTRY *)(record + 1);
	if (remaining_size <
	    (record->ErrInfoNum * sizeof(EFI_ARM_ERROR_INFORMATION_ENTRY))) {
		json_object_put(error_info_array);
		json_object_put(section_ir);
		free(*desc_string);
		*desc_string = NULL;
		cper_print_log(
			"Invalid CPER file: Invalid processor error info num.\n");
		return NULL;
	}
	strncat(*desc_string, "; Error Type(s): {",
		EFI_ERROR_DESCRIPTION_STRING_LEN);
	char *err_info_desc_i =
		calloc(1, EFI_ERROR_INFORMATION_DESCRIPTION_STRING_LEN);
	size_t err_info_desc_i_len = 0;
	for (int i = 0; i < record->ErrInfoNum; i++) {
		json_object_array_add(
			error_info_array,
			cper_arm_error_info_to_ir(cur_error, &err_info_desc_i));
		err_info_desc_i_len = strlen(err_info_desc_i);
		if (err_info_desc_i_len > 0 &&
		    strlen(*desc_string) + err_info_desc_i_len <
			    SECTION_DESC_STRING_SIZE) {
			strncat(*desc_string, err_info_desc_i,
				SECTION_DESC_STRING_SIZE -
					strlen(*desc_string) - 1);
		} else {
			cper_print_log(
				"Error: Error info description string too long, not added to description string: %s\n",
				err_info_desc_i);
		}
		cur_error++;
		if (i == record->ErrInfoNum - 1) {
			if (strlen(*desc_string) + 2 <
			    SECTION_DESC_STRING_SIZE) {
				strncat(*desc_string, "}", 2);
			} else {
				cper_print_log(
					"Error: Description string too long, not added '}'to description string: %s\n",
					*desc_string);
			}
			break;
		}
		if (strlen(*desc_string) + 3 < SECTION_DESC_STRING_SIZE) {
			strncat(*desc_string, ", ", 3);
		} else {
			cper_print_log(
				"Error: Description string too long, not added ',' to description string: %s\n",
				*desc_string);
		}
	}
	free(err_info_desc_i);

	cur_pos += (UINT32)(record->ErrInfoNum *
			    sizeof(EFI_ARM_ERROR_INFORMATION_ENTRY));
	remaining_size -= (UINT32)(record->ErrInfoNum *
				   sizeof(EFI_ARM_ERROR_INFORMATION_ENTRY));

	json_object_object_add(section_ir, "errorInfo", error_info_array);

	//Processor context structures.
	//The current position is moved within the processing, as it is a dynamic size structure.
	json_object *context_info_array = json_object_new_array();
	for (int i = 0; i < record->ContextInfoNum; i++) {
		if (remaining_size <
		    sizeof(EFI_ARM_CONTEXT_INFORMATION_HEADER)) {
			json_object_put(context_info_array);
			json_object_put(section_ir);
			free(*desc_string);
			*desc_string = NULL;
			cper_print_log(
				"Invalid CPER file: Invalid processor context info num.\n");
			return NULL;
		}
		EFI_ARM_CONTEXT_INFORMATION_HEADER *header =
			(EFI_ARM_CONTEXT_INFORMATION_HEADER *)cur_pos;

		cur_pos += sizeof(EFI_ARM_CONTEXT_INFORMATION_HEADER);
		remaining_size -= sizeof(EFI_ARM_CONTEXT_INFORMATION_HEADER);
		json_object *processor_context =
			cper_arm_processor_context_to_ir(header, &cur_pos,
							 &remaining_size);
		if (processor_context == NULL) {
			json_object_put(context_info_array);
			json_object_put(section_ir);
			free(*desc_string);
			*desc_string = NULL;
			cper_print_log(
				"Invalid CPER file: Invalid processor context info num.\n");
			return NULL;
		}
		json_object_array_add(context_info_array, processor_context);
	}
	json_object_object_add(section_ir, "contextInfo", context_info_array);

	//Is there any vendor-specific information following?
	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		if (cur_pos < (uint8_t *)section + record->SectionLength) {
			json_object *vendor_specific = json_object_new_object();
			size_t input_size = (uint8_t *)section +
					    record->SectionLength - cur_pos;
			if (remaining_size < input_size) {
				json_object_put(vendor_specific);
				json_object_put(section_ir);
				free(*desc_string);
				*desc_string = NULL;
				cper_print_log(
					"Invalid CPER file: Invalid vendor-specific info length.\n");
				return NULL;
			}
			add_binary_base64(vendor_specific, "data", cur_pos,
					  input_size);

			json_object_object_add(section_ir, "vendorSpecificInfo",
					       vendor_specific);
		} else {
			cper_print_log(
				"vendorSpecificInfo is marked valid but not present in binary\n");
		}
	}

	return section_ir;
}

//Handle unknown error type
static void handle_unknown_error_type(char *err_info_desc,
				      size_t err_info_desc_buffer_len)
{
	const char *unknown_error_desc = "Unknown Error";
	if (strlen(unknown_error_desc) >= err_info_desc_buffer_len) {
		cper_print_log(
			"Error: Unknown error description string too long, not added to description string: %s\n",
			unknown_error_desc);
		return;
	}
	strncpy(err_info_desc, unknown_error_desc,
		strlen(unknown_error_desc) + 1);
}

//Converts a single ARM Process Error Information structure into JSON IR.
json_object *
cper_arm_error_info_to_ir(EFI_ARM_ERROR_INFORMATION_ENTRY *error_info,
			  char **err_info_desc_i)
{
	json_object *error_info_ir = json_object_new_object();
	int outstr_len = 0;

	//Version, length.
	add_int(error_info_ir, "version", error_info->Version);
	add_int(error_info_ir, "length", error_info->Length);

	//Validation bitfield.
	ValidationTypes ui16Type = { UINT_16T,
				     .value.ui16 = error_info->ValidationBits };

	//The type of error information in this log.
	json_object *error_type = integer_to_readable_pair(
		error_info->Type, 4, ARM_ERROR_INFO_ENTRY_INFO_TYPES_KEYS,
		ARM_ERROR_INFO_ENTRY_INFO_TYPES_VALUES, "Unknown (Reserved)");
	json_object_object_add(error_info_ir, "errorType", error_type);

	//Multiple error count.
	if (isvalid_prop_to_ir(&ui16Type, 0)) {
		json_object *multiple_error = json_object_new_object();
		add_int(multiple_error, "value", error_info->MultipleError);
		add_string(multiple_error, "type",
			   error_info->MultipleError < 1 ? "Single Error" :
							   "Multiple Errors");
		json_object_object_add(error_info_ir, "multipleError",
				       multiple_error);
	}

	//Flags.
	if (isvalid_prop_to_ir(&ui16Type, 1)) {
		json_object *flags = bitfield_to_ir(
			error_info->Flags, 4, ARM_ERROR_INFO_ENTRY_FLAGS_NAMES);
		json_object_object_add(error_info_ir, "flags", flags);
	}

	//Error information, split by type.
	if (isvalid_prop_to_ir(&ui16Type, 2)) {
		json_object *error_subinfo = NULL;
		switch (error_info->Type) {
		case ARM_ERROR_INFORMATION_TYPE_CACHE: //Cache
			error_subinfo = cper_arm_cache_tlb_error_to_ir(
				(EFI_ARM_CACHE_ERROR_STRUCTURE *)&error_info
					->ErrorInformation,
				error_info);
			const char *cache_error_desc = "Cache Error";
			if (strlen(cache_error_desc) >=
			    EFI_ERROR_INFORMATION_DESCRIPTION_STRING_LEN) {
				cper_print_log(
					"Error: Cache Error Description too long %s\n",
					cache_error_desc);
			} else {
				strncpy(*err_info_desc_i, cache_error_desc,
					strlen(cache_error_desc) + 1);
			}
			break;
		case ARM_ERROR_INFORMATION_TYPE_TLB: //TLB
			error_subinfo = cper_arm_cache_tlb_error_to_ir(
				(EFI_ARM_CACHE_ERROR_STRUCTURE *)&error_info
					->ErrorInformation,
				error_info);
			const char *tlb_error_desc = "TLB Error";
			if (strlen(tlb_error_desc) >=
			    EFI_ERROR_INFORMATION_DESCRIPTION_STRING_LEN) {
				cper_print_log(
					"Error: TLB Error Description too long %s\n",
					tlb_error_desc);
			} else {
				strncpy(*err_info_desc_i, tlb_error_desc,
					strlen(tlb_error_desc) + 1);
			}
			break;
		case ARM_ERROR_INFORMATION_TYPE_BUS: //Bus
			error_subinfo = cper_arm_bus_error_to_ir(
				(EFI_ARM_BUS_ERROR_STRUCTURE *)&error_info
					->ErrorInformation);
			const char *bus_error_desc = "Bus Error";
			if (strlen(bus_error_desc) >=
			    EFI_ERROR_INFORMATION_DESCRIPTION_STRING_LEN) {
				cper_print_log(
					"Error: Bus Error Description too long %s\n",
					bus_error_desc);
			} else {
				strncpy(*err_info_desc_i, bus_error_desc,
					strlen(bus_error_desc) + 1);
			}
			break;

		default:
			//Unknown/microarch, will not support.
			handle_unknown_error_type(
				*err_info_desc_i,
				EFI_ERROR_INFORMATION_DESCRIPTION_STRING_LEN);
			break;
		}
		if (error_subinfo != NULL) {
			json_object_object_add(error_info_ir,
					       "errorInformation",
					       error_subinfo);
		}
	} else {
		handle_unknown_error_type(
			*err_info_desc_i,
			EFI_ERROR_INFORMATION_DESCRIPTION_STRING_LEN);
	}

	//Virtual fault address, physical fault address.
	char *fault_address_desc = calloc(1, EFI_ERROR_DESCRIPTION_STRING_LEN);
	if (isvalid_prop_to_ir(&ui16Type, 3)) {
		outstr_len = snprintf(fault_address_desc,
				      EFI_ERROR_DESCRIPTION_STRING_LEN,
				      " at Virtual Addr=0x%llX",
				      error_info->VirtualFaultAddress);
		if (outstr_len < 0) {
			cper_print_log(
				"Error: Could not write to fault address description string\n");
		} else if (outstr_len > EFI_ERROR_DESCRIPTION_STRING_LEN) {
			cper_print_log(
				"Error: Virtual fault address description string truncated: %s\n",
				fault_address_desc);
		} else {
			if (strlen(fault_address_desc) +
				    strlen(*err_info_desc_i) <
			    EFI_ERROR_INFORMATION_DESCRIPTION_STRING_LEN) {
				strncat(*err_info_desc_i, fault_address_desc,
					outstr_len);
			} else {
				cper_print_log(
					"Error: Virtual fault address description string too long, not added to description string: %s\n",
					fault_address_desc);
			}
		}
		add_uint(error_info_ir, "virtualFaultAddress",
			 error_info->VirtualFaultAddress);
	}
	if (isvalid_prop_to_ir(&ui16Type, 4)) {
		outstr_len = snprintf(fault_address_desc,
				      EFI_ERROR_DESCRIPTION_STRING_LEN,
				      " Physical Addr=0x%llX",
				      error_info->PhysicalFaultAddress);
		if (outstr_len < 0) {
			cper_print_log(
				"Error: Could not write to physical fault address description string\n");
		} else if (outstr_len > EFI_ERROR_DESCRIPTION_STRING_LEN) {
			cper_print_log(
				"Error: Physical fault address description string truncated: %s\n",
				fault_address_desc);
		} else {
			if (strlen(fault_address_desc) +
				    strlen(*err_info_desc_i) <
			    EFI_ERROR_INFORMATION_DESCRIPTION_STRING_LEN) {
				strncat(*err_info_desc_i, fault_address_desc,
					outstr_len);
			} else {
				cper_print_log(
					"Error:Physical fault address description string too long, not added to description string: %s\n",
					fault_address_desc);
			}
		}
		add_uint(error_info_ir, "physicalFaultAddress",
			 error_info->PhysicalFaultAddress);
	}

	free(fault_address_desc);

	return error_info_ir;
}

//Converts a single ARM cache/TLB error information structure into JSON IR format.
json_object *
cper_arm_cache_tlb_error_to_ir(EFI_ARM_CACHE_ERROR_STRUCTURE *cache_tlb_error,
			       EFI_ARM_ERROR_INFORMATION_ENTRY *error_info)
{
	json_object *cache_tlb_error_ir = json_object_new_object();
	json_object *cache_tlb_prop = json_object_new_object();
	char *cache_tlb_propname;

	//Validation bitfield.
	ValidationTypes ui64Type = {
		UINT_64T, .value.ui64 = cache_tlb_error->ValidationBits
	};

	//Transaction type.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *transaction_type = integer_to_readable_pair(
			cache_tlb_error->TransactionType, 3,
			ARM_ERROR_TRANSACTION_TYPES_KEYS,
			ARM_ERROR_TRANSACTION_TYPES_VALUES,
			"Unknown (Reserved)");
		json_object_object_add(cache_tlb_error_ir, "transactionType",
				       transaction_type);
	}

	//Operation.
	bool cacheErrorFlag = 1;
	if (error_info->Type == ARM_ERROR_INFORMATION_TYPE_CACHE) {
		cache_tlb_propname = "cacheError";
	} else {
		//TLB operation.
		cache_tlb_propname = "tlbError";
		cacheErrorFlag = 0;
	}

	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		json_object *operation;

		if (cacheErrorFlag) {
			//Cache operation.
			operation = integer_to_readable_pair(
				cache_tlb_error->Operation, 11,
				ARM_CACHE_BUS_OPERATION_TYPES_KEYS,
				ARM_CACHE_BUS_OPERATION_TYPES_VALUES,
				"Unknown (Reserved)");
		} else {
			operation = integer_to_readable_pair(
				cache_tlb_error->Operation, 9,
				ARM_TLB_OPERATION_TYPES_KEYS,
				ARM_TLB_OPERATION_TYPES_VALUES,
				"Unknown (Reserved)");
		}
		json_object_object_add(cache_tlb_error_ir, "operation",
				       operation);
	}

	//Miscellaneous remaining fields.
	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		add_int(cache_tlb_error_ir, "level", cache_tlb_error->Level);
	}
	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		add_bool(cache_tlb_error_ir, "processorContextCorrupt",
			 cache_tlb_error->ProcessorContextCorrupt);
	}
	if (isvalid_prop_to_ir(&ui64Type, 4)) {
		add_bool(cache_tlb_error_ir, "corrected",
			 cache_tlb_error->Corrected);
	}
	if (isvalid_prop_to_ir(&ui64Type, 5)) {
		add_bool(cache_tlb_error_ir, "precisePC",
			 cache_tlb_error->PrecisePC);
	}
	if (isvalid_prop_to_ir(&ui64Type, 6)) {
		add_bool(cache_tlb_error_ir, "restartablePC",
			 cache_tlb_error->RestartablePC);
	}

	json_object_object_add(cache_tlb_prop, cache_tlb_propname,
			       cache_tlb_error_ir);

	return cache_tlb_prop;
}

//Converts a single ARM bus error information structure into JSON IR format.
json_object *cper_arm_bus_error_to_ir(EFI_ARM_BUS_ERROR_STRUCTURE *bus_error)
{
	json_object *bus_error_ir = json_object_new_object();
	json_object *bus_prop = json_object_new_object();
	char *bus_propname = "busError";

	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = bus_error->ValidationBits };

	//Transaction type.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *transaction_type = integer_to_readable_pair(
			bus_error->TransactionType, 3,
			ARM_ERROR_TRANSACTION_TYPES_KEYS,
			ARM_ERROR_TRANSACTION_TYPES_VALUES,
			"Unknown (Reserved)");
		json_object_object_add(bus_error_ir, "transactionType",
				       transaction_type);
	}

	//Operation.
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		json_object *operation = integer_to_readable_pair(
			bus_error->Operation, 7,
			ARM_CACHE_BUS_OPERATION_TYPES_KEYS,
			ARM_CACHE_BUS_OPERATION_TYPES_VALUES,
			"Unknown (Reserved)");
		json_object_object_add(bus_error_ir, "operation", operation);
	}

	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		//Affinity level of bus error, + miscellaneous fields.
		add_int(bus_error_ir, "level", bus_error->Level);
	}
	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		add_bool(bus_error_ir, "processorContextCorrupt",
			 bus_error->ProcessorContextCorrupt);
	}
	if (isvalid_prop_to_ir(&ui64Type, 4)) {
		add_bool(bus_error_ir, "corrected", bus_error->Corrected);
	}
	if (isvalid_prop_to_ir(&ui64Type, 5)) {
		add_bool(bus_error_ir, "precisePC", bus_error->PrecisePC);
	}
	if (isvalid_prop_to_ir(&ui64Type, 6)) {
		add_bool(bus_error_ir, "restartablePC",
			 bus_error->RestartablePC);
	}

	//Participation type.
	if (isvalid_prop_to_ir(&ui64Type, 7)) {
		json_object *participation_type = integer_to_readable_pair(
			bus_error->ParticipationType, 4,
			ARM_BUS_PARTICIPATION_TYPES_KEYS,
			ARM_BUS_PARTICIPATION_TYPES_VALUES, "Unknown");
		json_object_object_add(bus_error_ir, "participationType",
				       participation_type);
	}
	if (isvalid_prop_to_ir(&ui64Type, 8)) {
		add_bool(bus_error_ir, "timedOut", bus_error->TimeOut);
	}

	//Address space.
	if (isvalid_prop_to_ir(&ui64Type, 9)) {
		json_object *address_space = integer_to_readable_pair(
			bus_error->AddressSpace, 3,
			ARM_BUS_ADDRESS_SPACE_TYPES_KEYS,
			ARM_BUS_ADDRESS_SPACE_TYPES_VALUES, "Unknown");
		json_object_object_add(bus_error_ir, "addressSpace",
				       address_space);
	}

	//Memory access attributes.
	//todo: find the specification of these in the ARM ARM
	if (isvalid_prop_to_ir(&ui64Type, 10)) {
		add_int(bus_error_ir, "memoryAttributes",
			bus_error->MemoryAddressAttributes);
	}

	//Access Mode
	if (isvalid_prop_to_ir(&ui64Type, 8)) {
		json_object *access_mode = json_object_new_object();
		add_int(access_mode, "value", bus_error->AccessMode);
		add_string(access_mode, "name",
			   bus_error->AccessMode == 0 ? "Secure" : "Normal");
		json_object_object_add(bus_error_ir, "accessMode", access_mode);
	}
	json_object_object_add(bus_prop, bus_propname, bus_error_ir);

	return bus_prop;
}

//Converts a single ARM processor context block into JSON IR.
json_object *
cper_arm_processor_context_to_ir(EFI_ARM_CONTEXT_INFORMATION_HEADER *header,
				 const UINT8 **cur_pos, UINT32 *remaining_size)
{
	json_object *context_ir __attribute__((cleanup(free_json_object)));

	if (header->RegisterArraySize > *remaining_size) {
		cper_print_log(
			"Invalid CPER file: Invalid processor context info num.\n");
		return NULL;
	}

	context_ir = json_object_new_object();

	//Version.
	add_int(context_ir, "version", header->Version);

	//Add the context type.
	json_object *context_type = integer_to_readable_pair(
		header->RegisterContextType,
		ARM_PROCESSOR_INFO_REGISTER_CONTEXT_TYPES_COUNT,
		ARM_PROCESSOR_INFO_REGISTER_CONTEXT_TYPES_KEYS,
		ARM_PROCESSOR_INFO_REGISTER_CONTEXT_TYPES_VALUES,
		"Unknown (Reserved)");
	json_object_object_add(context_ir, "registerContextType", context_type);

	//Register array size (bytes).
	add_uint(context_ir, "registerArraySize", header->RegisterArraySize);

	//The register array itself.
	json_object *register_array = NULL;
	switch (header->RegisterContextType) {
	case EFI_ARM_CONTEXT_TYPE_AARCH32_GPR:
		if (*remaining_size < sizeof(EFI_ARM_V8_AARCH32_GPR)) {
			cper_print_log(
				"Invalid CPER file: Invalid processor context info num.\n");
			return NULL;
		}
		if (header->RegisterArraySize <
		    sizeof(EFI_ARM_V8_AARCH32_GPR)) {
			cper_print_log(
				"Invalid CPER file: Not enough bytes for aarch32 gpr\n");
			return NULL;
		}
		register_array = uniform_struct_to_ir(
			(UINT32 *)*cur_pos,
			sizeof(EFI_ARM_V8_AARCH32_GPR) / sizeof(UINT32),
			ARM_AARCH32_GPR_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH32_EL1:
		if (*remaining_size <
		    sizeof(EFI_ARM_AARCH32_EL1_CONTEXT_REGISTERS)) {
			cper_print_log(
				"Invalid CPER file: Invalid processor context info num.\n");
			return NULL;
		}
		if (header->RegisterArraySize <
		    sizeof(EFI_ARM_AARCH32_EL1_CONTEXT_REGISTERS)) {
			cper_print_log(
				"Invalid CPER file: Not enough bytes for aarch32 el1\n");
			return NULL;
		}
		register_array = uniform_struct_to_ir(
			(UINT32 *)*cur_pos,
			sizeof(EFI_ARM_AARCH32_EL1_CONTEXT_REGISTERS) /
				sizeof(UINT32),
			ARM_AARCH32_EL1_REGISTER_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH32_EL2:
		if (*remaining_size <
		    sizeof(EFI_ARM_AARCH32_EL2_CONTEXT_REGISTERS)) {
			cper_print_log(
				"Invalid CPER file: Invalid processor context info num.\n");
			return NULL;
		}
		if (header->RegisterArraySize <
		    sizeof(EFI_ARM_AARCH32_EL2_CONTEXT_REGISTERS)) {
			cper_print_log(
				"Invalid CPER file: Not enough bytes for aarch32 el2\n");
			return NULL;
		}
		register_array = uniform_struct_to_ir(
			(UINT32 *)*cur_pos,
			sizeof(EFI_ARM_AARCH32_EL2_CONTEXT_REGISTERS) /
				sizeof(UINT32),
			ARM_AARCH32_EL2_REGISTER_NAMES);

		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH32_SECURE:
		if (*remaining_size <
		    sizeof(EFI_ARM_AARCH32_SECURE_CONTEXT_REGISTERS)) {
			json_object_put(context_ir);
			cper_print_log(
				"Invalid CPER file: Invalid processor context info num.\n");
			return NULL;
		}
		if (header->RegisterArraySize <
		    sizeof(EFI_ARM_AARCH32_SECURE_CONTEXT_REGISTERS)) {
			cper_print_log(
				"Invalid CPER file: Not enough bytes for aarch32 secure\n");
			return NULL;
		}
		register_array = uniform_struct_to_ir(
			(UINT32 *)*cur_pos,
			sizeof(EFI_ARM_AARCH32_SECURE_CONTEXT_REGISTERS) /
				sizeof(UINT32),
			ARM_AARCH32_SECURE_REGISTER_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH64_GPR:
		if (*remaining_size < sizeof(EFI_ARM_V8_AARCH64_GPR)) {
			cper_print_log(
				"Invalid CPER file: Invalid processor context info num.\n");
			return NULL;
		}
		if (header->RegisterArraySize <
		    sizeof(EFI_ARM_V8_AARCH64_GPR)) {
			cper_print_log(
				"Invalid CPER file: Not enough bytes for aarch64 gpr\n");
			return NULL;
		}
		register_array = uniform_struct64_to_ir(
			(UINT64 *)*cur_pos,
			sizeof(EFI_ARM_V8_AARCH64_GPR) / sizeof(UINT64),
			ARM_AARCH64_GPR_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH64_EL1:
		if (*remaining_size <
		    sizeof(EFI_ARM_AARCH64_EL1_CONTEXT_REGISTERS)) {
			cper_print_log(
				"Invalid CPER file: Invalid processor context info num.\n");
			return NULL;
		}
		if (header->RegisterArraySize <
		    sizeof(EFI_ARM_AARCH64_EL1_CONTEXT_REGISTERS)) {
			cper_print_log(
				"Invalid CPER file: Not enough bytes for aarch64 el1\n");
			return NULL;
		}
		register_array = uniform_struct64_to_ir(
			(UINT64 *)*cur_pos,
			sizeof(EFI_ARM_AARCH64_EL1_CONTEXT_REGISTERS) /
				sizeof(UINT64),
			ARM_AARCH64_EL1_REGISTER_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH64_EL2:
		if (*remaining_size <
		    sizeof(EFI_ARM_AARCH64_EL2_CONTEXT_REGISTERS)) {
			cper_print_log(
				"Invalid CPER file: Invalid processor context info num.\n");
			return NULL;
		}
		if (header->RegisterArraySize <
		    sizeof(EFI_ARM_AARCH64_EL2_CONTEXT_REGISTERS)) {
			cper_print_log(
				"Invalid CPER file: Not enough bytes for aarch64 el2\n");
			return NULL;
		}
		register_array = uniform_struct64_to_ir(
			(UINT64 *)*cur_pos,
			sizeof(EFI_ARM_AARCH64_EL2_CONTEXT_REGISTERS) /
				sizeof(UINT64),
			ARM_AARCH64_EL2_REGISTER_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_AARCH64_EL3:
		if (*remaining_size <
		    sizeof(EFI_ARM_AARCH64_EL3_CONTEXT_REGISTERS)) {
			cper_print_log(
				"Invalid CPER file: Invalid processor context info num.\n");
			return NULL;
		}
		if (header->RegisterArraySize <
		    sizeof(EFI_ARM_AARCH64_EL3_CONTEXT_REGISTERS)) {
			cper_print_log(
				"Invalid CPER file: Not enough bytes for aarch64 el3\n");
			return NULL;
		}
		register_array = uniform_struct64_to_ir(
			(UINT64 *)*cur_pos,
			sizeof(EFI_ARM_AARCH64_EL3_CONTEXT_REGISTERS) /
				sizeof(UINT64),
			ARM_AARCH64_EL3_REGISTER_NAMES);
		break;
	case EFI_ARM_CONTEXT_TYPE_MISC:
		if (*remaining_size < sizeof(EFI_ARM_MISC_CONTEXT_REGISTER)) {
			cper_print_log(
				"Invalid CPER file: Invalid processor context info num.\n");
			return NULL;
		}
		if (header->RegisterArraySize <
		    sizeof(EFI_ARM_MISC_CONTEXT_REGISTER)) {
			cper_print_log(
				"Invalid CPER file: Not enough bytes for misc\n");
			return NULL;
		}
		register_array = cper_arm_misc_register_array_to_ir(
			(EFI_ARM_MISC_CONTEXT_REGISTER *)*cur_pos);
		break;
	default:
		if (*remaining_size < header->RegisterArraySize) {
			cper_print_log(
				"Invalid CPER file: Invalid processor context info num.\n");
			return NULL;
		}
		//Unknown register array type, add as base64 data instead.
		register_array = json_object_new_object();
		add_binary_base64(register_array, "data", *cur_pos,
				  header->RegisterArraySize);

		break;
	}
	json_object_object_add(context_ir, "registerArray", register_array);

	//Set the current position to after the processor context structure.
	*cur_pos = (UINT8 *)(*cur_pos) + header->RegisterArraySize;
	*remaining_size -= header->RegisterArraySize;

	return json_object_get(context_ir);
}

//Converts a single CPER ARM miscellaneous register array to JSON IR format.
json_object *
cper_arm_misc_register_array_to_ir(EFI_ARM_MISC_CONTEXT_REGISTER *misc_register)
{
	json_object *register_array = json_object_new_object();
	json_object *mrs_encoding = json_object_new_object();
	add_uint(mrs_encoding, "op2", misc_register->MrsOp2);
	add_uint(mrs_encoding, "crm", misc_register->MrsCrm);
	add_uint(mrs_encoding, "crn", misc_register->MrsCrn);
	add_uint(mrs_encoding, "op1", misc_register->MrsOp1);
	add_uint(mrs_encoding, "o0", misc_register->MrsO0);
	json_object_object_add(register_array, "mrsEncoding", mrs_encoding);
	add_uint(register_array, "value", misc_register->Value);

	return register_array;
}

//Converts a single CPER-JSON ARM error section into CPER binary, outputting to the given stream.
void ir_section_arm_to_cper(json_object *section, FILE *out)
{
	EFI_ARM_ERROR_RECORD section_cper;
	memset(&section_cper, 0, sizeof(section_cper));

	//Validation bits.
	struct json_object *obj = NULL;
	ValidationTypes u32Type = { UINT_32T, .value.ui32 = 0 };

	//Count of error/context info structures.
	section_cper.ErrInfoNum = json_object_get_int(
		json_object_object_get(section, "errorInfoNum"));
	section_cper.ContextInfoNum = json_object_get_int(
		json_object_object_get(section, "contextInfoNum"));

	//Miscellaneous raw value fields.
	section_cper.SectionLength = json_object_get_uint64(
		json_object_object_get(section, "sectionLength"));
	if (json_object_object_get_ex(section, "mpidrEl1", &obj)) {
		section_cper.MPIDR_EL1 = json_object_get_uint64(obj);
		add_to_valid_bitfield(&u32Type, 0);
	}
	if (json_object_object_get_ex(section, "errorAffinity", &obj)) {
		section_cper.ErrorAffinityLevel = readable_pair_to_integer(obj);
		add_to_valid_bitfield(&u32Type, 1);
	}
	section_cper.MIDR_EL1 = json_object_get_uint64(
		json_object_object_get(section, "midrEl1"));
	if (json_object_object_get_ex(section, "running", &obj)) {
		section_cper.RunningState = json_object_get_boolean(obj);
		add_to_valid_bitfield(&u32Type, 2);
	}

	//Optional PSCI state.
	json_object *psci_state = json_object_object_get(section, "psciState");
	if (psci_state != NULL) {
		section_cper.PsciState = json_object_get_uint64(psci_state);
	}

	//Validationbits for EFI_ARM_ERROR_RECORD should also consider vendorSpecificInfo
	bool vendorSpecificPresent =
		json_object_object_get_ex(section, "vendorSpecificInfo", &obj);
	json_object *vendor_specific_info = obj;
	if (vendorSpecificPresent) {
		add_to_valid_bitfield(&u32Type, 3);
	}

	section_cper.ValidFields = u32Type.value.ui32;

	//Flush header to stream.
	fwrite(&section_cper, sizeof(section_cper), 1, out);

	//Error info structure array.

	json_object *error_info = json_object_object_get(section, "errorInfo");
	for (int i = 0; i < section_cper.ErrInfoNum; i++) {
		ir_arm_error_info_to_cper(
			json_object_array_get_idx(error_info, i), out);
	}

	//Context info structure array.
	json_object *context_info =
		json_object_object_get(section, "contextInfo");
	for (int i = 0; i < section_cper.ContextInfoNum; i++) {
		ir_arm_context_info_to_cper(
			json_object_array_get_idx(context_info, i), out);
	}

	//Vendor specific error info.
	if (vendorSpecificPresent) {
		json_object *vendor_info_string =
			json_object_object_get(vendor_specific_info, "data");
		int vendor_specific_len =
			json_object_get_string_len(vendor_info_string);

		int32_t decoded_len = 0;

		UINT8 *decoded = base64_decode(
			json_object_get_string(vendor_info_string),
			vendor_specific_len, &decoded_len);

		//Write out to file.
		fwrite(decoded, decoded_len, 1, out);
		free(decoded);
	}

	fflush(out);
}

//Converts a single ARM error information structure into CPER binary, outputting to the given stream.
void ir_arm_error_info_to_cper(json_object *error_info, FILE *out)
{
	EFI_ARM_ERROR_INFORMATION_ENTRY error_info_cper;
	memset(&error_info_cper, 0, sizeof(error_info_cper));
	struct json_object *obj = NULL;
	ValidationTypes ui16Type = { UINT_16T, .value.ui16 = 0 };

	//Version, length.
	error_info_cper.Version = json_object_get_int(
		json_object_object_get(error_info, "version"));
	error_info_cper.Length = json_object_get_int(
		json_object_object_get(error_info, "length"));

	//Type
	if (json_object_object_get_ex(error_info, "errorType", &obj)) {
		error_info_cper.Type = readable_pair_to_integer(obj);
	} else {
		error_info_cper.Type = 0;
	}

	//multiple error.
	if (json_object_object_get_ex(error_info, "multipleError", &obj)) {
		error_info_cper.MultipleError =
			(UINT16)readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui16Type, 0);
	} else {
		error_info_cper.MultipleError = 0;
	}

	//Flags object.
	if (json_object_object_get_ex(error_info, "flags", &obj)) {
		error_info_cper.Flags = (UINT8)ir_to_bitfield(
			obj, 4, ARM_ERROR_INFO_ENTRY_FLAGS_NAMES);
		add_to_valid_bitfield(&ui16Type, 1);
	} else {
		error_info_cper.Flags = 0;
	}

	//Error information.
	if (json_object_object_get_ex(error_info, "errorInformation", &obj)) {
		json_object *error_info_information = obj;
		json_object *error_info_prop = NULL;
		switch (error_info_cper.Type) {
		case ARM_ERROR_INFORMATION_TYPE_CACHE:
			error_info_cper.ErrorInformation.Value = 0;
			error_info_prop = json_object_object_get(
				error_info_information, "cacheError");
			ir_arm_error_cache_tlb_info_to_cper(
				error_info_prop,
				&error_info_cper.ErrorInformation.CacheError);
			break;
		case ARM_ERROR_INFORMATION_TYPE_TLB:
			error_info_cper.ErrorInformation.Value = 0;
			error_info_prop = json_object_object_get(
				error_info_information, "tlbError");
			ir_arm_error_cache_tlb_info_to_cper(
				error_info_prop,
				&error_info_cper.ErrorInformation.CacheError);
			break;

		case ARM_ERROR_INFORMATION_TYPE_BUS:
			error_info_cper.ErrorInformation.Value = 0;
			error_info_prop = json_object_object_get(
				error_info_information, "busError");
			ir_arm_error_bus_info_to_cper(
				error_info_prop,
				&error_info_cper.ErrorInformation.BusError);
			break;

		default:
			//Unknown error information type.
			break;
		}
		add_to_valid_bitfield(&ui16Type, 2);
	}

	//Virtual/physical fault address.
	if (json_object_object_get_ex(error_info, "virtualFaultAddress",
				      &obj)) {
		error_info_cper.VirtualFaultAddress =
			json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui16Type, 3);
	} else {
		error_info_cper.VirtualFaultAddress = 0;
	}

	if (json_object_object_get_ex(error_info, "physicalFaultAddress",
				      &obj)) {
		error_info_cper.PhysicalFaultAddress =
			json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui16Type, 4);
	} else {
		error_info_cper.PhysicalFaultAddress = 0;
	}
	error_info_cper.ValidationBits = ui16Type.value.ui16;

	//Write out to stream.
	fwrite(&error_info_cper, sizeof(EFI_ARM_ERROR_INFORMATION_ENTRY), 1,
	       out);
}

//Converts a single ARM cache/TLB error information structure into a CPER structure.
void ir_arm_error_cache_tlb_info_to_cper(
	json_object *error_information,
	EFI_ARM_CACHE_ERROR_STRUCTURE *error_info_cper)
{
	// //Validation bits.
	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;

	//Miscellaneous value fields.
	if (json_object_object_get_ex(error_information, "transactionType",
				      &obj)) {
		error_info_cper->TransactionType =
			readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 0);
	}
	if (json_object_object_get_ex(error_information, "operation", &obj)) {
		error_info_cper->Operation = readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 1);
	}
	if (json_object_object_get_ex(error_information, "level", &obj)) {
		error_info_cper->Level = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 2);
	}
	if (json_object_object_get_ex(error_information,
				      "processorContextCorrupt", &obj)) {
		error_info_cper->ProcessorContextCorrupt =
			json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 3);
	}
	if (json_object_object_get_ex(error_information, "corrected", &obj)) {
		error_info_cper->Corrected = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 4);
	}
	if (json_object_object_get_ex(error_information, "precisePC", &obj)) {
		error_info_cper->PrecisePC = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 5);
	}
	if (json_object_object_get_ex(error_information, "restartablePC",
				      &obj)) {
		error_info_cper->RestartablePC = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 6);
	}
	error_info_cper->Reserved = 0;
	error_info_cper->ValidationBits = ui64Type.value.ui64;
}

//Converts a single ARM bus error information structure into a CPER structure.
void ir_arm_error_bus_info_to_cper(json_object *error_information,
				   EFI_ARM_BUS_ERROR_STRUCTURE *error_info_cper)
{
	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;

	//Miscellaneous value fields.
	if (json_object_object_get_ex(error_information, "transactionType",
				      &obj)) {
		error_info_cper->TransactionType =
			readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 0);
	} else {
		error_info_cper->TransactionType = 0;
	}
	if (json_object_object_get_ex(error_information, "operation", &obj)) {
		error_info_cper->Operation = readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 1);
	} else {
		error_info_cper->Operation = 0;
	}
	if (json_object_object_get_ex(error_information, "level", &obj)) {
		error_info_cper->Level = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 2);
	} else {
		error_info_cper->Level = 0;
	}
	if (json_object_object_get_ex(error_information,
				      "processorContextCorrupt", &obj)) {
		error_info_cper->ProcessorContextCorrupt =
			json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 3);
	} else {
		error_info_cper->ProcessorContextCorrupt = 0;
	}
	if (json_object_object_get_ex(error_information, "corrected", &obj)) {
		error_info_cper->Corrected = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 4);
	} else {
		error_info_cper->Corrected = 0;
	}
	if (json_object_object_get_ex(error_information, "precisePC", &obj)) {
		error_info_cper->PrecisePC = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 5);
	} else {
		error_info_cper->PrecisePC = 0;
	}
	if (json_object_object_get_ex(error_information, "restartablePC",
				      &obj)) {
		error_info_cper->RestartablePC = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 6);
	} else {
		error_info_cper->RestartablePC = 0;
	}
	if (json_object_object_get_ex(error_information, "participationType",
				      &obj)) {
		error_info_cper->ParticipationType =
			readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 7);
	} else {
		error_info_cper->ParticipationType = 0;
	}
	if (json_object_object_get_ex(error_information, "timedOut", &obj)) {
		error_info_cper->TimeOut = json_object_get_boolean(obj);
		add_to_valid_bitfield(&ui64Type, 8);
	} else {
		error_info_cper->TimeOut = 0;
	}
	if (json_object_object_get_ex(error_information, "addressSpace",
				      &obj)) {
		error_info_cper->AddressSpace = readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 9);
	} else {
		error_info_cper->AddressSpace = 0;
	}
	if (json_object_object_get_ex(error_information, "accessMode", &obj)) {
		error_info_cper->AccessMode = readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 11);
	} else {
		error_info_cper->AccessMode = 0;
	}
	if (json_object_object_get_ex(error_information, "memoryAttributes",
				      &obj)) {
		error_info_cper->MemoryAddressAttributes =
			json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 10);
	} else {
		error_info_cper->MemoryAddressAttributes = 0;
	}
	error_info_cper->Reserved = 0;
	error_info_cper->ValidationBits = ui64Type.value.ui64;
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

	int32_t decoded_len = 0;

	UINT8 *decoded = base64_decode(json_object_get_string(encoded),
				       json_object_get_string_len(encoded),
				       &decoded_len);

	if (decoded == NULL) {
		cper_print_log("Failed to allocate decode output buffer. \n");
	} else {
		//Flush out to stream.
		fwrite(&decoded, decoded_len, 1, out);
		fflush(out);
		free(decoded);
	}
}
