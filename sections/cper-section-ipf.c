/**
 * Describes functions for converting Intel IPF CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <json.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-ipf.h>
#include <libcper/log.h>
#include <string.h>

json_object *cper_ipf_mod_error_read_array(EFI_IPF_MOD_ERROR_INFO **cur_error,
					   int num_to_read);
json_object *cper_ipf_mod_error_to_ir(EFI_IPF_MOD_ERROR_INFO *mod_error);

//Converts a single Intel IPF error CPER section into JSON IR.
json_object *cper_section_ipf_to_ir(const UINT8 *section, UINT32 size,
				    char **desc_string)
{
	int outstr_len = 0;
	*desc_string = NULL;
	if (size < sizeof(EFI_IPF_ERROR_INFO_HEADER)) {
		cper_print_log("Error: IPF section too small\n");
		return NULL;
	}

	*desc_string = calloc(1, SECTION_DESC_STRING_SIZE);
	if (*desc_string == NULL) {
		cper_print_log("Error: Failed to allocate IPF desc string\n");
		return NULL;
	}
	outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
			      "An IPF Error occurred");
	if (outstr_len < 0) {
		cper_print_log(
			"Error: Could not write to IPF description string\n");
	} else if (outstr_len > SECTION_DESC_STRING_SIZE) {
		cper_print_log("Error: IPF description string truncated\n");
	}

	EFI_IPF_ERROR_INFO_HEADER *ipf_error =
		(EFI_IPF_ERROR_INFO_HEADER *)section;
	json_object *section_ir = json_object_new_object();

	//Validation bits.
	json_object *validation = json_object_new_object();
	json_object_object_add(validation, "errorMapValid",
			       json_object_new_boolean(
				       ipf_error->ValidBits.ProcErrorMapValid));
	json_object_object_add(validation, "stateParameterValid",
			       json_object_new_boolean(
				       ipf_error->ValidBits.ProcErrorMapValid));
	json_object_object_add(
		validation, "crLIDValid",
		json_object_new_boolean(ipf_error->ValidBits.ProcCrLidValid));
	json_object_object_add(
		validation, "psiStaticStructValid",
		json_object_new_boolean(
			ipf_error->ValidBits.PsiStaticStructValid));
	json_object_object_add(
		validation, "cpuInfoValid",
		json_object_new_boolean(ipf_error->ValidBits.CpuIdInfoValid));
	json_object_object_add(section_ir, "validationBits", validation);

	//Numbers of various variable length segments.
	add_uint(section_ir, "cacheCheckNum", ipf_error->ValidBits.CacheCheckNum);
	add_uint(section_ir, "tlbCheckNum", ipf_error->ValidBits.TlbCheckNum);
	add_uint(section_ir, "busCheckNum", ipf_error->ValidBits.BusCheckNum);
	add_uint(section_ir, "regFileCheckNum", ipf_error->ValidBits.RegFileCheckNum);
	add_uint(section_ir, "msCheckNum", ipf_error->ValidBits.MsCheckNum);

	//Process error map, state params/CR LID.
	add_uint(section_ir, "procErrorMap", ipf_error->ProcErrorMap);
	add_uint(section_ir, "procStateParameter", ipf_error->ProcStateParameter);
	add_uint(section_ir, "procCRLID", ipf_error->ProcCrLid);

	//Read cache, TLB, bus, register file, MS errors.
	EFI_IPF_MOD_ERROR_INFO *cur_error =
		(EFI_IPF_MOD_ERROR_INFO *)(ipf_error + 1);
	json_object_object_add(section_ir, "cacheErrors",
			       cper_ipf_mod_error_read_array(
				       &cur_error,
				       ipf_error->ValidBits.CacheCheckNum));
	json_object_object_add(section_ir, "tlbErrors",
			       cper_ipf_mod_error_read_array(
				       &cur_error,
				       ipf_error->ValidBits.TlbCheckNum));
	json_object_object_add(section_ir, "busErrors",
			       cper_ipf_mod_error_read_array(
				       &cur_error,
				       ipf_error->ValidBits.BusCheckNum));
	json_object_object_add(section_ir, "regFileErrors",
			       cper_ipf_mod_error_read_array(
				       &cur_error,
				       ipf_error->ValidBits.RegFileCheckNum));
	json_object_object_add(
		section_ir, "msErrors",
		cper_ipf_mod_error_read_array(&cur_error,
					      ipf_error->ValidBits.MsCheckNum));

	//CPU ID information.
	EFI_IPF_CPU_INFO *cpu_info = (EFI_IPF_CPU_INFO *)cur_error;
	//stretch: find out how this is represented

	//Processor static information.
	EFI_IPF_PSI_STATIC *psi_static = (EFI_IPF_PSI_STATIC *)(cpu_info + 1);
	json_object *psi_static_ir = json_object_new_object();

	//PSI validation bits.
	json_object *psi_validation =
		bitfield_to_ir(psi_static->ValidBits, 6,
			       IPF_PSI_STATIC_INFO_VALID_BITFIELD_NAMES);
	json_object_object_add(psi_static_ir, "validationBits", psi_validation);

	//PSI minimal state save info.
	//stretch: structure min save state area as in Intel Itanium Architecture Software Developer's Manual.

	//BRs, CRs, ARs, RRs, FRs.
	json_object_object_add(psi_static_ir, "brs",
			       uint64_array_to_ir_array(psi_static->Brs, 8));
	json_object_object_add(psi_static_ir, "crs",
			       uint64_array_to_ir_array(psi_static->Crs, 128));
	json_object_object_add(psi_static_ir, "ars",
			       uint64_array_to_ir_array(psi_static->Ars, 128));
	json_object_object_add(psi_static_ir, "rrs",
			       uint64_array_to_ir_array(psi_static->Rrs, 8));
	json_object_object_add(psi_static_ir, "frs",
			       uint64_array_to_ir_array(psi_static->Frs, 256));
	json_object_object_add(section_ir, "psiStaticInfo", psi_static_ir);

	return section_ir;
}

//Reads a continuous stream of CPER IPF mod errors beginning from the given pointer, for n entries.
//Returns an array containing all read entries as JSON IR.
json_object *cper_ipf_mod_error_read_array(EFI_IPF_MOD_ERROR_INFO **cur_error,
					   int num_to_read)
{
	json_object *error_array = json_object_new_array();
	for (int i = 0; i < num_to_read; i++) {
		json_object_array_add(error_array,
				      cper_ipf_mod_error_to_ir(*cur_error));
		*cur_error = *cur_error + 1;
	}

	return error_array;
}

//Converts a single CPER IPF mod error info structure into JSON IR.
json_object *cper_ipf_mod_error_to_ir(EFI_IPF_MOD_ERROR_INFO *mod_error)
{
	json_object *mod_error_ir = json_object_new_object();

	//Validation bits.
	json_object *validation = bitfield_to_ir(
		mod_error->ValidBits, 5, IPF_MOD_ERROR_VALID_BITFIELD_NAMES);
	json_object_object_add(mod_error_ir, "validationBits", validation);

	//Numeric fields.
	add_uint(mod_error_ir, "modCheckInfo", mod_error->ModCheckInfo);
	add_uint(mod_error_ir, "modTargetID", mod_error->ModTargetId);
	add_uint(mod_error_ir, "modRequestorID", mod_error->ModRequestorId);
	add_uint(mod_error_ir, "modResponderID", mod_error->ModResponderId);
	add_uint(mod_error_ir, "modPreciseIP", mod_error->ModPreciseIp);

	return mod_error_ir;
}
