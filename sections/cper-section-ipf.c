/**
 * Describes functions for converting Intel IPF CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <json.h>
#include "../edk/Cper.h"
#include "../cper-utils.h"
#include "cper-section-ipf.h"

json_object *cper_ipf_mod_error_read_array(EFI_IPF_MOD_ERROR_INFO **cur_error,
					   int num_to_read);
json_object *cper_ipf_mod_error_to_ir(EFI_IPF_MOD_ERROR_INFO *mod_error);

//Converts a single Intel IPF error CPER section into JSON IR.
json_object *cper_section_ipf_to_ir(void *section)
{
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
	json_object_object_add(
		section_ir, "cacheCheckNum",
		json_object_new_uint64(ipf_error->ValidBits.CacheCheckNum));
	json_object_object_add(
		section_ir, "tlbCheckNum",
		json_object_new_uint64(ipf_error->ValidBits.TlbCheckNum));
	json_object_object_add(
		section_ir, "busCheckNum",
		json_object_new_uint64(ipf_error->ValidBits.BusCheckNum));
	json_object_object_add(
		section_ir, "regFileCheckNum",
		json_object_new_uint64(ipf_error->ValidBits.RegFileCheckNum));
	json_object_object_add(
		section_ir, "msCheckNum",
		json_object_new_uint64(ipf_error->ValidBits.MsCheckNum));

	//Process error map, state params/CR LID.
	json_object_object_add(section_ir, "procErrorMap",
			       json_object_new_uint64(ipf_error->ProcErrorMap));
	json_object_object_add(
		section_ir, "procStateParameter",
		json_object_new_uint64(ipf_error->ProcStateParameter));
	json_object_object_add(section_ir, "procCRLID",
			       json_object_new_uint64(ipf_error->ProcCrLid));

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
	json_object_object_add(mod_error_ir, "modCheckInfo",
			       json_object_new_uint64(mod_error->ModCheckInfo));
	json_object_object_add(mod_error_ir, "modTargetID",
			       json_object_new_uint64(mod_error->ModTargetId));
	json_object_object_add(
		mod_error_ir, "modRequestorID",
		json_object_new_uint64(mod_error->ModRequestorId));
	json_object_object_add(
		mod_error_ir, "modResponderID",
		json_object_new_uint64(mod_error->ModResponderId));
	json_object_object_add(mod_error_ir, "modPreciseIP",
			       json_object_new_uint64(mod_error->ModPreciseIp));

	return mod_error_ir;
}
