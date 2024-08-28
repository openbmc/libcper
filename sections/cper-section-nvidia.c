/**
 * Describes functions for converting NVIDIA CPER sections from binary and JSON format
 * into an intermediate format.
 **/

#include <stdio.h>
#include <string.h>
#include <json.h>
#include "../edk/Cper.h"
#include "../cper-utils.h"
#include "cper-section-nvidia.h"

//Converts a single NVIDIA CPER section into JSON IR.
json_object *cper_section_nvidia_to_ir(void *section)
{
	EFI_NVIDIA_ERROR_DATA *nvidia_error = (EFI_NVIDIA_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Signature.
	json_object_object_add(section_ir, "signature",
			       json_object_new_string(nvidia_error->Signature));

	//Fields.
	json_object_object_add(section_ir, "errorType",
			       json_object_new_int(nvidia_error->ErrorType));
	json_object_object_add(
		section_ir, "errorInstance",
		json_object_new_int(nvidia_error->ErrorInstance));
	json_object_object_add(section_ir, "severity",
			       json_object_new_int(nvidia_error->Severity));
	json_object_object_add(section_ir, "socket",
			       json_object_new_int(nvidia_error->Socket));
	json_object_object_add(section_ir, "numberRegs",
			       json_object_new_int(nvidia_error->NumberRegs));
	json_object_object_add(
		section_ir, "instanceBase",
		json_object_new_uint64(nvidia_error->InstanceBase));

	// Registers (Address Value pairs).
	json_object *regarr = json_object_new_array();
	UINT64 *regPtr = &nvidia_error->InstanceBase;
	for (int i = 0; i < nvidia_error->NumberRegs; i++) {
		json_object *reg = json_object_new_object();
		json_object_object_add(reg, "address",
				       json_object_new_uint64(*++regPtr));
		json_object_object_add(reg, "value",
				       json_object_new_uint64(*++regPtr));
		json_object_array_add(regarr, reg);
	}
	json_object_object_add(section_ir, "registers", regarr);

	return section_ir;
}

//Converts a single NVIDIA CPER-JSON section into CPER binary, outputting to the given stream.
void ir_section_nvidia_to_cper(json_object *section, FILE *out)
{
	json_object *regarr = json_object_object_get(section, "registers");
	int numRegs = json_object_array_length(regarr);

	size_t section_sz =
		sizeof(EFI_NVIDIA_ERROR_DATA) + (numRegs * 2 * sizeof(UINT64));
	EFI_NVIDIA_ERROR_DATA *section_cper =
		(EFI_NVIDIA_ERROR_DATA *)calloc(1, section_sz);

	//Signature.
	strncpy(section_cper->Signature,
		json_object_get_string(
			json_object_object_get(section, "signature")),
		sizeof(section_cper->Signature) - 1);
	section_cper->Signature[sizeof(section_cper->Signature) - 1] = '\0';

	//Fields.
	section_cper->ErrorType = json_object_get_int(
		json_object_object_get(section, "errorType"));
	section_cper->ErrorInstance = json_object_get_int(
		json_object_object_get(section, "errorInstance"));
	section_cper->Severity = json_object_get_int(
		json_object_object_get(section, "severity"));
	section_cper->Socket =
		json_object_get_int(json_object_object_get(section, "socket"));
	section_cper->NumberRegs = json_object_get_int(
		json_object_object_get(section, "numberRegs"));
	section_cper->InstanceBase = json_object_get_uint64(
		json_object_object_get(section, "instanceBase"));

	// Registers (Address Value pairs).
	UINT64 *regPtr = &section_cper->InstanceBase;
	for (int i = 0; i < numRegs; i++) {
		json_object *reg = json_object_array_get_idx(regarr, i);
		*++regPtr = json_object_get_uint64(
			json_object_object_get(reg, "address"));
		*++regPtr = json_object_get_uint64(
			json_object_object_get(reg, "value"));
	}

	//Write to stream, free resources.
	fwrite(section_cper, section_sz, 1, out);
	fflush(out);
	free(section_cper);
}
