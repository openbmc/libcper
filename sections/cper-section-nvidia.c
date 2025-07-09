/**
 * Describes functions for converting NVIDIA CPER sections from binary and JSON format
 * into an intermediate format.
 **/

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <json.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-nvidia.h>
#include <libcper/log.h>
#include <string.h>

void parse_cmet_info(EFI_NVIDIA_REGISTER_DATA *regPtr, UINT8 NumberRegs,
		     size_t size, json_object *section_ir)
{
	json_object *regarr = json_object_new_array();
	for (int i = 0; i < NumberRegs; i++, regPtr++) {
		json_object *reg = NULL;
		if (sizeof(EFI_NVIDIA_ERROR_DATA) +
			    i * sizeof(EFI_NVIDIA_REGISTER_DATA) <
		    size) {
			reg = json_object_new_object();
			add_int_hex_64(reg, "ChannelAddress", regPtr->Address);
			add_int(reg, "ErrorCount", regPtr->CmetInfo.ErrorCount);
			add_bool(reg, "ChannelEnabled",
				 regPtr->CmetInfo.ChannelEnabled);
			add_bool(reg, "ChannelIsSpare",
				 regPtr->CmetInfo.ChannelIsSpare);
			add_dict(reg, "DisabledReason",
				 regPtr->CmetInfo.DisabledReason,
				 channel_disable_reason_dict,
				 channel_disable_reason_dict_size);
		} else {
			reg = json_object_new_null();
		}

		json_object_array_add(regarr, reg);
	}

	json_object_object_add(section_ir, "CMETInfo", regarr);
}

void parse_fwerror(EFI_NVIDIA_REGISTER_DATA *regPtr, UINT8 NumberRegs,
		   size_t size, json_object *section_ir)
{
	(void)NumberRegs;
	json_object *fwinfo;
	if (sizeof(EFI_NVIDIA_ERROR_DATA) + sizeof(EFI_NVIDIA_FWERROR) > size) {
		fwinfo = json_object_new_null();
	} else {
		fwinfo = json_object_new_object();
		EFI_NVIDIA_FWERROR *fwerror = (EFI_NVIDIA_FWERROR *)regPtr;
		add_untrusted_string(fwinfo, "initiating_firmware",
				     fwerror->initiating_firmware,
				     sizeof(fwerror->initiating_firmware));
		add_int_hex_64(fwinfo, "task_checkpoint",
			       fwerror->task_checkpoint);
		add_int_hex_64(fwinfo, "mb1_error_code",
			       fwerror->mb1_error_code);
		add_untrusted_string(fwinfo, "mb1_version_string",
				     fwerror->mb1_version_string,
				     sizeof(fwerror->mb1_version_string));
		add_int_hex_64(fwinfo, "bad_pages_retired_mask",
			       fwerror->bad_pages_retired_mask);
		add_int_hex_64(fwinfo, "training_or_alias_check_retired_mask",
			       fwerror->training_or_alias_check_retired_mask);
	}

	json_object_object_add(section_ir, "FWErrorInfo", fwinfo);
}

void parse_registers(EFI_NVIDIA_REGISTER_DATA *regPtr, UINT8 NumberRegs,
		     size_t size, json_object *section_ir)
{
	// Registers (Address Value pairs).
	json_object *regarr = json_object_new_array();
	for (int i = 0; i < NumberRegs; i++, regPtr++) {
		json_object *reg = NULL;
		if (sizeof(EFI_NVIDIA_ERROR_DATA) +
			    i * sizeof(EFI_NVIDIA_REGISTER_DATA) <
		    size) {
			reg = json_object_new_object();
			json_object_object_add(
				reg, "address",
				json_object_new_uint64(regPtr->Address));
			json_object_object_add(
				reg, "value",
				json_object_new_uint64(regPtr->Value));
		} else {
			reg = json_object_new_null();
		}

		json_object_array_add(regarr, reg);
	}
	json_object_object_add(section_ir, "registers", regarr);
}

typedef struct {
	const char *ip_signature;
	void (*callback)(EFI_NVIDIA_REGISTER_DATA *, UINT8, size_t,
			 json_object *);
} NV_SECTION_CALLBACKS;

NV_SECTION_CALLBACKS section_handlers[] = {
	{ "CMET-INFO\0", &parse_cmet_info },
	{ "FWERROR\0", &parse_fwerror },
	{ "", &parse_registers },
};

//Converts a single NVIDIA CPER section into JSON IR.
json_object *cper_section_nvidia_to_ir(const UINT8 *section, UINT32 size,
				       char **desc_string)
{
	*desc_string = malloc(SECTION_DESC_STRING_SIZE);
	char *property_desc = malloc(EFI_ERROR_DESCRIPTION_STRING_LEN);

	if (size < sizeof(EFI_NVIDIA_ERROR_DATA)) {
		free(property_desc);
		*desc_string = NULL;
		return NULL;
	}

	EFI_NVIDIA_ERROR_DATA *nvidia_error = (EFI_NVIDIA_ERROR_DATA *)section;

	json_object *section_ir = json_object_new_object();

	const char *signature = nvidia_error->Signature;
	add_untrusted_string(section_ir, "signature", signature,
			     strlen(signature));

	json_object *severity = json_object_new_object();
	json_object_object_add(severity, "code",
			       json_object_new_uint64(nvidia_error->Severity));
	const char *severity_name = severity_to_string(nvidia_error->Severity);
	json_object_object_add(severity, "name",
			       json_object_new_string(severity_name));
	int outstr_len = 0;
	outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
			      "A %s %s NVIDIA Error occurred", severity_name,
			      signature);
	if (outstr_len < 0) {
		cper_print_log(
			"Error: Could not write to description string\n");
	} else if (outstr_len > SECTION_DESC_STRING_SIZE) {
		cper_print_log("Error: Description string truncated: %s\n",
			       *desc_string);
	}
	json_object_object_add(section_ir, "severity", severity);

	json_object_object_add(section_ir, "errorType",
			       json_object_new_int(nvidia_error->ErrorType));
	json_object_object_add(
		section_ir, "errorInstance",
		json_object_new_int(nvidia_error->ErrorInstance));
	json_object_object_add(section_ir, "socket",
			       json_object_new_int(nvidia_error->Socket));

	outstr_len = snprintf(property_desc, EFI_ERROR_DESCRIPTION_STRING_LEN,
			      " on CPU %d", nvidia_error->Socket);
	if (outstr_len < 0) {
		cper_print_log("Error: Could not write to property string\n");
	} else if (outstr_len > EFI_ERROR_DESCRIPTION_STRING_LEN) {
		cper_print_log("Error: Property string truncated: %s\n",
			       property_desc);
	}

	int property_desc_len = strlen(property_desc);
	strncat(*desc_string, property_desc, SECTION_DESC_STRING_SIZE - strlen(*desc_string) - 1);
	// We still want to get as much info as possible, just warn about truncation
	if (property_desc_len + strlen(*desc_string) >=
	    SECTION_DESC_STRING_SIZE) {
		cper_print_log("Error: Description string truncated: %s\n",
			       *desc_string);
	}
	free(property_desc);

	json_object_object_add(section_ir, "registerCount",
			       json_object_new_int(nvidia_error->NumberRegs));
	json_object_object_add(
		section_ir, "instanceBase",
		json_object_new_uint64(nvidia_error->InstanceBase));

	for (long unsigned int i = 0;
	     i < sizeof(section_handlers) / sizeof(section_handlers[0]); i++) {
		const char *ip_signature = section_handlers[i].ip_signature;
		if (strncmp(nvidia_error->Signature, ip_signature,
			    strlen(ip_signature)) == 0) {
			section_handlers[i].callback(&nvidia_error->Register[0],
						     nvidia_error->NumberRegs,
						     size, section_ir);
			break;
		}
	}
	return section_ir;
}

//Converts a single NVIDIA CPER-JSON section into CPER binary, outputting to the given stream.
void ir_section_nvidia_to_cper(json_object *section, FILE *out)
{
	json_object *regarr = json_object_object_get(section, "registers");
	int numRegs = json_object_array_length(regarr);

	size_t section_sz = offsetof(EFI_NVIDIA_ERROR_DATA, Register) +
			    numRegs * sizeof(EFI_NVIDIA_REGISTER_DATA);
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
	json_object *severity = json_object_object_get(section, "severity");
	section_cper->Severity = (UINT8)json_object_get_uint64(
		json_object_object_get(severity, "code"));
	section_cper->Socket =
		json_object_get_int(json_object_object_get(section, "socket"));
	section_cper->NumberRegs = json_object_get_int(
		json_object_object_get(section, "registerCount"));
	section_cper->InstanceBase = json_object_get_uint64(
		json_object_object_get(section, "instanceBase"));

	// Registers (Address Value pairs).
	EFI_NVIDIA_REGISTER_DATA *regPtr = section_cper->Register;
	for (int i = 0; i < numRegs; i++, regPtr++) {
		json_object *reg = json_object_array_get_idx(regarr, i);
		regPtr->Address = json_object_get_uint64(
			json_object_object_get(reg, "address"));
		regPtr->Value = json_object_get_uint64(
			json_object_object_get(reg, "value"));
	}

	//Write to stream, free resources.
	fwrite(section_cper, section_sz, 1, out);
	fflush(out);
	free(section_cper);
}
