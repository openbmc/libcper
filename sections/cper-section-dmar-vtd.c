/**
 * Describes functions for converting VT-d specific DMAr CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <string.h>
#include <json.h>
#include "libbase64.h"
#include "../edk/Cper.h"
#include "../cper-utils.h"
#include "cper-section-dmar-vtd.h"

//Converts a single VT-d specific DMAr CPER section into JSON IR.
json_object *cper_section_dmar_vtd_to_ir(void *section)
{
	EFI_DIRECTED_IO_DMAR_ERROR_DATA *vtd_error =
		(EFI_DIRECTED_IO_DMAR_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Version, revision and OEM ID, as defined in the VT-d architecture.
	UINT64 oem_id = 0;
	for (int i = 0; i < 6; i++) {
		oem_id |= (UINT64)vtd_error->OemId[i] << (i * 8);
	}
	json_object_object_add(section_ir, "version",
			       json_object_new_int(vtd_error->Version));
	json_object_object_add(section_ir, "revision",
			       json_object_new_int(vtd_error->Revision));
	json_object_object_add(section_ir, "oemID",
			       json_object_new_uint64(oem_id));

	//Registers.
	json_object_object_add(section_ir, "capabilityRegister",
			       json_object_new_uint64(vtd_error->Capability));
	json_object_object_add(section_ir, "extendedCapabilityRegister",
			       json_object_new_uint64(vtd_error->CapabilityEx));
	json_object_object_add(
		section_ir, "globalCommandRegister",
		json_object_new_uint64(vtd_error->GlobalCommand));
	json_object_object_add(section_ir, "globalStatusRegister",
			       json_object_new_uint64(vtd_error->GlobalStatus));
	json_object_object_add(section_ir, "faultStatusRegister",
			       json_object_new_uint64(vtd_error->FaultStatus));

	//Fault record basic fields.
	json_object *fault_record_ir = json_object_new_object();
	EFI_VTD_FAULT_RECORD *fault_record =
		(EFI_VTD_FAULT_RECORD *)vtd_error->FaultRecord;
	json_object_object_add(
		fault_record_ir, "faultInformation",
		json_object_new_uint64(fault_record->FaultInformation));
	json_object_object_add(
		fault_record_ir, "sourceIdentifier",
		json_object_new_uint64(fault_record->SourceIdentifier));
	json_object_object_add(
		fault_record_ir, "privelegeModeRequested",
		json_object_new_boolean(fault_record->PrivelegeModeRequested));
	json_object_object_add(
		fault_record_ir, "executePermissionRequested",
		json_object_new_boolean(
			fault_record->ExecutePermissionRequested));
	json_object_object_add(
		fault_record_ir, "pasidPresent",
		json_object_new_boolean(fault_record->PasidPresent));
	json_object_object_add(
		fault_record_ir, "faultReason",
		json_object_new_uint64(fault_record->FaultReason));
	json_object_object_add(
		fault_record_ir, "pasidValue",
		json_object_new_uint64(fault_record->PasidValue));
	json_object_object_add(
		fault_record_ir, "addressType",
		json_object_new_uint64(fault_record->AddressType));

	//Fault record type.
	json_object *fault_record_type = integer_to_readable_pair(
		fault_record->Type, 2, VTD_FAULT_RECORD_TYPES_KEYS,
		VTD_FAULT_RECORD_TYPES_VALUES, "Unknown");
	json_object_object_add(fault_record_ir, "type", fault_record_type);
	json_object_object_add(section_ir, "faultRecord", fault_record_ir);

	//Root entry.
	char *encoded = malloc(2 * 16);
	size_t encoded_len = 0;
	if (!encoded) {
		printf("Failed to allocate encode output buffer. \n");
	} else {
		base64_encode((const char *)vtd_error->RootEntry, 16, encoded,
			      &encoded_len, 0);
		json_object_object_add(section_ir, "rootEntry",
				       json_object_new_string_len(encoded,
								  encoded_len));
		free(encoded);
	}

	//Context entry.
	encoded = malloc(2 * 16);
	encoded_len = 0;
	if (!encoded) {
		printf("Failed to allocate encode output buffer. \n");
	} else {
		base64_encode((const char *)vtd_error->ContextEntry, 16,
			      encoded, &encoded_len, 0);
		json_object_object_add(section_ir, "contextEntry",
				       json_object_new_string_len(encoded,
								  encoded_len));
		free(encoded);
	}

	//PTE entry for all page levels.
	json_object_object_add(section_ir, "pageTableEntry_Level6",
			       json_object_new_uint64(vtd_error->PteL6));
	json_object_object_add(section_ir, "pageTableEntry_Level5",
			       json_object_new_uint64(vtd_error->PteL5));
	json_object_object_add(section_ir, "pageTableEntry_Level4",
			       json_object_new_uint64(vtd_error->PteL4));
	json_object_object_add(section_ir, "pageTableEntry_Level3",
			       json_object_new_uint64(vtd_error->PteL3));
	json_object_object_add(section_ir, "pageTableEntry_Level2",
			       json_object_new_uint64(vtd_error->PteL2));
	json_object_object_add(section_ir, "pageTableEntry_Level1",
			       json_object_new_uint64(vtd_error->PteL1));

	return section_ir;
}

//Converts a single VT-d DMAR CPER-JSON segment into CPER binary, outputting to the given stream.
void ir_section_dmar_vtd_to_cper(json_object *section, FILE *out)
{
	EFI_DIRECTED_IO_DMAR_ERROR_DATA *section_cper =
		(EFI_DIRECTED_IO_DMAR_ERROR_DATA *)calloc(
			1, sizeof(EFI_DIRECTED_IO_DMAR_ERROR_DATA));

	//OEM ID.
	UINT64 oem_id = json_object_get_uint64(
		json_object_object_get(section, "oemID"));
	for (int i = 0; i < 6; i++) {
		section_cper->OemId[i] = (oem_id >> (i * 8)) & 0xFF;
	}

	//Registers & basic numeric fields.
	section_cper->Version = (UINT8)json_object_get_int(
		json_object_object_get(section, "version"));
	section_cper->Revision = (UINT8)json_object_get_int(
		json_object_object_get(section, "revision"));
	section_cper->Capability = json_object_get_uint64(
		json_object_object_get(section, "capabilityRegister"));
	section_cper->CapabilityEx = json_object_get_uint64(
		json_object_object_get(section, "extendedCapabilityRegister"));
	section_cper->GlobalCommand = json_object_get_uint64(
		json_object_object_get(section, "globalCommandRegister"));
	section_cper->GlobalStatus = json_object_get_uint64(
		json_object_object_get(section, "globalStatusRegister"));
	section_cper->FaultStatus = json_object_get_uint64(
		json_object_object_get(section, "faultStatusRegister"));

	//Fault record.
	json_object *fault_record =
		json_object_object_get(section, "faultRecord");
	EFI_VTD_FAULT_RECORD *fault_record_cper =
		(EFI_VTD_FAULT_RECORD *)section_cper->FaultRecord;
	fault_record_cper->FaultInformation = json_object_get_uint64(
		json_object_object_get(fault_record, "faultInformation"));
	fault_record_cper->SourceIdentifier = json_object_get_uint64(
		json_object_object_get(fault_record, "sourceIdentifier"));
	fault_record_cper->PrivelegeModeRequested = json_object_get_boolean(
		json_object_object_get(fault_record, "privelegeModeRequested"));
	fault_record_cper->ExecutePermissionRequested = json_object_get_boolean(
		json_object_object_get(fault_record,
				       "executePermissionRequested"));
	fault_record_cper->PasidPresent = json_object_get_boolean(
		json_object_object_get(fault_record, "pasidPresent"));
	fault_record_cper->FaultReason = json_object_get_uint64(
		json_object_object_get(fault_record, "faultReason"));
	fault_record_cper->PasidValue = json_object_get_uint64(
		json_object_object_get(fault_record, "pasidValue"));
	fault_record_cper->AddressType = json_object_get_uint64(
		json_object_object_get(fault_record, "addressType"));
	fault_record_cper->Type = readable_pair_to_integer(
		json_object_object_get(fault_record, "type"));

	//Root entry.
	json_object *encoded = json_object_object_get(section, "rootEntry");
	char *decoded = malloc(json_object_get_string_len(encoded));
	size_t decoded_len = 0;
	if (!decoded) {
		printf("Failed to allocate decode output buffer. \n");
	} else {
		base64_decode(json_object_get_string(encoded),
			      json_object_get_string_len(encoded), decoded,
			      &decoded_len, 0);
		memcpy(section_cper->RootEntry, decoded, decoded_len);
		free(decoded);
	}
	//Context entry.
	encoded = json_object_object_get(section, "contextEntry");
	decoded = malloc(json_object_get_string_len(encoded));
	decoded_len = 0;
	if (!decoded) {
		printf("Failed to allocate decode output buffer. \n");
	} else {
		base64_decode(json_object_get_string(encoded),
			      json_object_get_string_len(encoded), decoded,
			      &decoded_len, 0);
		memcpy(section_cper->ContextEntry, decoded, decoded_len);
		free(decoded);
	}

	//Page table entries.
	section_cper->PteL1 = json_object_get_uint64(
		json_object_object_get(section, "pageTableEntry_Level1"));
	section_cper->PteL2 = json_object_get_uint64(
		json_object_object_get(section, "pageTableEntry_Level2"));
	section_cper->PteL3 = json_object_get_uint64(
		json_object_object_get(section, "pageTableEntry_Level3"));
	section_cper->PteL4 = json_object_get_uint64(
		json_object_object_get(section, "pageTableEntry_Level4"));
	section_cper->PteL5 = json_object_get_uint64(
		json_object_object_get(section, "pageTableEntry_Level5"));
	section_cper->PteL6 = json_object_get_uint64(
		json_object_object_get(section, "pageTableEntry_Level6"));

	//Write to stream, free resources.
	fwrite(section_cper, sizeof(EFI_DIRECTED_IO_DMAR_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}
