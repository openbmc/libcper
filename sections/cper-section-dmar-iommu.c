/**
 * Describes functions for converting IOMMU specific DMAr CPER sections from binary and JSON format
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
#include "cper-section-dmar-iommu.h"

//Converts a single IOMMU specific DMAr CPER section into JSON IR.
json_object *cper_section_dmar_iommu_to_ir(void *section)
{
	EFI_IOMMU_DMAR_ERROR_DATA *iommu_error =
		(EFI_IOMMU_DMAR_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Revision.
	json_object_object_add(section_ir, "revision",
			       json_object_new_int(iommu_error->Revision));

	//IOMMU registers.
	json_object_object_add(section_ir, "controlRegister",
			       json_object_new_uint64(iommu_error->Control));
	json_object_object_add(section_ir, "statusRegister",
			       json_object_new_uint64(iommu_error->Status));

	//IOMMU event log entry.
	//The format of these entries differ widely by the type of error.
	char *encoded = malloc(2 * 16);
	size_t encoded_len = 0;
	if (!encoded) {
		printf("Failed to allocate encode output buffer. \n");
	} else {
		base64_encode((const char *)iommu_error->EventLogEntry, 16,
			      encoded, &encoded_len, 0);
		json_object_object_add(section_ir, "eventLogEntry",
				       json_object_new_string_len(encoded,
								  encoded_len));
		free(encoded);
	}

	//Device table entry (as base64).
	encoded = malloc(2 * 32);
	encoded_len = 0;
	if (!encoded) {
		printf("Failed to allocate encode output buffer. \n");
	} else {
		base64_encode((const char *)iommu_error->DeviceTableEntry, 32,
			      encoded, &encoded_len, 0);
		json_object_object_add(section_ir, "deviceTableEntry",
				       json_object_new_string_len(encoded,
								  encoded_len));
		free(encoded);
	}

	//Page table entries.
	json_object_object_add(section_ir, "pageTableEntry_Level6",
			       json_object_new_uint64(iommu_error->PteL6));
	json_object_object_add(section_ir, "pageTableEntry_Level5",
			       json_object_new_uint64(iommu_error->PteL5));
	json_object_object_add(section_ir, "pageTableEntry_Level4",
			       json_object_new_uint64(iommu_error->PteL4));
	json_object_object_add(section_ir, "pageTableEntry_Level3",
			       json_object_new_uint64(iommu_error->PteL3));
	json_object_object_add(section_ir, "pageTableEntry_Level2",
			       json_object_new_uint64(iommu_error->PteL2));
	json_object_object_add(section_ir, "pageTableEntry_Level1",
			       json_object_new_uint64(iommu_error->PteL1));

	return section_ir;
}

//Converts a single DMAR IOMMU CPER-JSON section into CPER binary, outputting to the given stream.
void ir_section_dmar_iommu_to_cper(json_object *section, FILE *out)
{
	EFI_IOMMU_DMAR_ERROR_DATA *section_cper =
		(EFI_IOMMU_DMAR_ERROR_DATA *)calloc(
			1, sizeof(EFI_IOMMU_DMAR_ERROR_DATA));

	//Revision, registers.
	section_cper->Revision = (UINT8)json_object_get_int(
		json_object_object_get(section, "revision"));
	section_cper->Control = json_object_get_uint64(
		json_object_object_get(section, "controlRegister"));
	section_cper->Status = json_object_get_uint64(
		json_object_object_get(section, "statusRegister"));

	//IOMMU event log entry.
	json_object *encoded = json_object_object_get(section, "eventLogEntry");
	char *decoded = malloc(json_object_get_string_len(encoded));
	size_t decoded_len = 0;
	if (!decoded) {
		printf("Failed to allocate decode output buffer. \n");
	} else {
		base64_decode(json_object_get_string(encoded),
			      json_object_get_string_len(encoded), decoded,
			      &decoded_len, 0);
		memcpy(section_cper->EventLogEntry, decoded, decoded_len);
		free(decoded);
	}

	//Device table entry.
	encoded = json_object_object_get(section, "deviceTableEntry");
	decoded = malloc(json_object_get_string_len(encoded));
	decoded_len = 0;
	if (!decoded) {
		printf("Failed to allocate decode output buffer. \n");
	} else {
		base64_decode(json_object_get_string(encoded),
			      json_object_get_string_len(encoded), decoded,
			      &decoded_len, 0);
		memcpy(section_cper->DeviceTableEntry, decoded, decoded_len);
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
	fwrite(section_cper, sizeof(EFI_IOMMU_DMAR_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}
