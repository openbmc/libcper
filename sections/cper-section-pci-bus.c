/**
 * Describes functions for converting PCI/PCI-X bus CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <string.h>
#include <json.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-pci-bus.h>
#include <libcper/log.h>
#include <string.h>

//Converts a single PCI/PCI-X bus CPER section into JSON IR.
json_object *cper_section_pci_bus_to_ir(const UINT8 *section, UINT32 size,
					char **desc_string)
{
	int outstr_len = 0;

	*desc_string = NULL;
	if (size < sizeof(EFI_PCI_PCIX_BUS_ERROR_DATA)) {
		cper_print_log("Error: PCI/PCI-X Bus section too small\n");
		return NULL;
	}

	*desc_string = calloc(1, SECTION_DESC_STRING_SIZE);
	if (*desc_string == NULL) {
		cper_print_log(
			"Error: Failed to allocate PCI/PCI-X Bus desc string\n");
		return NULL;
	}
	outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
			      "A PCI/PCI-X Bus Error occurred");
	if (outstr_len < 0) {
		cper_print_log(
			"Error: Could not write to PCI/PCI-X Bus description string\n");
	} else if (outstr_len > SECTION_DESC_STRING_SIZE) {
		cper_print_log(
			"Error: PCI/PCI-X Bus description string truncated\n");
	}

	EFI_PCI_PCIX_BUS_ERROR_DATA *bus_error =
		(EFI_PCI_PCIX_BUS_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = bus_error->ValidFields };

	//Error status.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *error_status = cper_generic_error_status_to_ir(
			&bus_error->ErrorStatus);
		json_object_object_add(section_ir, "errorStatus", error_status);
	}

	//PCI bus error type.
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		json_object *error_type = integer_to_readable_pair(
			bus_error->Type, 8, PCI_BUS_ERROR_TYPES_KEYS,
			PCI_BUS_ERROR_TYPES_VALUES, "Unknown (Reserved)");
		json_object_object_add(section_ir, "errorType", error_type);
	}

	//Bus ID.
	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		json_object *bus_id = json_object_new_object();
		json_object_object_add(bus_id, "busNumber",
				       json_object_new_int(bus_error->BusId &
							   0xFF));
		json_object_object_add(bus_id, "segmentNumber",
				       json_object_new_int(bus_error->BusId >>
							   8));
		json_object_object_add(section_ir, "busID", bus_id);
	}

	//Miscellaneous numeric fields.
	//Byte 7, bit 0.
	UINT8 command_type = (bus_error->BusCommand >> 56) & 0x1;
	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		json_object_object_add(
			section_ir, "busAddress",
			json_object_new_uint64(bus_error->BusAddress));
	}
	if (isvalid_prop_to_ir(&ui64Type, 4)) {
		json_object_object_add(
			section_ir, "busData",
			json_object_new_uint64(bus_error->BusData));
	}
	if (isvalid_prop_to_ir(&ui64Type, 5)) {
		json_object_object_add(
			section_ir, "busCommandType",
			json_object_new_string(command_type == 0 ? "PCI" :
								   "PCI-X"));
	}
	char hexstring_buf[EFI_UINT64_HEX_STRING_LEN];

	if (isvalid_prop_to_ir(&ui64Type, 6)) {
		json_object_object_add(
			section_ir, "busRequestorID",
			json_object_new_uint64(bus_error->RequestorId));

		snprintf(hexstring_buf, EFI_UINT64_HEX_STRING_LEN, "0x%016llX",
			 bus_error->RequestorId);
		json_object_object_add(section_ir, "busRequestorIDHex",
				       json_object_new_string(hexstring_buf));
	}

	if (isvalid_prop_to_ir(&ui64Type, 7)) {
		json_object_object_add(
			section_ir, "busCompleterID",
			json_object_new_uint64(bus_error->ResponderId));
		snprintf(hexstring_buf, EFI_UINT64_HEX_STRING_LEN, "0x%016llX",
			 bus_error->ResponderId);
		json_object_object_add(section_ir, "busCompleterIDHex",
				       json_object_new_string(hexstring_buf));
	}

	if (isvalid_prop_to_ir(&ui64Type, 8)) {
		json_object_object_add(
			section_ir, "targetID",
			json_object_new_uint64(bus_error->TargetId));
	}

	return section_ir;
}

//Converts a single provided PCI/PCI-X bus CPER-JSON section into CPER binary, outputting to the
//provided stream.
void ir_section_pci_bus_to_cper(json_object *section, FILE *out)
{
	EFI_PCI_PCIX_BUS_ERROR_DATA *section_cper =
		(EFI_PCI_PCIX_BUS_ERROR_DATA *)calloc(
			1, sizeof(EFI_PCI_PCIX_BUS_ERROR_DATA));

	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;

	//Error status.
	if (json_object_object_get_ex(section, "errorStatus", &obj)) {
		ir_generic_error_status_to_cper(obj,
						&section_cper->ErrorStatus);
		add_to_valid_bitfield(&ui64Type, 0);
	}

	//Bus ID.
	if (json_object_object_get_ex(section, "busID", &obj)) {
		json_object *bus_id = json_object_object_get(section, "busID");
		UINT16 bus_number = (UINT8)json_object_get_int(
			json_object_object_get(bus_id, "busNumber"));
		UINT16 segment_number = (UINT8)json_object_get_int(
			json_object_object_get(bus_id, "segmentNumber"));
		section_cper->BusId = bus_number + (segment_number << 8);
		add_to_valid_bitfield(&ui64Type, 2);
	}

	//Remaining fields.
	UINT64 pcix_command = (UINT64)0x1 << 56;

	if (json_object_object_get_ex(section, "errorType", &obj)) {
		section_cper->Type = (UINT16)readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 1);
	}
	if (json_object_object_get_ex(section, "busAddress", &obj)) {
		section_cper->BusAddress = json_object_get_uint64(
			json_object_object_get(section, "busAddress"));
		add_to_valid_bitfield(&ui64Type, 3);
	}
	if (json_object_object_get_ex(section, "busData", &obj)) {
		section_cper->BusData = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 4);
	}
	if (json_object_object_get_ex(section, "busCommandType", &obj)) {
		const char *bus_command = json_object_get_string(obj);
		section_cper->BusCommand =
			strcmp(bus_command, "PCI") == 0 ? 0 : pcix_command;
		add_to_valid_bitfield(&ui64Type, 5);
	}
	if (json_object_object_get_ex(section, "busRequestorID", &obj)) {
		section_cper->RequestorId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 6);
	}
	if (json_object_object_get_ex(section, "busCompleterID", &obj)) {
		section_cper->ResponderId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 7);
	}
	if (json_object_object_get_ex(section, "targetID", &obj)) {
		section_cper->TargetId = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 8);
	}
	section_cper->ValidFields = ui64Type.value.ui64;

	//Write to stream, free resources.
	fwrite(section_cper, sizeof(EFI_PCI_PCIX_BUS_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}
