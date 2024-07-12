/**
 * Describes functions for converting PCI/PCI-X bus CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <string.h>
#include <json.h>
#include "../edk/Cper.h"
#include "../cper-utils.h"
#include "cper-section-pci-bus.h"

//Converts a single PCI/PCI-X bus CPER section into JSON IR.
json_object *cper_section_pci_bus_to_ir(void *section)
{
	EFI_PCI_PCIX_BUS_ERROR_DATA *bus_error =
		(EFI_PCI_PCIX_BUS_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Validation bits.
	json_object *validation = bitfield_to_ir(
		bus_error->ValidFields, 9, PCI_BUS_ERROR_VALID_BITFIELD_NAMES);
	json_object_object_add(section_ir, "validationBits", validation);

	//Error status.
	json_object *error_status =
		cper_generic_error_status_to_ir(&bus_error->ErrorStatus);
	json_object_object_add(section_ir, "errorStatus", error_status);

	//PCI bus error type.
	json_object *error_type = integer_to_readable_pair(
		bus_error->Type, 8, PCI_BUS_ERROR_TYPES_KEYS,
		PCI_BUS_ERROR_TYPES_VALUES, "Unknown (Reserved)");
	json_object_object_add(section_ir, "errorType", error_type);

	//Bus ID.
	json_object *bus_id = json_object_new_object();
	json_object_object_add(bus_id, "busNumber",
			       json_object_new_int(bus_error->BusId & 0xFF));
	json_object_object_add(bus_id, "segmentNumber",
			       json_object_new_int(bus_error->BusId >> 8));
	json_object_object_add(section_ir, "busID", bus_id);

	//Miscellaneous numeric fields.
	UINT8 command_type = (bus_error->BusCommand >> 56) &
			     0x1; //Byte 7, bit 0.
	json_object_object_add(section_ir, "busAddress",
			       json_object_new_uint64(bus_error->BusAddress));
	json_object_object_add(section_ir, "busData",
			       json_object_new_uint64(bus_error->BusData));
	json_object_object_add(
		section_ir, "busCommandType",
		json_object_new_string(command_type == 0 ? "PCI" : "PCI-X"));
	json_object_object_add(section_ir, "busRequestorID",
			       json_object_new_uint64(bus_error->RequestorId));
	json_object_object_add(section_ir, "busCompleterID",
			       json_object_new_uint64(bus_error->ResponderId));
	json_object_object_add(section_ir, "targetID",
			       json_object_new_uint64(bus_error->TargetId));

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
	section_cper->ValidFields = ir_to_bitfield(
		json_object_object_get(section, "validationBits"), 9,
		PCI_BUS_ERROR_VALID_BITFIELD_NAMES);

	//Error status.
	ir_generic_error_status_to_cper(json_object_object_get(section,
							       "errorStatus"),
					&section_cper->ErrorStatus);

	//Bus ID.
	json_object *bus_id = json_object_object_get(section, "busID");
	UINT16 bus_number = (UINT8)json_object_get_int(
		json_object_object_get(bus_id, "busNumber"));
	UINT16 segment_number = (UINT8)json_object_get_int(
		json_object_object_get(bus_id, "segmentNumber"));
	section_cper->BusId = bus_number + (segment_number << 8);

	//Remaining fields.
	UINT64 pcix_command = (UINT64)0x1 << 56;
	const char *bus_command = json_object_get_string(
		json_object_object_get(section, "busCommandType"));
	section_cper->Type = (UINT16)readable_pair_to_integer(
		json_object_object_get(section, "errorType"));
	section_cper->BusAddress = json_object_get_uint64(
		json_object_object_get(section, "busAddress"));
	section_cper->BusData = json_object_get_uint64(
		json_object_object_get(section, "busData"));
	section_cper->BusCommand =
		strcmp(bus_command, "PCI") == 0 ? 0 : pcix_command;
	section_cper->RequestorId = json_object_get_uint64(
		json_object_object_get(section, "busRequestorID"));
	section_cper->ResponderId = json_object_get_uint64(
		json_object_object_get(section, "busCompleterID"));
	section_cper->TargetId = json_object_get_uint64(
		json_object_object_get(section, "targetID"));

	//Write to stream, free resources.
	fwrite(section_cper, sizeof(EFI_PCI_PCIX_BUS_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}
