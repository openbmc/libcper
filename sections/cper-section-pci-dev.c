/**
 * Describes functions for converting PCI/PCI-X device CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <json.h>
#include "../edk/Cper.h"
#include "../cper-utils.h"
#include "cper-section-pci-dev.h"

//Converts a single PCI/PCI-X device CPER section into JSON IR.
json_object *cper_section_pci_dev_to_ir(void *section)
{
	EFI_PCI_PCIX_DEVICE_ERROR_DATA *dev_error =
		(EFI_PCI_PCIX_DEVICE_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Validation bits.
	json_object *validation = bitfield_to_ir(
		dev_error->ValidFields, 5, PCI_DEV_ERROR_VALID_BITFIELD_NAMES);
	json_object_object_add(section_ir, "validationBits", validation);

	//Error status.
	json_object *error_status =
		cper_generic_error_status_to_ir(&dev_error->ErrorStatus);
	json_object_object_add(section_ir, "errorStatus", error_status);

	//ID information.
	json_object *id_info = json_object_new_object();
	json_object_object_add(
		id_info, "vendorID",
		json_object_new_uint64(dev_error->IdInfo.VendorId));
	json_object_object_add(
		id_info, "deviceID",
		json_object_new_uint64(dev_error->IdInfo.DeviceId));
	json_object_object_add(
		id_info, "classCode",
		json_object_new_uint64(dev_error->IdInfo.ClassCode));
	json_object_object_add(
		id_info, "functionNumber",
		json_object_new_uint64(dev_error->IdInfo.FunctionNumber));
	json_object_object_add(
		id_info, "deviceNumber",
		json_object_new_uint64(dev_error->IdInfo.DeviceNumber));
	json_object_object_add(
		id_info, "busNumber",
		json_object_new_uint64(dev_error->IdInfo.BusNumber));
	json_object_object_add(
		id_info, "segmentNumber",
		json_object_new_uint64(dev_error->IdInfo.SegmentNumber));
	json_object_object_add(section_ir, "idInfo", id_info);

	//Number of following register data pairs.
	json_object_object_add(section_ir, "memoryNumber",
			       json_object_new_uint64(dev_error->MemoryNumber));
	json_object_object_add(section_ir, "ioNumber",
			       json_object_new_uint64(dev_error->IoNumber));
	int num_data_pairs = dev_error->MemoryNumber + dev_error->IoNumber;

	//Register pairs, described by the numeric fields.
	//The actual "pairs" of address and data aren't necessarily 8 bytes long, so can't assume the contents.
	//Hence the naming "firstHalf" and "secondHalf" rather than "address" and "data".
	json_object *register_data_pair_array = json_object_new_array();
	UINT64 *cur_pos = (UINT64 *)(dev_error + 1);
	for (int i = 0; i < num_data_pairs; i++) {
		//Save current pair to array.
		json_object *register_data_pair = json_object_new_object();
		json_object_object_add(register_data_pair, "firstHalf",
				       json_object_new_uint64(*cur_pos));
		json_object_object_add(register_data_pair, "secondHalf",
				       json_object_new_uint64(*(cur_pos + 1)));
		json_object_array_add(register_data_pair_array,
				      register_data_pair);

		//Move to next pair.
		cur_pos += 2;
	}
	json_object_object_add(section_ir, "registerDataPairs",
			       register_data_pair_array);

	return section_ir;
}

void ir_section_pci_dev_to_cper(json_object *section, FILE *out)
{
	EFI_PCI_PCIX_DEVICE_ERROR_DATA *section_cper =
		(EFI_PCI_PCIX_DEVICE_ERROR_DATA *)calloc(
			1, sizeof(EFI_PCI_PCIX_DEVICE_ERROR_DATA));

	//Validation bits.
	section_cper->ValidFields = ir_to_bitfield(
		json_object_object_get(section, "validationBits"), 5,
		PCI_DEV_ERROR_VALID_BITFIELD_NAMES);

	//Error status.
	ir_generic_error_status_to_cper(json_object_object_get(section,
							       "errorStatus"),
					&section_cper->ErrorStatus);

	//Device ID information.
	json_object *id_info = json_object_object_get(section, "idInfo");
	section_cper->IdInfo.VendorId = json_object_get_uint64(
		json_object_object_get(id_info, "vendorID"));
	section_cper->IdInfo.DeviceId = json_object_get_uint64(
		json_object_object_get(id_info, "deviceID"));
	section_cper->IdInfo.ClassCode = json_object_get_uint64(
		json_object_object_get(id_info, "classCode"));
	section_cper->IdInfo.FunctionNumber = json_object_get_uint64(
		json_object_object_get(id_info, "functionNumber"));
	section_cper->IdInfo.DeviceNumber = json_object_get_uint64(
		json_object_object_get(id_info, "deviceNumber"));
	section_cper->IdInfo.BusNumber = json_object_get_uint64(
		json_object_object_get(id_info, "busNumber"));
	section_cper->IdInfo.SegmentNumber = json_object_get_uint64(
		json_object_object_get(id_info, "segmentNumber"));

	//Amount of following data pairs.
	section_cper->MemoryNumber = (UINT32)json_object_get_uint64(
		json_object_object_get(section, "memoryNumber"));
	section_cper->IoNumber = (UINT32)json_object_get_uint64(
		json_object_object_get(section, "ioNumber"));

	//Write header out to stream, free it.
	fwrite(section_cper, sizeof(EFI_PCI_PCIX_DEVICE_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);

	//Begin writing register pairs.
	json_object *register_pairs =
		json_object_object_get(section, "registerDataPairs");
	int num_pairs = json_object_array_length(register_pairs);
	for (int i = 0; i < num_pairs; i++) {
		//Get the pair array item out.
		json_object *register_pair =
			json_object_array_get_idx(register_pairs, i);

		//Create the pair array.
		UINT64 pair[2];
		pair[0] = json_object_get_uint64(
			json_object_object_get(register_pair, "firstHalf"));
		pair[1] = json_object_get_uint64(
			json_object_object_get(register_pair, "secondHalf"));

		//Push to stream.
		fwrite(pair, sizeof(UINT64), 2, out);
		fflush(out);
	}
}
