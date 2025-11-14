/**
 * Describes functions for converting PCI/PCI-X device CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <json.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-pci-dev.h>
#include <libcper/log.h>
#include <string.h>

//Converts a single PCI/PCI-X device CPER section into JSON IR.
json_object *cper_section_pci_dev_to_ir(const UINT8 *section, UINT32 size,
					char **desc_string)
{
	int outstr_len = 0;
	*desc_string = calloc(1, SECTION_DESC_STRING_SIZE);
	outstr_len = snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
			      "A PCI/PCI-X Device Error occurred");
	if (outstr_len < 0) {
		cper_print_log(
			"Error: Could not write to PCI/PCI-X Device description string\n");
	} else if (outstr_len > SECTION_DESC_STRING_SIZE) {
		cper_print_log(
			"Error: PCI/PCI-X Device description string truncated\n");
	}

	if (size < sizeof(EFI_PCI_PCIX_DEVICE_ERROR_DATA)) {
		return NULL;
	}

	EFI_PCI_PCIX_DEVICE_ERROR_DATA *dev_error =
		(EFI_PCI_PCIX_DEVICE_ERROR_DATA *)section;

	if (size < sizeof(EFI_PCI_PCIX_DEVICE_ERROR_DATA) +
			   ((dev_error->MemoryNumber + dev_error->IoNumber) *
			    sizeof(EFI_PCI_PCIX_DEVICE_ERROR_DATA_REGISTER))) {
		return NULL;
	}

	json_object *section_ir = json_object_new_object();

	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = dev_error->ValidFields };

	//Error status.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *error_status = cper_generic_error_status_to_ir(
			&dev_error->ErrorStatus);
		json_object_object_add(section_ir, "errorStatus", error_status);
	}

	//ID information.
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
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
			json_object_new_uint64(
				dev_error->IdInfo.FunctionNumber));
		json_object_object_add(
			id_info, "deviceNumber",
			json_object_new_uint64(dev_error->IdInfo.DeviceNumber));
		json_object_object_add(
			id_info, "busNumber",
			json_object_new_uint64(dev_error->IdInfo.BusNumber));
		json_object_object_add(
			id_info, "segmentNumber",
			json_object_new_uint64(
				dev_error->IdInfo.SegmentNumber));
		json_object_object_add(section_ir, "idInfo", id_info);
	}

	//Number of following register data pairs.
	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		json_object_object_add(
			section_ir, "memoryNumber",
			json_object_new_uint64(dev_error->MemoryNumber));
	}
	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		json_object_object_add(
			section_ir, "ioNumber",
			json_object_new_uint64(dev_error->IoNumber));
	}

	if (isvalid_prop_to_ir(&ui64Type, 4)) {
		int num_data_pairs =
			dev_error->MemoryNumber + dev_error->IoNumber;

		//Register pairs, described by the numeric fields.
		//The actual "pairs" of address and data aren't necessarily 8 bytes long, so can't assume the contents.
		//Hence the naming "firstHalf" and "secondHalf" rather than "address" and "data".
		json_object *register_data_pair_array = json_object_new_array();
		UINT64 *cur_pos = (UINT64 *)(dev_error + 1);
		for (int i = 0; i < num_data_pairs; i++) {
			//Save current pair to array.
			json_object *register_data_pair =
				json_object_new_object();
			json_object_object_add(
				register_data_pair, "firstHalf",
				json_object_new_uint64(*cur_pos));
			json_object_object_add(
				register_data_pair, "secondHalf",
				json_object_new_uint64(*(cur_pos + 1)));
			json_object_array_add(register_data_pair_array,
					      register_data_pair);

			//Move to next pair.
			cur_pos += 2;
		}
		json_object_object_add(section_ir, "registerDataPairs",
				       register_data_pair_array);
	}

	return section_ir;
}

void ir_section_pci_dev_to_cper(json_object *section, FILE *out)
{
	EFI_PCI_PCIX_DEVICE_ERROR_DATA *section_cper =
		(EFI_PCI_PCIX_DEVICE_ERROR_DATA *)calloc(
			1, sizeof(EFI_PCI_PCIX_DEVICE_ERROR_DATA));

	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;

	//Error status.
	if (json_object_object_get_ex(section, "errorStatus", &obj)) {
		ir_generic_error_status_to_cper(obj,
						&section_cper->ErrorStatus);
		add_to_valid_bitfield(&ui64Type, 0);
	}

	//Device ID information.
	if (json_object_object_get_ex(section, "idInfo", &obj)) {
		json_object *id_info = obj;
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
		add_to_valid_bitfield(&ui64Type, 1);
	}

	//Amount of following data pairs.
	if (json_object_object_get_ex(section, "memoryNumber", &obj)) {
		section_cper->MemoryNumber =
			(UINT32)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 2);
	}
	if (json_object_object_get_ex(section, "ioNumber", &obj)) {
		section_cper->IoNumber = (UINT32)json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 3);
	}
	json_object *register_pairs = NULL;
	if (json_object_object_get_ex(section, "registerDataPairs", &obj)) {
		register_pairs = obj;
		add_to_valid_bitfield(&ui64Type, 4);
	}

	section_cper->ValidFields = ui64Type.value.ui64;

	//Write header out to stream, free it.
	fwrite(section_cper, sizeof(EFI_PCI_PCIX_DEVICE_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);

	//Begin writing register pairs.
	if (register_pairs != NULL) {
		int num_pairs = json_object_array_length(register_pairs);
		for (int i = 0; i < num_pairs; i++) {
			//Get the pair array item out.
			json_object *register_pair =
				json_object_array_get_idx(register_pairs, i);

			//Create the pair array.
			UINT64 pair[2];
			pair[0] = json_object_get_uint64(json_object_object_get(
				register_pair, "firstHalf"));
			pair[1] = json_object_get_uint64(json_object_object_get(
				register_pair, "secondHalf"));

			//Push to stream.
			fwrite(pair, sizeof(UINT64), 2, out);
			fflush(out);
		}
	}
}
