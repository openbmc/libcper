/**
 * Functions for generating pseudo-random CPER ARM processor sections.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libcper/BaseTypes.h>
#include <libcper/Cper.h>
#include <libcper/generator/gen-utils.h>
#include <libcper/generator/sections/gen-section.h>
#define ARM_ERROR_INFO_SIZE 32

void *generate_arm_error_info(GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_arm_context_info(void **location);

//Generates a single pseudo-random ARM processor section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_arm(void **location,
			    GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	//Set up for generation of error/context structures.
	UINT16 error_structure_num = cper_rand() % 4 + 1; //Must be at least 1.
	UINT16 context_structure_num = cper_rand() % 3 + 1;
	void *error_structures[error_structure_num];
	void *context_structures[context_structure_num];
	size_t context_structure_lengths[context_structure_num];

	//Generate the structures.
	for (int i = 0; i < error_structure_num; i++) {
		error_structures[i] = generate_arm_error_info(validBitsType);
	}
	for (int i = 0; i < context_structure_num; i++) {
		context_structure_lengths[i] =
			generate_arm_context_info(context_structures + i);
	}

	//Determine a random amount of vendor specific info.
	size_t vendor_info_len = cper_rand() % 16 + 4;

	//Create the section as a whole.
	size_t total_len = 40 + (error_structure_num * ARM_ERROR_INFO_SIZE);
	for (int i = 0; i < context_structure_num; i++) {
		total_len += context_structure_lengths[i];
	}
	total_len += vendor_info_len;
	UINT8 *section = generate_random_bytes(total_len);

	//Set header information.
	UINT16 *info_nums = (UINT16 *)(section + 4);
	*info_nums = error_structure_num;
	*(info_nums + 1) = context_structure_num;
	UINT32 *section_length = (UINT32 *)(section + 8);
	*section_length = total_len;

	//Error affinity.
	*(section + 12) = cper_rand() % 4;

	//Reserved zero bytes.
	UINT32 *validation = (UINT32 *)section;
	*validation &= 0xF;
	if (validBitsType == ALL_VALID) {
		*validation = 0xF;
	} else if (validBitsType == SOME_VALID) {
		*validation = 0xA;
	}
	UINT32 *running_state = (UINT32 *)(section + 32);
	*running_state &= 0x1;
	memset(section + 13, 0, 3);

	//Copy in the sections/context structures, free resources.
	UINT8 *cur_pos = section + 40;
	for (int i = 0; i < error_structure_num; i++) {
		memcpy(cur_pos, error_structures[i], ARM_ERROR_INFO_SIZE);
		free(error_structures[i]);
		cur_pos += ARM_ERROR_INFO_SIZE;
	}
	for (int i = 0; i < context_structure_num; i++) {
		memcpy(cur_pos, context_structures[i],
		       context_structure_lengths[i]);
		free(context_structures[i]);
		cur_pos += context_structure_lengths[i];
	}

	//vendor specific
	for (size_t i = 0; i < vendor_info_len; i++) {
		//Ensure only printable ascii is used so we don't
		// fail base64E
		*cur_pos = cper_rand() % (0x7f - 0x20) + 0x20;
		cur_pos += 1;
	}

	//Set return values and exit.
	*location = section;
	return total_len;
}

//Generates a single pseudo-random ARM error info structure. Must be later freed.
void *generate_arm_error_info(GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	UINT8 *error_info = generate_random_bytes(ARM_ERROR_INFO_SIZE);

	//Version (zero for revision of table referenced), length.
	*error_info = 0;
	*(error_info + 1) = ARM_ERROR_INFO_SIZE;

	//Type of error. UEFI spec uses bit positions: 1=Cache, 2=TLB, 4=Bus, 8=Microarch
	const UINT8 error_type_values[] = { 1, 2, 4, 8 };
	UINT8 error_type = error_type_values[cper_rand() % 4];
	*(error_info + 4) = error_type;

	//Reserved bits for error information.
	UINT16 *validation = (UINT16 *)(error_info + 2);
	*validation &= 0x1F;
	if (validBitsType == ALL_VALID) {
		*validation = 0x1F;
	} else if (validBitsType == SOME_VALID) {
		*validation = 0x15;
	}

	//Make sure reserved bits are zero according with the type.
	UINT64 *error_subinfo = (UINT64 *)(error_info + 8);
	switch (error_type) {
	//Cache/TLB
	case ARM_ERROR_INFORMATION_TYPE_CACHE:
	case ARM_ERROR_INFORMATION_TYPE_TLB:
		*error_subinfo &= 0xFFFFFFF;
		//Reserved bits for cache/tlb.
		UINT16 *val_cache = (UINT16 *)(error_info + 8);
		if (validBitsType == ALL_VALID) {
			*val_cache = 0x7F;
		} else if (validBitsType == SOME_VALID) {
			*val_cache = 0x55;
		}
		break;

	//Bus
	case ARM_ERROR_INFORMATION_TYPE_BUS:
		*error_subinfo &= 0xFFFFFFFFFFF;
		UINT16 *val_bus = (UINT16 *)(error_info + 8);
		if (validBitsType == ALL_VALID) {
			*val_bus = 0xFFF;
		} else if (validBitsType == SOME_VALID) {
			*val_bus = 0x555;
		}

		break;

	//Microarch/other.
	default:
		break;
	}

	//flags
	UINT8 *flags = (UINT8 *)(error_info + 7);
	*flags &= 0xF;

	return error_info;
}

//Generates a single pseudo-random ARM context info structure. Must be later freed.
size_t generate_arm_context_info(void **location)
{
	//Initial length is 8 bytes. Add extra based on type.
	UINT16 reg_type = cper_rand() % 9;
	UINT32 reg_size = 0;

	//Set register size.
	switch (reg_type) {
	//AARCH32 GPR, AARCH32 EL2
	case 0:
	case 2:
		reg_size = 64;
		break;

	//AARCH32 EL1
	case 1:
		reg_size = 96;
		break;

	//AARCH32 EL3
	case 3:
		reg_size = 8;
		break;

	//AARCH64 GPR
	case 4:
		reg_size = 256;
		break;

	//AARCH64 EL1
	case 5:
		reg_size = 136;
		break;

	//AARCH64 EL2
	case 6:
		reg_size = 120;
		break;

	//AARCH64 EL3
	case 7:
		reg_size = 80;
		break;

	//Misc. single register.
	case 8:
		reg_size = 10;
		break;
	}

	//Create context structure randomly.
	int total_size = 8 + reg_size;
	UINT16 *context_info = (UINT16 *)generate_random_bytes(total_size);

	//UEFI spec is not clear about bit 15 in the
	// reg type 8 section. This sets it to 0 to
	// avoid confusion for now.
	if (reg_type == 8) {
		UINT8 *reg_decode = (UINT8 *)context_info;
		*(reg_decode + 9) &= 0x7F;
	}

	//Set header information.
	*(context_info + 1) = reg_type;
	*((UINT32 *)(context_info + 2)) = reg_size;

	//Set return values and exit.
	*location = context_info;
	return total_size;
}
