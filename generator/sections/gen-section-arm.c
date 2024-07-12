/**
 * Functions for generating pseudo-random CPER ARM processor sections.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdlib.h>
#include <string.h>
#include "../../edk/BaseTypes.h"
#include "../gen-utils.h"
#include "gen-section.h"
#define ARM_ERROR_INFO_SIZE 32

void *generate_arm_error_info();
size_t generate_arm_context_info(void **location);

//Generates a single pseudo-random ARM processor section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_arm(void **location)
{
	//Set up for generation of error/context structures.
	UINT16 error_structure_num = rand() % 4 + 1; //Must be at least 1.
	UINT16 context_structure_num = rand() % 3 + 1;
	void *error_structures[error_structure_num];
	void *context_structures[context_structure_num];
	size_t context_structure_lengths[context_structure_num];

	//Generate the structures.
	for (int i = 0; i < error_structure_num; i++) {
		error_structures[i] = generate_arm_error_info();
	}
	for (int i = 0; i < context_structure_num; i++) {
		context_structure_lengths[i] =
			generate_arm_context_info(context_structures + i);
	}

	//Determine a random amount of vendor specific info.
	int vendor_info_len = rand() % 16;

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
	*(section + 12) = rand() % 4;

	//Reserved zero bytes.
	UINT64 *validation = (UINT64 *)section;
	*validation &= 0x7;
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

	//Set return values and exit.
	*location = section;
	return total_len;
}

//Generates a single pseudo-random ARM error info structure. Must be later freed.
void *generate_arm_error_info()
{
	UINT8 *error_info = generate_random_bytes(ARM_ERROR_INFO_SIZE);

	//Version (zero for revision of table referenced), length.
	*error_info = 0;
	*(error_info + 1) = ARM_ERROR_INFO_SIZE;

	//Type of error.
	UINT8 error_type = rand() % 4;
	*(error_info + 4) = error_type;

	//Reserved bits for error information.
	UINT16 *validation = (UINT16 *)(error_info + 2);
	*validation &= 0x1F;

	//Make sure reserved bits are zero according with the type.
	UINT64 *error_subinfo = (UINT64 *)(error_info + 8);
	switch (error_type) {
	//Cache/TLB
	case 0:
	case 1:
		*error_subinfo &= 0xFFFFFFF;
		break;

	//Bus
	case 2:
		*error_subinfo &= 0xFFFFFFFFFFF;
		break;

	//Microarch/other.
	default:
		break;
	}

	return error_info;
}

//Generates a single pseudo-random ARM context info structure. Must be later freed.
size_t generate_arm_context_info(void **location)
{
	//Initial length is 8 bytes. Add extra based on type.
	UINT16 reg_type = rand() % 9;
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

	//Set header information.
	*(context_info + 1) = reg_type;
	*((UINT32 *)(context_info + 2)) = reg_size;

	//Set return values and exit.
	*location = context_info;
	return total_size;
}
