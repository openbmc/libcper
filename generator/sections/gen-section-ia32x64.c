/**
 * Functions for generating pseudo-random CPER IA32/x64 sections.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdlib.h>
#include <string.h>
#include "../../edk/Cper.h"
#include "../gen-utils.h"
#include "gen-section.h"
#define IA32X64_ERROR_STRUCTURE_SIZE 64

void *generate_ia32x64_error_structure();
size_t generate_ia32x64_context_structure(void **location);

//Generates a single pseudo-random IA32/x64 section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_ia32x64(void **location)
{
	//Set up for generation of error/context structures.
	UINT16 error_structure_num = rand() % 4 + 1;
	UINT16 context_structure_num = rand() % 4 + 1;
	void *error_structures[error_structure_num];
	void *context_structures[context_structure_num];
	size_t context_structure_lengths[context_structure_num];

	//Generate the structures.
	for (int i = 0; i < error_structure_num; i++) {
		error_structures[i] = generate_ia32x64_error_structure();
	}
	for (int i = 0; i < context_structure_num; i++) {
		context_structure_lengths[i] =
			generate_ia32x64_context_structure(context_structures +
							   i);
	}

	//Create a valid IA32/x64 section.
	size_t total_len =
		64 + (IA32X64_ERROR_STRUCTURE_SIZE * error_structure_num);
	for (int i = 0; i < context_structure_num; i++) {
		total_len += context_structure_lengths[i];
	}
	UINT8 *section = generate_random_bytes(total_len);

	//Null extend the end of the CPUID in the header.
	for (int i = 0; i < 16; i++) {
		*(section + 48 + i) = 0x0;
	}

	//Set header information.
	UINT64 *validation = (UINT64 *)section;
	*validation &= 0x3;
	*validation |= error_structure_num << 2;
	*validation |= context_structure_num << 8;

	//Copy in structures, free resources.
	UINT8 *cur_pos = section + 64;
	for (int i = 0; i < error_structure_num; i++) {
		memcpy(cur_pos, error_structures[i],
		       IA32X64_ERROR_STRUCTURE_SIZE);
		free(error_structures[i]);
		cur_pos += IA32X64_ERROR_STRUCTURE_SIZE;
	}
	for (int i = 0; i < context_structure_num; i++) {
		memcpy(cur_pos, context_structures[i],
		       context_structure_lengths[i]);
		free(context_structures[i]);
		cur_pos += context_structure_lengths[i];
	}

	//Set return values, exist.
	*location = section;
	return total_len;
}

//Generates a single IA32/x64 error structure. Must later be freed.
void *generate_ia32x64_error_structure()
{
	UINT8 *error_structure =
		generate_random_bytes(IA32X64_ERROR_STRUCTURE_SIZE);

	//Set error structure reserved space to zero.
	UINT64 *validation = (UINT64 *)(error_structure + 16);
	*validation &= 0x1F;

	//Create a random type of error structure.
	EFI_GUID *guid = (EFI_GUID *)error_structure;
	UINT64 *check_info = (UINT64 *)(error_structure + 24);
	int error_structure_type = rand() % 4;
	switch (error_structure_type) {
	//Cache
	case 0:
		memcpy(guid, &gEfiIa32x64ErrorTypeCacheCheckGuid,
		       sizeof(EFI_GUID));

		//Set reserved space to zero.
		*check_info &= ~0x20FF00;
		*check_info &= 0x3FFFFFFF;
		break;

	//TLB
	case 1:
		memcpy(guid, &gEfiIa32x64ErrorTypeTlbCheckGuid,
		       sizeof(EFI_GUID));

		//Set reserved space to zero.
		*check_info &= ~0x20FF00;
		*check_info &= 0x3FFFFFFF;
		break;

	//Bus
	case 2:
		memcpy(guid, &gEfiIa32x64ErrorTypeBusCheckGuid,
		       sizeof(EFI_GUID));

		//Set reserved space to zero.
		*check_info &= ~0x20F800;
		*check_info &= 0x7FFFFFFFF;
		break;

	//MS
	case 3:
		memcpy(guid, &gEfiIa32x64ErrorTypeMsCheckGuid,
		       sizeof(EFI_GUID));

		//Set reserved space to zero.
		*check_info &= ~0xFFE0;
		*check_info &= 0xFFFFFF;
		break;
	}

	return error_structure;
}

//Generates a single IA32/x64 context structure. Must later be freed.
size_t generate_ia32x64_context_structure(void **location)
{
	//Initial length is 16 bytes. Add extra based on type.
	int reg_type = rand() % 8;
	int reg_size = 0;

	//Set register size.
	if (reg_type == 2) {
		reg_size = 92;			  //IA32 registers.
	} else if (reg_type == 3) {
		reg_size = 244;			  //x64 registers.
	} else {
		reg_size = (rand() % 5 + 1) * 32; //Not table defined.
	}

	//Create structure randomly.
	int total_size = 16 + reg_size;
	UINT16 *context_structure = (UINT16 *)generate_random_bytes(total_size);

	//If it is x64 registers, set reserved area accordingly.
	if (reg_type == 3) {
		UINT8 *reg_bytes = (UINT8 *)(context_structure + 8);
		UINT32 *reserved = (UINT32 *)(reg_bytes + 140);
		*reserved = 0;
	}

	//Set header information.
	*(context_structure) = reg_type;
	*(context_structure + 1) = reg_size;

	//Set return values and exit.
	*location = context_structure;
	return total_size;
}
