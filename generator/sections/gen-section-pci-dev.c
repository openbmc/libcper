/**
 * Functions for generating pseudo-random CPER PCI component error sections.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdlib.h>
#include "../../edk/BaseTypes.h"
#include "../gen-utils.h"
#include "gen-section.h"

//Generates a single pseudo-random PCI component error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_pci_dev(void **location)
{
	//Generate how many register pairs will be attached to this section.
	UINT32 num_memory_pairs = rand() % 4;
	UINT32 num_io_pairs = rand() % 4;
	UINT32 num_registers = num_memory_pairs + num_io_pairs;

	//Create random bytes.
	int size = 40 + (num_registers * 16);
	UINT8 *bytes = generate_random_bytes(size);

	//Set reserved areas to zero.
	UINT64 *validation = (UINT64 *)bytes;
	*validation &= 0x1F;	       //Validation 5-63
	for (int i = 0; i < 5; i++) {
		*(bytes + 27 + i) = 0; //Bytes 11-15 of ID info.
	}

	//Set expected values.
	UINT32 *memory_number_field = (UINT32 *)(bytes + 32);
	UINT32 *io_number_field = (UINT32 *)(bytes + 36);
	*memory_number_field = num_memory_pairs;
	*io_number_field = num_io_pairs;

	//Fix error status.
	create_valid_error_section(bytes + 8);

	//Set return values, exit.
	*location = bytes;
	return size;
}
