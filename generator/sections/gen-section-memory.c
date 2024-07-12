/**
 * Functions for generating pseudo-random CPER platform memory error sections.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdlib.h>
#include "../../edk/BaseTypes.h"
#include "../gen-utils.h"
#include "gen-section.h"

//Generates a single pseudo-random platform memory error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_memory(void **location)
{
	//Create random bytes.
	int size = 80;
	UINT8 *bytes = generate_random_bytes(size);

	//Set reserved areas to zero.
	UINT64 *validation = (UINT64 *)bytes;
	*validation &= 0x2FFFFF; //Validation 22-63
	*(bytes + 73) &= ~0x1C;	 //Extended bits 2-4

	//Fix values that could be above range.
	*(bytes + 72) = rand() % 16; //Memory error type

	//Fix error status.
	create_valid_error_section(bytes + 8);

	//Set return values, exit.
	*location = bytes;
	return size;
}

//Generates a single pseudo-random memory 2 error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_memory2(void **location)
{
	//Create random bytes.
	int size = 96;
	UINT8 *bytes = generate_random_bytes(size);

	//Set reserved areas to zero.
	UINT64 *validation = (UINT64 *)bytes;
	*validation &= 0x2FFFFF; //Validation 22-63
	*(bytes + 63) = 0;	 //Reserved byte 63

	//Fix values that could be above range.
	*(bytes + 61) = rand() % 16; //Memory error type
	*(bytes + 62) = rand() % 2;  //Status

	//Fix error status.
	create_valid_error_section(bytes + 8);

	//Set return values, exit.
	*location = bytes;
	return size;
}
