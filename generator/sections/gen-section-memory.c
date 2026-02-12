/**
 * Functions for generating pseudo-random CPER platform memory error sections.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdlib.h>
#include <libcper/BaseTypes.h>
#include <libcper/generator/gen-utils.h>
#include <libcper/generator/sections/gen-section.h>

//Generates a single pseudo-random platform memory error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_memory(void **location,
			       GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	//Create random bytes.
	int size = 80;
	UINT8 *bytes = generate_random_bytes(size);

	//Set reserved areas to zero.
	UINT64 *validation = (UINT64 *)bytes;
	//Validation 22-63 reserved. 19/20=0 for bank
	*validation &= 0x27FFFF;
	if (validBitsType == ALL_VALID) {
		*validation = 0x27FFFF;
	} else if (validBitsType == SOME_VALID) {
		*validation = 0x275555;
	}
	*(bytes + 73) &= ~0x1C; //Extended bits 2-4

	//Fix values that could be above range.
	*(bytes + 72) = cper_rand() % 16; //Memory error type

	//Fix error status.
	create_valid_error_status(bytes + 8);

	//Set return values, exit.
	*location = bytes;
	return size;
}

//Generates a single pseudo-random memory 2 error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_memory2(void **location,
				GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	//Create random bytes.
	int size = 96;
	UINT8 *bytes = generate_random_bytes(size);

	//Set reserved areas to zero.
	UINT64 *validation = (UINT64 *)bytes;
	//Validation 22-63, 20/21 is 0 since 6 is valid
	*validation &= 0xFFFFF;
	if (validBitsType == ALL_VALID) {
		*validation = 0xFFFFF;
	} else if (validBitsType == SOME_VALID) {
		*validation = 0x55555;
	}
	*(bytes + 63) = 0; //Reserved byte 63

	//Fix values that could be above range.
	*(bytes + 61) = cper_rand() % 16; //Memory error type
	*(bytes + 62) = cper_rand() % 2;  //Status

	//Fix error status.
	create_valid_error_status(bytes + 8);

	//Set return values, exit.
	*location = bytes;
	return size;
}
