/**
 * Functions for generating pseudo-random CCIX PER error sections.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdlib.h>
#include <libcper/BaseTypes.h>
#include <libcper/generator/gen-utils.h>
#include <libcper/generator/sections/gen-section.h>

//Generates a single pseudo-random CCIX PER error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_ccix_per(void **location,
				 GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	//Create a random length for the CCIX PER log.
	//The log attached here does not necessarily conform to the CCIX specification, and is simply random.
	int log_len = (cper_rand() % 5 + 1) * 32;

	//Create random bytes.
	int size = 16 + log_len;
	UINT8 *bytes = generate_random_bytes(size);

	//Set reserved areas to zero.
	UINT32 *validation = (UINT32 *)(bytes + 4);
	*validation &= 0x7;    //Validation bits 3-63.
	*(validation + 1) = 0; //Validation bits 3-63.
	if (validBitsType == ALL_VALID) {
		*validation = 0x7;
	} else if (validBitsType == SOME_VALID) {
		*validation = 0x5;
	}
	*(bytes + 13) &= 0x1F; //CCIX port ID bits 5-7.
	UINT16 *reserved = (UINT16 *)(bytes + 14);
	*reserved = 0;	       //Reserved bytes 14-15.

	//Set expected values.
	UINT32 *length = (UINT32 *)bytes;
	*length = size;

	//Set return values, exit.
	*location = bytes;
	return size;
}
