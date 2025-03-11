/**
 * Functions for generating pseudo-random CXL component error sections.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdlib.h>
#include <libcper/BaseTypes.h>
#include <libcper/generator/gen-utils.h>
#include <libcper/generator/sections/gen-section.h>

//Generates a single pseudo-random CXL component error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_cxl_component(void **location,
				      GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	//Create a random length for the CXL component event log.
	//The logs attached here do not necessarily conform to the specification, and are simply random.
	int log_len = cper_rand() % 64;

	//Create random bytes.
	int size = 32 + log_len;
	UINT8 *bytes = generate_random_bytes(size);

	//Set reserved areas to zero.
	UINT32 *validation = (UINT32 *)(bytes + 4);
	*validation &= 0x7;
	if (validBitsType == ALL_VALID) {
		*validation = 0x7;
	} else if (validBitsType == SOME_VALID) {
		*validation = 0x5;
	}
	*(validation + 1) = 0;
	UINT8 *slot_number = (UINT8 *)(bytes + 21);
	*slot_number &= ~0x7; //Device ID slot number bits 0-2.
	*(bytes + 23) = 0;    //Device ID byte 11.

	//Set expected values.
	UINT32 *length = (UINT32 *)bytes;
	*length = size;

	//Set return values, exit.
	*location = bytes;
	return size;
}
