/**
 * Functions for generating pseudo-random CPER generic processor sections.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdlib.h>
#include <libcper/BaseTypes.h>
#include <libcper/generator/gen-utils.h>
#include <libcper/generator/sections/gen-section.h>

//Generates a single pseudo-random generic processor section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_generic(void **location,
				GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	//Create random bytes.
	size_t size = generate_random_section(location, 192);

	//Set reserved locations to zero.
	UINT8 *start_byte = (UINT8 *)*location;
	UINT64 *validation = (UINT64 *)*location;
	*validation &= 0x1FFF;
	if (validBitsType == ALL_VALID) {
		*validation = 0x1FFF;
	} else if (validBitsType == SOME_VALID) {
		*validation = 0x1555;
	}
	*(start_byte + 12) &= 0x7;
	*((UINT16 *)(start_byte + 14)) = 0x0;

	//Ensure CPU brand string does not terminate early.
	for (int i = 0; i < 128; i++) {
		UINT8 *byte = start_byte + 24 + i;
		//Ensure only printable ascii is used
		*byte = cper_rand() % (0x7f - 0x20) + 0x20;

		//Null terminate last byte.
		if (i == 127) {
			*byte = 0x0;
		}
	}

	return size;
}
