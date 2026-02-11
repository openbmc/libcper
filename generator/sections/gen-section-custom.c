/**
 * Functions for generating pseudo-random CPER info-ppr error sections.
 *
 * Author: Custom Section Generator
 **/

#include <stdlib.h>
#include <libcper/BaseTypes.h>
#include <libcper/generator/gen-utils.h>
#include <libcper/generator/sections/gen-section.h>

//Generates a single pseudo-random info-ppr error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_info_ppr(void **location,
				 GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	(void)validBitsType;
	
	//Create random bytes for the custom section.
	//You can adjust the size as needed for your custom section structure.
	int size = 64;
	UINT8 *bytes = generate_random_bytes(size);

	//If your custom section has reserved areas, set them to zero here.
	//Example: *(bytes + offset) = 0;

	//If your custom section has specific fields with expected values, set them here.
	//Example: *(bytes + offset) = expected_value;

	//Set return values, exit.
	*location = bytes;
	return size;
}
