/**
 * Functions for generating pseudo-random CPER AMPERE error sections.
 *
 **/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libcper/BaseTypes.h>
#include <libcper/generator/gen-utils.h>
#include <libcper/generator/sections/gen-section.h>

//Generates a single pseudo-random Ampere error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_ampere(void **location,
			       GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	(void)validBitsType;
	//Create random bytes.
	size_t size = sizeof(EFI_AMPERE_ERROR_DATA);
	UINT8 *section = generate_random_bytes(size);

	//Reserved byte.
	EFI_AMPERE_ERROR_DATA *ampere_error = (EFI_AMPERE_ERROR_DATA *)section;
	ampere_error->TypeId = 10;
	ampere_error->SubtypeId = 1;
	ampere_error->InstanceId = 0;

	//Set return values, exit.
	*location = section;
	return size;
}
