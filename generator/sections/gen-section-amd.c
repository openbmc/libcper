/**
 * Functions for generating pseudo-random CPER AMD error sections.
 *
 **/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../../edk/BaseTypes.h"
#include "../gen-utils.h"
#include "gen-section.h"

//Generates a single pseudo-random AMD error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_fatal_amd(void **location)
{
	//Create random bytes.
	size_t total_size = sizeof(EFI_AMD_FATAL_ERROR_DATA);

	UINT8 *error_record = generate_random_bytes(total_size);

	*location = error_record;

	return total_size;
}
