/**
 * Functions for generating pseudo-random CPER firmware error sections.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdlib.h>
#include "../../edk/BaseTypes.h"
#include "../gen-utils.h"
#include "gen-section.h"

//Generates a single pseudo-random firmware error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_firmware(void **location)
{
	//Create random bytes.
	int size = 32;
	UINT8 *bytes = generate_random_bytes(size);

	//Set reserved areas to zero.
	for (int i = 0; i < 6; i++) {
		*(bytes + 2 + i) = 0; //Reserved bytes 2-7.
	}

	//Set expected values.
	*(bytes + 1) = 2;    //Revision, referenced version of spec is 2.
	UINT64 *record_id = (UINT64 *)(bytes + 8);
	*record_id = 0;	     //Record ID, should be forced to NULL.
	*bytes = rand() % 3; //Record type.

	//Set return values, exit.
	*location = bytes;
	return size;
}
