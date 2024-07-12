/**
 * Utility functions to assist in generating pseudo-random CPER sections.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdlib.h>
#include <time.h>
#include "../edk/BaseTypes.h"
#include "gen-utils.h"

//Generates a random section of the given byte size, saving the result to the given location.
//Returns the length of the section as passed in.
size_t generate_random_section(void **location, size_t size)
{
	*location = generate_random_bytes(size);
	return size;
}

//Generates a random byte allocation of the given size.
UINT8 *generate_random_bytes(size_t size)
{
	UINT8 *bytes = malloc(size);
	for (size_t i = 0; i < size; i++) {
		bytes[i] = rand();
	}
	return bytes;
}

//Creates a valid common CPER error section, given the start of the error section.
//Clears reserved bits.
void create_valid_error_section(UINT8 *start)
{
	//Fix reserved bits.
	UINT64 *error_section = (UINT64 *)start;
	*error_section &= ~0xFF;    //Reserved bits 0-7.
	*error_section &= 0x7FFFFF; //Reserved bits 23-63

	//Ensure error type has a valid value.
	*(start + 1) =
		CPER_ERROR_TYPES_KEYS[rand() % (sizeof(CPER_ERROR_TYPES_KEYS) /
						sizeof(int))];
}

//Initializes the random seed for rand() using the current time.
void init_random()
{
	srand((unsigned int)time(NULL));
}
