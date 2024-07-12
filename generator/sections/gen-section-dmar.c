/**
 * Functions for generating pseudo-random CPER DMAr error sections.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdlib.h>
#include "../../edk/BaseTypes.h"
#include "../gen-utils.h"
#include "gen-section.h"

//Generates a single pseudo-random generic DMAr error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_dmar_generic(void **location)
{
	//Create random bytes.
	int size = 32;
	UINT8 *bytes = generate_random_bytes(size);

	//Set reserved areas to zero.
	UINT64 *reserved = (UINT64 *)(bytes + 16);
	*reserved = 0;
	*(reserved + 1) = 0;

	//Set expected values.
	*(bytes + 4) = rand() % 0xC;   //Fault reason.
	*(bytes + 5) = rand() % 2;     //Access type.
	*(bytes + 6) = rand() % 2;     //Address type.
	*(bytes + 7) = rand() % 2 + 1; //Architecture type.

	//Set return values, exit.
	*location = bytes;
	return size;
}

//Generates a single pseudo-random VT-d DMAr error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_dmar_vtd(void **location)
{
	//Create random bytes.
	int size = 144;
	UINT8 *bytes = generate_random_bytes(size);

	//Set reserved areas to zero.
	for (int i = 0; i < 12; i++) {
		*(bytes + 36 + i) = 0; //Reserved bytes 36-47.
	}
	UINT8 *fault_record = bytes + 48;
	UINT32 *reserved = (UINT32 *)(fault_record);
	*reserved &= ~0xFFF;	     //First 12 bits of fault record.
	reserved = (UINT32 *)(fault_record + 8);
	*reserved &= ~0x1FFF0000;    //Bits 80-92 of fault record.
	*(fault_record + 15) &= 0x7; //Very last bit of fault record.

	//Set return values, exit.
	*location = bytes;
	return size;
}

//Generates a single pseudo-random IOMMU DMAr error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_dmar_iommu(void **location)
{
	//Create random bytes.
	int size = 144;
	UINT8 *bytes = generate_random_bytes(size);

	//Set reserved areas to zero.
	for (int i = 0; i < 7; i++) {
		*(bytes + 1 + i) = 0; //Reserved bytes 1 to 7.
	}
	UINT64 *reserved = (UINT64 *)(bytes + 24);
	*reserved = 0;		       //Reserved bytes 24-31.
	for (int i = 0; i < 16; i++) {
		*(bytes + 48 + i) = 0; //Reserved bytes 48-63.
	}

	//Set return values, exit.
	*location = bytes;
	return size;
}
