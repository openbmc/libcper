/**
 * Functions for generating pseudo-random CPER PCIe error sections.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdlib.h>
#include "../../edk/BaseTypes.h"
#include "../gen-utils.h"
#include "gen-section.h"

#define PCIE_PORT_TYPES                                                        \
	(int[])                                                                \
	{                                                                      \
		0, 1, 4, 5, 6, 7, 8, 9, 10                                     \
	}

//Generates a single pseudo-random PCIe error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_pcie(void **location)
{
	//Create random bytes.
	int size = 208;
	UINT8 *bytes = generate_random_bytes(size);

	//Set reserved areas to zero.
	UINT64 *validation = (UINT64 *)bytes;
	*validation &= 0xFF;   //Validation 8-63
	UINT32 *version = (UINT32 *)(bytes + 12);
	*version &= 0xFFFF;    //Version bytes 2-3
	UINT32 *reserved = (UINT32 *)(bytes + 20);
	*reserved = 0;	       //Reserved bytes 20-24
	*(bytes + 37) &= ~0x7; //Device ID byte 13 bits 0-3
	*(bytes + 39) = 0;     //Device ID byte 15

	//Set expected values.
	int minor = rand() % 128;
	int major = rand() % 128;
	*version = int_to_bcd(minor);
	*version |= int_to_bcd(major) << 8;

	//Fix values that could be above range.
	UINT32 *port_type = (UINT32 *)(bytes + 8);
	*port_type = PCIE_PORT_TYPES[rand() %
				     (sizeof(PCIE_PORT_TYPES) / sizeof(int))];

	//Set return values, exit.
	*location = bytes;
	return size;
}
