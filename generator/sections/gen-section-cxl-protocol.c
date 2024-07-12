/**
 * Functions for generating pseudo-random CXL protocol error sections.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdlib.h>
#include "../../edk/BaseTypes.h"
#include "../gen-utils.h"
#include "gen-section.h"

//Generates a single pseudo-random CXL protocol error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_cxl_protocol(void **location)
{
	//Create a random length for the CXL DVSEC and CXL error log.
	//The logs attached here do not necessarily conform to the specification, and are simply random.
	int dvsec_len = rand() % 64;
	int error_log_len = rand() % 64;

	//Create random bytes.
	int size = 116 + dvsec_len + error_log_len;
	UINT8 *bytes = generate_random_bytes(size);

	//Set CXL agent type.
	int cxl_agent_type = rand() % 2;
	*(bytes + 8) = cxl_agent_type;

	//Set reserved areas to zero.
	UINT64 *validation = (UINT64 *)bytes;
	*validation &= 0x3F;	      //Validation bits 6-63.
	for (int i = 0; i < 7; i++) {
		*(bytes + 9 + i) = 0; //Reserved bytes 9-15.
	}

	//We only reserve bytes if it's a CXL 1.1 device, and not a host downstream port.
	if (cxl_agent_type == 0) {
		for (int i = 0; i < 3; i++) {
			*(bytes + 21 + i) = 0; //CXL agent address bytes 5-7.
		}
	}

	*(bytes + 34) &= ~0x7; //Device ID byte 10 bits 0-2.
	UINT32 *reserved = (UINT32 *)(bytes + 36);
	*reserved = 0;	       //Device ID bytes 12-15.
	reserved = (UINT32 *)(bytes + 112);
	*reserved = 0;	       //Reserved bytes 112-115.

	//If the device is a host downstream port, serial/capability structure is invalid.
	if (cxl_agent_type != 0) {
		for (int i = 0; i < 68; i++) {
			*(bytes + 40 + i) =
				0; //Device serial & capability structure.
		}
	}

	//Set expected values.
	UINT16 *dvsec_length_field = (UINT16 *)(bytes + 108);
	UINT16 *error_log_len_field = (UINT16 *)(bytes + 110);
	*dvsec_length_field = dvsec_len;
	*error_log_len_field = error_log_len;

	//Set return values, exit.
	*location = bytes;
	return size;
}
