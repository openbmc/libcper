/**
 * Describes common utility functions shared between CPER projects within this repository.
 * No functions here depend on json-c or b64.c.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include "edk/BaseTypes.h"
#include "common-utils.h"

//Converts the given BCD byte to a standard integer.
int bcd_to_int(UINT8 bcd)
{
	return ((bcd & 0xF0) >> 4) * 10 + (bcd & 0x0F);
}

//Converts the given integer to a single byte BCD.
UINT8 int_to_bcd(int value)
{
	UINT8 result = 0;
	int shift = 0;
	while (value > 0) {
		result |= (value % 10) << (shift++ << 2);
		value /= 10;
	}

	return result;
}
