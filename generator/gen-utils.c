/**
 * Utility functions to assist in generating pseudo-random CPER sections.
 *
 * Author: Lawrence.Tang@arm.com
 *         drewwalton@microsoft.com
 **/
#include <stdlib.h>
#include <time.h>
#include <libcper/BaseTypes.h>
#include <libcper/generator/gen-utils.h>

UINT32 lfsr = 0xACE1u;

void cper_rand_seed(UINT32 seed)
{
	lfsr = seed;
}

UINT32 cper_rand(void)
{
	lfsr |= lfsr == 0; // if x == 0, set x = 1 instead
	lfsr ^= (lfsr & 0x0007ffff) << 13;
	lfsr ^= lfsr >> 17;
	lfsr ^= (lfsr & 0x07ffffff) << 5;
	return lfsr;
}

UINT64 cper_rand64()
{
	UINT64 result = (UINT64)cper_rand();
	result = result << 32;
	result |= (UINT64)cper_rand();

	return result;
}

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
		bytes[i] = cper_rand();
	}
	return bytes;
}

// Generates a null terminated string of printable chracters
void generate_random_printable_string(char *dest, size_t length)
{
	for (size_t i = 0; i < length; i++) {
		dest[i] = cper_rand() % ('z' - 'a') + 'a';
	}
	dest[length - 1] = 0;
}

//Creates a valid common CPER Error Status Field, given the start of the Error Status.
//This Error Status Field is defined in section N.2.1.2 of the CPER specification Version 2.9

//Clears reserved bits.//Clears reserved bits.
void create_valid_error_status(UINT8 *error_status_field)
{
	//Fix reserved bits
	UINT64 *error_status64 = (UINT64 *)error_status_field;
	*error_status64 &= 0x7FFF00; //Zero out reserved bits 0-7 and 23-63

	//Ensure error type has a valid value.
	*(error_status_field + 1) = CPER_ERROR_TYPES_KEYS[cper_rand() %
					     (sizeof(CPER_ERROR_TYPES_KEYS) /
					      sizeof(int))];
}

EFI_GUID generate_random_guid()
{
    EFI_GUID guid;
    guid.Data1 = cper_rand();
    guid.Data2 = (UINT16)cper_rand();
    guid.Data3 = (UINT16)cper_rand();
    for(int i=0; i<8; i++) {
        guid.Data4[i] = (UINT8)cper_rand();
    }
    return guid;
}

void generate_random_timestamp(EFI_ERROR_TIME_STAMP *timestamp)
{
    timestamp->Century = int_to_bcd(cper_rand() % 100);
    timestamp->Year = int_to_bcd(cper_rand() % 100);
    timestamp->Month = int_to_bcd(cper_rand() % 12 + 1);
    timestamp->Day = int_to_bcd(cper_rand() % 31 + 1);
    timestamp->Hours = int_to_bcd(cper_rand() % 24 + 1);
    timestamp->Seconds = int_to_bcd(cper_rand() % 60);
    timestamp->Flag = cper_rand() % 2; // Randomly set precise bit
}

// Generates a random null-terminated string of printable ASCII characters.
void generate_random_string(char *buffer, size_t buffer_size)
{
    for (size_t i = 0; i < buffer_size - 1; i++) {
        // Printable ASCII range: 0x20 (space) to 0x7E (~)
        buffer[i] = (char)(cper_rand() % (0x7E - 0x20 + 1) + 0x20);
    }
    buffer[buffer_size-1] = '\0';
}

