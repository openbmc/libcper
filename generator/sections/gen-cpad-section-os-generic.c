/**
 * Functions for generating pseudo-random CPER generic processor sections.
 *
 * Author: Lawrence.Tang@arm.com
 *         drewwalton@microsoft.com
 **/

#include <stdlib.h>
#include <libcper/BaseTypes.h>
#include <libcper/Cpad.h>
#include <libcper/generator/gen-utils.h>
#include <libcper/generator/sections/gen-cpad-section.h>

//Generates a single pseudo-random generic processor section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_cpad_section__os_generic(void **location)
{
	size_t size = sizeof(OS_GENERIC_CPAD_DATA);
	OS_GENERIC_CPAD_DATA *section = (OS_GENERIC_CPAD_DATA *)calloc(1, size);
	section->Operation = cper_rand64();
	section->TargetAddr = cper_rand64();
	section->Parameter1 = cper_rand64();
	section->Parameter2 = cper_rand64();
	section->Parameter3 = cper_rand64();
	*location =	section;
	return size;
}
