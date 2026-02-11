/**
 * Describes available section generators to the CPER generator.
 *
 * Author: Lawrence.Tang@arm.com
 *         drewwalton@microsoft.com
 **/
#include <libcper/generator/sections/gen-cpad-section.h>

CPAD_GENERATOR_DEFINITION cpad_generator_definitions[] = {
	{ &gEfiCpadOsGenericSectionGuid, "os-generic",
	  generate_cpad_section__os_generic },
};
const size_t cpad_generator_definitions_len =
	sizeof(cpad_generator_definitions) / sizeof(CPAD_GENERATOR_DEFINITION);