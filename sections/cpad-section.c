/**
 * Describes available sections to the CPAD parser.
 *
 * Author: Lawrence.Tang@arm.com
 * Author: drewwalton@microsoft.com
 **/
#include <libcper/Cpad.h>
#include <libcper/sections/cpad-section.h>
#include <libcper/sections/cpad-section-os-generic.h>

// Definitions of all sections available to the CPAD parser.
//   Note that few standard CPAD sections are expected to be defined; most
//   sections will be vendor-specific.
CPAD_SECTION_DEFINITION cpad_section_definitions[] = {
	{ &gEfiCpadOsGenericSectionGuid, "OS Generic",
	  "GenericOS", cpad_section_os_generic_to_ir,
	  ir_section_os_generic_to_cpad },
};
const size_t cpad_section_definitions_len =
	sizeof(cpad_section_definitions) / sizeof(CPAD_SECTION_DEFINITION);
