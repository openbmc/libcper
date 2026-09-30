/**
 * Functions for generating pseudo-random CPER MTIA (Meta Training and Inference
 * Accelerator) OEM error sections.
 *
 **/

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <libcper/BaseTypes.h>
#include <libcper/common-utils.h>
#include <libcper/generator/gen-utils.h>
#include <libcper/generator/sections/gen-section.h>

//Generates a single pseudo-random MTIA error section, saving the resulting
//address to the given location. Returns the size of the newly created section.
size_t generate_section_mtia(void **location,
			     GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	(void)validBitsType;

	size_t size = sizeof(EFI_MTIA_ERROR_DATA);
	UINT8 *section = generate_random_bytes(size);

	EFI_MTIA_ERROR_DATA *mtia_error = (EFI_MTIA_ERROR_DATA *)section;

	//Reserved fields must round-trip as zero.
	mtia_error->Reserved1 = 0;
	memset(mtia_error->Reserved2, 0, sizeof(mtia_error->Reserved2));

	//Byte 1 = major, byte 0 = minor: v1.0.
	mtia_error->Version = 0x0100;
	mtia_error->RecordSize = (UINT16)size;

	//Severity is 0-3 (Info/Warning/Recoverable/Fatal).
	mtia_error->Severity %= 4;

	//EventId is a 12-bit identifier.
	mtia_error->EventId &= 0x0FFF;

	//DetailLength must not exceed the EventDetailRaw payload size.
	mtia_error->DetailLength %= sizeof(mtia_error->EventDetailRaw) + 1;

	*location = section;
	return size;
}
