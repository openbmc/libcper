/**
 * Functions for generating pseudo-random CPER NVIDIA error sections.
 *
 **/

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <libcper/BaseTypes.h>
#include <libcper/generator/gen-utils.h>
#include <libcper/generator/sections/gen-section.h>

//Generates a single pseudo-random NVIDIA error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_nvidia(void **location,
			       GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	(void)validBitsType;
	const char signatures[][16] = {
		"DCC-ECC\0\0\0\0\0\0\0\0\0",
		"DCC-COH\0\0\0\0\0\0\0\0\0",
		"HSS-BUSY\0\0\0\0\0\0\0\0",
		"HSS-IDLE\0\0\0\0\0\0\0\0",
		"CLink\0\0\0\0\0\0\0\0\0\0",
		"C2C\0\0\0\0\0\0\0\0\0\0",
		"C2C-IP-FAIL\0\0\0\0\0",
		"L0 RESET\0\0\0\0\0\0\0\0",
		"L1 RESET\0\0\0\0\0\0\0\0",
		"L2 RESET\0\0\0\0\0\0\0\0",
		"PCIe\0\0\0\0\0\0\0\0",
		"PCIe-DPC\0\0\0\0\0\0\0\0",
		"SOCHUB\0\0\0\0\0\0\0\0",
		"CCPLEXSCF\0\0\0\0\0",
		"CMET-NULL\0\0\0\0\0",
		"CMET-SHA256\0\0\0\0\0",
		"CMET-FULL\0\0\0\0\0",
		"DRAM-CHANNELS\0\0\0",
		"PAGES-RETIRED\0\0\0",
		"CCPLEXGIC\0\0\0\0\0",
		"MCF\0\0\0\0\0",
		"GPU-STATUS\0\0\0\0\0\0",
		"GPU-CONTNMT\0\0\0\0\0",
		"SMMU\0\0\0\0\0\0\0\0",
		"CMET-INFO\0\0\0\0\0\0\0",
	};

	//Create random bytes.
	int numRegs = 6;
	size_t size = offsetof(EFI_NVIDIA_ERROR_DATA, Register) +
		      numRegs * sizeof(EFI_NVIDIA_REGISTER_DATA);
	UINT8 *section = generate_random_bytes(size);

	//Reserved byte.
	EFI_NVIDIA_ERROR_DATA *nvidia_error = (EFI_NVIDIA_ERROR_DATA *)section;
	nvidia_error->Reserved = 0;

	//Number of Registers.
	nvidia_error->NumberRegs = numRegs;

	//Severity (0 to 3 as defined in UEFI spec).
	nvidia_error->Severity %= 4;

	//Signature.
	int idx_random =
		cper_rand() % (sizeof(signatures) / sizeof(signatures[0]));
	memcpy(nvidia_error->Signature, signatures[idx_random],
		sizeof(nvidia_error->Signature));

	//Set return values, exit.
	*location = section;
	return size;
}
