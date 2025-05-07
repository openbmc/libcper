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
	const char *signatures[] = {
		"DCC-ECC",   "DCC-COH",	      "HSS-BUSY",      "HSS-IDLE",
		"CLink",     "C2C",	      "C2C-IP-FAIL",   "L0 RESET",
		"L1 RESET",  "L2 RESET",      "PCIe",	       "PCIe-DPC",
		"SOCHUB",    "CCPLEXSCF",     "CMET-NULL",     "CMET-SHA256",
		"CMET-FULL", "DRAM-CHANNELS", "PAGES-RETIRED", "CCPLEXGIC",
		"MCF",	     "GPU-STATUS",    "GPU-CONTNMT",   "SMMU",
		"CMET-INFO",
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
	strncpy(nvidia_error->Signature, signatures[idx_random],
		sizeof(nvidia_error->Signature) - 1);
	nvidia_error->Signature[sizeof(nvidia_error->Signature) - 1] = '\0';

	//Set return values, exit.
	*location = section;
	return size;
}
