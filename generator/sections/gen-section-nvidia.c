/**
 * Functions for generating pseudo-random CPER NVIDIA error sections.
 *
 **/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../../edk/BaseTypes.h"
#include "../gen-utils.h"
#include "gen-section.h"

//Generates a single pseudo-random NVIDIA error section, saving the resulting address to the given
//location. Returns the size of the newly created section.
size_t generate_section_nvidia(void **location)
{
	const char *signatures[] = {
		"DCC-ECC",   "DCC-COH",	      "HSS-BUSY",      "HSS-IDLE",
		"CLink",     "C2C",	      "C2C-IP-FAIL",   "L0 RESET",
		"L1 RESET",  "L2 RESET",      "PCIe",	       "PCIe-DPC",
		"SOCHUB",    "CCPLEXSCF",     "CMET-NULL",     "CMET-SHA256",
		"CMET-FULL", "DRAM-CHANNELS", "PAGES-RETIRED", "CCPLEXGIC",
		"MCF",	     "GPU-STATUS",    "GPU-CONTNMT",   "SMMU",
	};

	init_random();

	//Create random bytes.
	size_t size = sizeof(EFI_NVIDIA_ERROR_DATA);
	UINT8 *section = generate_random_bytes(size);

	//Reserved byte.
	EFI_NVIDIA_ERROR_DATA *nvidia_error = (EFI_NVIDIA_ERROR_DATA *)section;
	nvidia_error->Reserved = 0;

	//Signature.
	int idx_random = rand() % (sizeof(signatures) / sizeof(signatures[0]));
	strncpy(nvidia_error->Signature, signatures[idx_random],
		sizeof(nvidia_error->Signature));

	//Set return values, exit.
	*location = section;
	return size;
}
