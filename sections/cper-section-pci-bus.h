#ifndef CPER_SECTION_PCI_BUS_H
#define CPER_SECTION_PCI_BUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include "../edk/Cper.h"

#define PCI_BUS_ERROR_VALID_BITFIELD_NAMES                                     \
	(const char *[])                                                       \
	{                                                                      \
		"errorStatusValid", "errorTypeValid", "busIDValid",            \
			"busAddressValid", "busDataValid", "commandValid",     \
			"requestorIDValid", "completerIDValid",                \
			"targetIDValid"                                        \
	}
#define PCI_BUS_ERROR_TYPES_KEYS                                               \
	(int[])                                                                \
	{                                                                      \
		0, 1, 2, 3, 4, 5, 6, 7                                         \
	}
#define PCI_BUS_ERROR_TYPES_VALUES                                             \
	(const char *[])                                                       \
	{                                                                      \
		"Unknown/OEM Specific Error", "Data Parity Error",             \
			"System Error", "Master Abort",                        \
			"Bus Timeout/No Device Present (No DEVSEL#)",          \
			"Master Data Parity Error", "Address Parity Error",    \
			"Command Parity Error"                                 \
	}

json_object *cper_section_pci_bus_to_ir(void *section);
void ir_section_pci_bus_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
