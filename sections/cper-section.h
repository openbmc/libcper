#ifndef CPER_SECTION_H
#define CPER_SECTION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include <stdio.h>
#include <stdlib.h>
#include "../edk/Cper.h"

//Definition structure for a single CPER section type.
typedef struct {
	EFI_GUID *Guid;
	const char *ReadableName;
	json_object *(*ToIR)(void *);
	void (*ToCPER)(json_object *, FILE *);
} CPER_SECTION_DEFINITION;

extern CPER_SECTION_DEFINITION section_definitions[];
extern const size_t section_definitions_len;

#ifdef __cplusplus
}
#endif

#endif
