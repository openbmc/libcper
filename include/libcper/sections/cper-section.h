#ifndef CPER_SECTION_H
#define CPER_SECTION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include <stdio.h>
#include <stdlib.h>
#include <libcper/Cper.h>

//Definition structure for a single CPER section type.
typedef struct {
	EFI_GUID *Guid;
	const char *ReadableName;
	const char *ShortName;
	json_object *(*ToIR)(const UINT8 *, UINT32, char **);
	void (*ToCPER)(json_object *, FILE *);
} CPER_SECTION_DEFINITION;

extern CPER_SECTION_DEFINITION section_definitions[];
extern const size_t section_definitions_len;

CPER_SECTION_DEFINITION *select_section_by_guid(EFI_GUID *guid);

#ifdef __cplusplus
}
#endif

#endif
