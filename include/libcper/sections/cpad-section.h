#ifndef CPAD_SECTION_H
#define CPAD_SECTION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include <stdio.h>
#include <stdlib.h>
#include <libcper/Cpad.h>

//Definition structure for a single CPAD section type.
typedef struct {
	EFI_GUID *Guid;
	const char *ReadableName;
	const char *ShortName;
	json_object *(*ToIR)(const UINT8 *, UINT32);
	void (*ToCPAD)(json_object *, FILE *);
} CPAD_SECTION_DEFINITION;

extern CPAD_SECTION_DEFINITION cpad_section_definitions[];
extern const size_t cpad_section_definitions_len;

CPAD_SECTION_DEFINITION *cpad_select_section_by_guid(EFI_GUID *guid);

#ifdef __cplusplus
}
#endif

#endif
