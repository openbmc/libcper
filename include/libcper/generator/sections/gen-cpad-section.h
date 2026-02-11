#ifndef GEN_CPAD_SECTIONS_H
#define GEN_CPAD_SECTIONS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <libcper/Cpad.h>

//Section generator function predefinitions.
size_t generate_cpad_section__os_generic(void **location);

//Definition structure for a single CPER section generator.
typedef struct {
	EFI_GUID *Guid;
	const char *ShortName;
	size_t (*Generate)(void **);
} CPAD_GENERATOR_DEFINITION;

extern CPAD_GENERATOR_DEFINITION cpad_generator_definitions[];
extern const size_t cpad_generator_definitions_len;

#ifdef __cplusplus
}
#endif

#endif // GEN_CPAD_SECTIONS_H
