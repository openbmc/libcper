#ifndef CPER_GEN_UTILS_H
#define CPER_GEN_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <libcper/BaseTypes.h>
#include <libcper/common-utils.h>

#define CPER_ERROR_TYPES_KEYS                                                  \
	(                                                                      \
		int[]){ 1,  16, 4,  5,	6,  7,	8,  9,	17,                    \
			18, 19, 20, 21, 22, 23, 24, 25, 26 }

size_t generate_random_section(void **location, size_t size);
UINT8 *generate_random_bytes(size_t size);

void generate_random_printable_string(char *dest, size_t length);

void cper_rand_seed(UINT32 seed);
UINT32 cper_rand(void);

void create_valid_error_section(UINT8 *start);

#ifdef __cplusplus
}
#endif

#endif
