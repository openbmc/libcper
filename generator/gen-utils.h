#ifndef GEN_UTILS_H
#define GEN_UTILS_H

#include "../common-utils.h"
#include "../edk/BaseTypes.h"

#include <stdlib.h>

#define CPER_ERROR_TYPES_KEYS                                                  \
    (int[])                                                                    \
    {                                                                          \
        1, 16, 4, 5, 6, 7, 8, 9, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26        \
    }

size_t generate_random_section(void** location, size_t size);
UINT8* generate_random_bytes(size_t size);
void init_random();
void create_valid_error_section(UINT8* start);
UINT8 int_to_bcd(int value);

#endif
