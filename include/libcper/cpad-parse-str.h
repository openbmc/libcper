#ifndef CPAD_PARSE_STR_H
#define CPAD_PARSE_STR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

char *cpadbuf_to_str_ir(const unsigned char *cpad, size_t size);
char *cpadbuf_single_section_to_str_ir(const unsigned char *cpad_section,
				       size_t size);

#ifdef __cplusplus
}
#endif

#endif
