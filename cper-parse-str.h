#ifndef CPER_PARSE_STR_H
#define CPER_PARSE_STR_H

#ifdef __cplusplus
extern "C" {
#endif

char *cper_to_str_ir(FILE *cper_file);
char *cper_single_section_to_str_ir(FILE *cper_section_file);

#ifdef __cplusplus
}
#endif

#endif
