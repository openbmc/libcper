#ifndef CPER_SECTION_NVIDIA_H
#define CPER_SECTION_NVIDIA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <json.h>
#include <libcper/Cper.h>

static const char *channel_disable_reason_dict[] = {
	"Alias Checker Failed",		     // 0x0
	"Training at POR frequency failed",  // 0x1
	"Training at boot frequency failed", // 0x2
	"Threshold of bad pages exceeded"    // 0x3
};

static const size_t channel_disable_reason_dict_size =
	sizeof(channel_disable_reason_dict) /
	sizeof(channel_disable_reason_dict[0]);

json_object *cper_section_nvidia_to_ir(const UINT8 *section, UINT32 size);
void ir_section_nvidia_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
