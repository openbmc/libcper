#ifndef CPER_SECTION_PLATFORM_ACTION_EVENT
#define CPER_SECTION_PLATFORM_ACTION_EVENT

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include <libcper/Cper.h>

json_object *cper_section_platform_action_event_to_ir(const UINT8 *section, UINT32 size);
void ir_section_platform_action_event_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
