#ifndef CPER_SECTION_FIRMWARE_H
#define CPER_SECTION_FIRMWARE_H

#include "../edk/Cper.h"

#include <json.h>

#define FIRMWARE_ERROR_RECORD_TYPES_KEYS                                       \
    (int[])                                                                    \
    {                                                                          \
        0, 1, 2                                                                \
    }
#define FIRMWARE_ERROR_RECORD_TYPES_VALUES                                     \
    (const char*[])                                                            \
    {                                                                          \
        "IPF SAL Error Record", "SOC Firmware Error Record (Type1 Legacy)",    \
            "SOC Firmware Error Record (Type2)"                                \
    }

json_object* cper_section_firmware_to_ir(void* section);
void ir_section_firmware_to_cper(json_object* section, FILE* out);

#endif
