#include "libcper/cper-parse.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  json_object *ir = cper_buf_to_ir(data, size);
  if (ir != NULL) {
    json_object_put(ir);
  }

  return 0;
}