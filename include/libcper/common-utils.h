#ifndef CPER_LIB_COMMON_UTILS_H
#define CPER_LIB_COMMON_UTILS_H

#include <libcper/BaseTypes.h>

int bcd_to_int(UINT8 bcd);
UINT8 int_to_bcd(int value);

#if defined __has_attribute
#if __has_attribute(counted_by)
#define LIBCPER_CC_COUNTED_BY(x) __attribute__((counted_by(x)))
#endif
#endif

#ifndef LIBCPER_CC_COUNTED_BY
#define LIBCPER_CC_COUNTED_BY(x)
#endif

#endif
