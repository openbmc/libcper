#ifndef CPER_BASE64_H
#define CPER_BASE64_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libcper/BaseTypes.h>

/**
 * base64_decode
 * Caller is responsible for freeing the returned buffer.
 */
UINT8 *base64_decode(const CHAR8 *src, INT32 len, INT32 *out_len);

/**
 * base64_encode
 * Caller is responsible for freeing the returned buffer.
 */
CHAR8 *base64_encode(const UINT8 *src, INT32 len, INT32 *out_len);

#ifdef __cplusplus
}
#endif

#endif
