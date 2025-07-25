/* SPDX-License-Identifier: Apache-2.0 */

#ifndef LIBCPER_LOG_H
#define LIBCPER_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

void cper_set_log_stdio(void);
void cper_set_log_custom(void (*fn)(const char *, ...));

void cper_print_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#ifdef __cplusplus
}
#endif

#endif /* LIBCPER_LOG_H */
