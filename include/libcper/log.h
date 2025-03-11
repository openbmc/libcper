/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _LIBCPER_LOG_H
#define _LIBCPER_LOG_H

void cper_set_log_stdio();
void cper_set_log_custom(void (*fn)(const char *, va_list));

void cper_print_log(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

#endif /* _LIBCPER_LOG_H */