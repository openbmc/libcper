/* SPDX-License-Identifier: Apache-2.0 */

#ifndef CPER_LOG_H
#define CPER_LOG_H

#include <stdarg.h>

#ifndef CPER_NO_STDIO
#include <stdio.h>
#endif

enum {
	CPER_LOG_NONE,
	CPER_LOG_STDIO,
	CPER_LOG_CUSTOM,
} log_type = CPER_LOG_STDIO;

static void (*log_custom_fn)(const char *, va_list);

void cper_print_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	switch (log_type) {
	case CPER_LOG_NONE:
		break;
	case CPER_LOG_STDIO:
#ifndef CPER_NO_STDIO
		vfprintf(stderr, fmt, ap);
		fputs("\n", stderr);
#endif
		break;
	case CPER_LOG_CUSTOM:
		log_custom_fn(fmt, ap);
		break;
	}

	va_end(ap);
}

void cper_set_log_stdio(void)
{
	log_type = CPER_LOG_STDIO;
}

void cper_set_log_custom(void (*fn)(const char *, va_list))
{
	log_type = CPER_LOG_CUSTOM;
	log_custom_fn = fn;
}

#endif /* CPER_LOG_H */
