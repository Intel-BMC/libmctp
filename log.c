/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <stdarg.h>

#include "libmctp.h"
#include "libmctp-log.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef MCTP_HAVE_STDIO
#include <stdio.h>
#endif

#ifdef MCTP_HAVE_SYSLOG
#include <syslog.h>
#endif

enum { MCTP_LOG_NONE,
       MCTP_LOG_STDIO,
       MCTP_LOG_SYSLOG,
       MCTP_LOG_CUSTOM,
} log_type = MCTP_LOG_NONE;

static int log_stdio_level;
static void (*log_custom_fn)(int, const char *, va_list);

#define MAX_TRACE_BYTES 128
#define TRACE_FORMAT "%02X "
#define TRACE_FORMAT_SIZE 3

static bool trace_enable;

void mctp_prlog(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	switch (log_type) {
	case MCTP_LOG_NONE:
		break;
	case MCTP_LOG_STDIO:
#ifdef MCTP_HAVE_STDIO
		if (level <= log_stdio_level) {
			vfprintf(stderr, fmt, ap);
			fputs("\n", stderr);
		}
#endif
		break;
	case MCTP_LOG_SYSLOG:
#ifdef MCTP_HAVE_SYSLOG
		vsyslog(level, fmt, ap);
#endif
		break;
	case MCTP_LOG_CUSTOM:
		log_custom_fn(level, fmt, ap);
		break;
	}

	va_end(ap);
}

void mctp_set_log_stdio(int level)
{
	log_type = MCTP_LOG_STDIO;
	log_stdio_level = level;
}

void mctp_set_log_syslog(void)
{
	log_type = MCTP_LOG_SYSLOG;
}

void mctp_set_log_custom(void (*fn)(int, const char *, va_list))
{
	log_type = MCTP_LOG_CUSTOM;
	log_custom_fn = fn;
}

void mctp_set_tracing_enabled(bool enable)
{
	trace_enable = enable;
}

void mctp_trace_common(const char *tag, const void *const payload,
		       const size_t len)
{
	char tracebuf[MAX_TRACE_BYTES * TRACE_FORMAT_SIZE + sizeof('\0')];
	/* if len is bigger than ::MAX_TRACE_BYTES, loop will leave place for '..'
	 * at the end to indicate that whole payload didn't fit
	 */
	const size_t limit = len > MAX_TRACE_BYTES ? MAX_TRACE_BYTES - 1 : len;
	char *ptr = tracebuf;
	unsigned int i;

	if (!trace_enable || len == 0)
		return;

	for (i = 0; i < limit; i++)
		ptr += sprintf(ptr, TRACE_FORMAT, ((uint8_t *)payload)[i]);

	/* buffer saturated, probably need to increase the size */
	if (limit < len)
		sprintf(ptr, "..");

	mctp_prlog(MCTP_LOG_DEBUG, "%s %s", tag, tracebuf);
}
