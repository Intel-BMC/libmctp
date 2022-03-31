/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_ASTI3C_H
#define _LIBMCTP_ASTI3C_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "libmctp.h"

struct mctp_binding_asti3c {
	struct mctp_binding binding;
};

struct mctp_asti3c_pkt_private {
	/* Accept the fd into the binding to carry out I/O operations */
	int fd;
} __attribute__((__packed__));

struct mctp_binding_asti3c *mctp_asti3c_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ASTI3C_H */
