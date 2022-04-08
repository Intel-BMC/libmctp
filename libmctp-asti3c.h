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

/* MCTP over I3C transmission unit needs to be atleast MCTP_BTU +
   MCTP_HEADER + PEC_BYTE_SIZE i.e. 69 bytes. Support buffer sizes
   of minimum transmission sizes */
#define MCTP_I3C_BUFFER_SIZE 100
#define MCTP_HEADER_SIZE 4
#define MCTP_I3C_PEC_SIZE 1

struct mctp_binding_asti3c {
	struct mctp_binding binding;
};

struct mctp_asti3c_pkt_private {
	/* Accept the fd into the binding to carry out I/O operations */
	int fd;
} __attribute__((__packed__));

struct mctp_binding_asti3c *mctp_asti3c_init(void);

void mctp_asti3c_free(struct mctp_binding_asti3c *asti3c);
int mctp_asti3c_poll(int fd, int timeout);
int mctp_asti3c_rx(struct mctp_binding_asti3c *asti3c, int fd);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ASTI3C_H */
