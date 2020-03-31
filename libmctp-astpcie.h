/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_ASTPCIE_H
#define _LIBMCTP_ASTPCIE_H

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

struct mctp_binding_astpcie;

struct mctp_binding_astpcie *mctp_binding_astpcie_init(void);

struct mctp_binding *mctp_binding_astpcie_core(struct mctp_binding_astpcie *b);

int mctp_binding_astpcie_poll(struct mctp_binding *binding, int timeout);

int mctp_binding_astpcie_rx(struct mctp_binding *binding, mctp_eid_t dest,
			    void *payload, size_t payload_size);

void mctp_binding_astpcie_free(struct mctp_binding_astpcie *b);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ASTPCIE_H */
