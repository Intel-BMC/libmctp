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

struct mctp_binding_astpcie *mctp_astpcie_init(void);

struct mctp_binding *mctp_astpcie_core(struct mctp_binding_astpcie *b);

int mctp_astpcie_poll(struct mctp_binding_astpcie *astpcie, int timeout);

int mctp_astpcie_rx(struct mctp_binding_astpcie *astpcie);

void mctp_astpcie_free(struct mctp_binding_astpcie *astpcie);

int mctp_astpcie_get_fd(struct mctp_binding_astpcie *astpcie);

int mctp_astpcie_get_bdf(struct mctp_binding_astpcie *astpcie, uint16_t *bdf);

uint8_t mctp_astpcie_get_medium_id(struct mctp_binding_astpcie *astpcie);

/*
 * Routing types
 */
enum mctp_astpcie_msg_routing {
	PCIE_ROUTE_TO_RC = 0,
	PCIE_ROUTE_BY_ID = 2,
	PCIE_BROADCAST_FROM_RC = 3
};

/*
 * Extended data for transport layer control
 */
struct mctp_astpcie_pkt_private {
	enum mctp_astpcie_msg_routing routing;
	/* source (rx)/target (tx) endpoint bdf */
	uint16_t remote_id;
} __attribute__((__packed__));

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ASTPCIE_H */
