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

/*
 * BDF representation in mctp o/PCIe VDM frame
 */
struct bdf {
	uint8_t bus;
#define BDF_DEVICE_SHIFT (3)
#define BDF_DEVICE_MASK (0x1F)
#define BDF_FUNCTION_SHIFT (0)
#define BDF_FUNCTION_MASK (0x7)
	uint8_t dev_fun;
} __attribute__((__packed__));

/*
 * Routing types
 */
enum pcie_message_routing {
	PCIE_ROUTE_TO_ROOT_COMPLEX = 0,
	PCIE_RESERVED = 1,
	PCIE_ROUTE_BY_ID = 2,
	PCIE_BROADCAST_FROM_ROOT = 3
};

/*
 * Extended data for transport layer control
 */
struct pcie_request_extra {
	enum pcie_message_routing routing;
	/* physical address of this endpoint */
	struct bdf local_id;
	/* source (rx)/target (tx) endpoint bdf */
	struct bdf remote_id;
};

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ASTPCIE_H */
