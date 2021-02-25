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

int mctp_astpcie_get_eid_info_ioctl(struct mctp_binding_astpcie *astpcie,
				    void *eid_info, uint16_t count,
				    uint8_t start_eid);

int mctp_astpcie_set_eid_info_ioctl(struct mctp_binding_astpcie *astpcie,
				    void *eid_info, uint16_t count);

int mctp_astpcie_register_default_handler(struct mctp_binding_astpcie *astpcie);

int mctp_astpcie_register_type_handler(struct mctp_binding_astpcie *astpcie,
				       uint8_t mctp_type,
				       uint16_t pci_vendor_id,
				       uint16_t vendor_type,
				       uint16_t vendor_type_mask);

int mctp_astpcie_unregister_type_handler(struct mctp_binding_astpcie *astpcie,
					 uint8_t mctp_type,
					 uint16_t pci_vendor_id,
					 uint16_t vendor_type,
					 uint16_t vendor_type_mask);

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
