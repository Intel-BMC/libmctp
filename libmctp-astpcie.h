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

void mctp_astpcie_free(struct mctp_binding_astpcie *b);

int mctp_astpcie_get_fd(struct mctp_binding_astpcie *astpcie);

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

#ifdef MCTP_ASTPCIE_RESPONSE_WA
	/*
	 * FIXME: In libmctp core there is no support for response, which means
	 * that we are not able to send MCTP packet with TO bit = 0b and MsgTag
	 * matching the request.
	 * Temporarily, as a workaround, we will store flags_seq_tag of the request's
	 * mctp_hdr in mctp_astpcie_pkt_private to be able set both fields correctly
	 * in response time.
	 * Remove, when dedicated API for response is added.
	 */
	uint8_t flags_seq_tag;
#endif
};

/* TODO: Remove, when libmctp callers use the new naming */
#define mctp_binding_astpcie_init mctp_astpcie_init
#define mctp_binding_astpcie_core mctp_astpcie_core
#define mctp_binding_astpcie_free mctp_astpcie_free

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ASTPCIE_H */
