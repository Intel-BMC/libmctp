/* SPDX-License-Identifier: Apache-2.0 */

#include "libmctp-alloc.h"
#include "libmctp-asti3c.h"

static int mctp_asti3c_tx(struct mctp_binding *binding, struct mctp_pktbuf *pkt)
{
	/* TODO: Implement TX functionality */
	return 0;
}

struct mctp_binding_asti3c *mctp_asti3c_init(void)
{
	struct mctp_binding_asti3c *asti3c;

	asti3c = __mctp_alloc(sizeof(*asti3c));
	if (!asti3c)
		return NULL;

	memset(asti3c, 0, sizeof(*asti3c));

	asti3c->binding.name = "asti3c";
	asti3c->binding.version = 1;
	asti3c->binding.tx = mctp_asti3c_tx;
	asti3c->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	asti3c->binding.pkt_priv_size = sizeof(struct mctp_asti3c_pkt_private);

	return asti3c;
}
