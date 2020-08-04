/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include "libmctp-astpcie.h"
#include "libmctp-cmds.h"
#include "libmctp-log.h"

#include <poll.h>

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(x) "test: " x
#endif

#define INIT_EID 0x00

struct mctp_ctrl_req {
	struct mctp_ctrl_msg_hdr hdr;
	uint8_t data[MCTP_BTU];
};

struct mctp_ctrl_resp {
	struct mctp_ctrl_msg_hdr hdr;
	uint8_t completion_code;
	uint8_t data[MCTP_BTU];
} resp;

struct ctx {
	struct mctp *mctp;
	struct mctp_binding *astpcie_binding;
	mctp_eid_t eid;
	bool discovered;
	uint16_t bus_owner_bdf;
};

static int discovery_prepare_broadcast_resp(void)
{
	mctp_prdebug("Broadcast");

	resp.completion_code = 0;

	return 1;
}

static int discovery_prepare_get_endpoint_id_resp(void)
{
	mctp_prdebug("Get endpoint ID");

	resp.completion_code = 0;

	resp.data[0] = 0; /* Endpoint ID not yet assigned */
	resp.data[1] = 0; /* Simple Endpoint */
	resp.data[2] = 0; /* Medium specific */

	return 4;
}

static int discovery_prepare_set_endpoint_id_resp(mctp_eid_t eid)
{
	mctp_prdebug("Set endpoint ID");

	resp.completion_code = 0;

	resp.data[0] = 0; /* Endpoint ID accepted */
	resp.data[1] = eid;
	resp.data[2] = 0; /* No dynamic pool eid */

	return 4;
}

static void discovery_handle_notify_resp(void)
{
	mctp_prdebug("Response for Discovery Notify");
}

static void rx_control_message(mctp_eid_t src, void *data, void *msg,
			       size_t len, void *ext)
{
	struct mctp_ctrl_req *req = (struct mctp_ctrl_req *)msg;
	struct mctp_astpcie_pkt_private *pkt_prv =
		(struct mctp_astpcie_pkt_private *)ext;
	int resp_len = sizeof(struct mctp_ctrl_msg_hdr);
	struct ctx *ctx = (struct ctx *)data;
	uint8_t cmd;
	int rc;

	assert(req);
	assert(pkt_prv);
	assert(ctx);

	cmd = req->hdr.command_code;
	memcpy(&resp.hdr, &req->hdr, sizeof(struct mctp_ctrl_msg_hdr));

	resp.hdr.rq_dgram_inst &= ~(MCTP_CTRL_HDR_FLAG_REQUEST);

	switch (cmd) {
	case MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY:
	case MCTP_CTRL_CMD_ENDPOINT_DISCOVERY:
		pkt_prv->routing = PCIE_ROUTE_TO_RC;
		ctx->bus_owner_bdf = pkt_prv->remote_id;
		pkt_prv->remote_id = 0x00;
		resp_len += discovery_prepare_broadcast_resp();
		break;
	case MCTP_CTRL_CMD_GET_ENDPOINT_ID:
		pkt_prv->routing = PCIE_ROUTE_BY_ID;
		resp_len += discovery_prepare_get_endpoint_id_resp();
		break;
	case MCTP_CTRL_CMD_SET_ENDPOINT_ID:
		ctx->discovered = true;
		ctx->eid = req->data[1];
		pkt_prv->routing = PCIE_ROUTE_BY_ID;
		resp_len += discovery_prepare_set_endpoint_id_resp(ctx->eid);
		break;

	default:
		mctp_prwarn("Not handled: %d", cmd);
		return;
	}

#ifdef MCTP_ASTPCIE_RESPONSE_WA
	pkt_prv->flags_seq_tag &= ~(MCTP_HDR_FLAG_TO);
#endif
	mctp_binding_set_tx_enabled(ctx->astpcie_binding, true);
	rc = mctp_message_tx(ctx->mctp, src, &resp, resp_len, (void *)pkt_prv);
}

static void rx_message(mctp_eid_t src, void *data, void *msg, size_t len,
		       void *msg_binding_private)
{
	struct mctp_ctrl_resp *resp = (struct mctp_ctrl_resp *)msg;
	uint8_t cmd = resp->hdr.command_code;

	/* XXX: For the test purposes - we don't expect other type of command */
	switch (cmd) {
	case MCTP_CTRL_CMD_DISCOVERY_NOTIFY:
		discovery_handle_notify_resp();
		break;

	default:
		mctp_prwarn("Not handled: %d", cmd);
		return;
	}
}

static void discovery_regular_flow(struct mctp_binding_astpcie *astpcie,
				   struct ctx *ctx)
{
	int rc;

	while (!ctx->discovered) {
		rc = mctp_astpcie_poll(astpcie, 1000);
		if (rc & POLLIN) {
			rc = mctp_astpcie_rx(astpcie);
			assert(rc == 0);
		}
	}
}

static void discovery_with_notify_flow(struct mctp_binding_astpcie *astpcie,
				       struct ctx *ctx)
{
	struct mctp_ctrl_req req;
	struct mctp_astpcie_pkt_private pkt_prv;
	int rc;

	ctx->discovered = false;

	req.hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	req.hdr.rq_dgram_inst |= MCTP_CTRL_HDR_FLAG_REQUEST;
	req.hdr.command_code = MCTP_CTRL_CMD_DISCOVERY_NOTIFY;

	pkt_prv.routing = PCIE_ROUTE_TO_RC;
	pkt_prv.remote_id = ctx->bus_owner_bdf;

#ifdef MCTP_ASTPCIE_RESPONSE_WA
	pkt_prv.flags_seq_tag |= MCTP_HDR_FLAG_TO;
#endif

	rc = mctp_message_tx(ctx->mctp, 0x00, &req,
			     sizeof(struct mctp_ctrl_msg_hdr), &pkt_prv);
	assert(rc == 0);

	discovery_regular_flow(astpcie, ctx);
}

int main(void)
{
	struct mctp_binding_astpcie *astpcie;
	struct mctp_binding *astpcie_binding;
	struct mctp *mctp;
	struct ctx ctx;
	int rc;

	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	mctp = mctp_init();
	assert(mctp);

	astpcie = mctp_astpcie_init();
	assert(astpcie);

	astpcie_binding = mctp_astpcie_core(astpcie);
	assert(astpcie_binding);

	rc = mctp_register_bus(mctp, astpcie_binding, INIT_EID);
	assert(rc == 0);

	ctx.mctp = mctp;
	ctx.astpcie_binding = astpcie_binding;
	ctx.discovered = false;

	mctp_set_rx_all(mctp, rx_message, &ctx);

	mctp_set_rx_ctrl(mctp, rx_control_message, &ctx);

	discovery_regular_flow(astpcie, &ctx);

	discovery_with_notify_flow(astpcie, &ctx);

	mctp_astpcie_free(astpcie);
	mctp_destroy(mctp);

	return 0;
}
