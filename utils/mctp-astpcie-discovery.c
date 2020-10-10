/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include "libmctp-astpcie.h"
#include "libmctp-cmds.h"
#include "libmctp-log.h"

#include <poll.h>

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(x) "test: " x
#endif

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
	mctp_eid_t bus_owner_eid;
};

static int discovery_prepare_broadcast_resp(void)
{
	mctp_prdebug("Broadcast");

	resp.completion_code = 0;

	return 1;
}

static int discovery_prepare_get_endpoint_id_resp(struct ctx *ctx)
{
	struct mctp_ctrl_resp_get_eid *get_eid_resp;
	int rc;

	mctp_prdebug("Get endpoint ID");

	get_eid_resp = (struct mctp_ctrl_resp_get_eid *)&resp;

	rc = mctp_ctrl_cmd_get_endpoint_id(ctx->mctp, ctx->bus_owner_eid, false,
					   get_eid_resp);

	assert(rc == 0);

	return 4;
}

static int discovery_prepare_set_endpoint_id_resp(struct ctx *ctx,
						  struct mctp_ctrl_req *req)
{
	struct mctp_ctrl_resp_set_eid *set_eid_resp;
	struct mctp_ctrl_cmd_set_eid *set_eid_req;
	int rc;

	mctp_prdebug("Set endpoint ID");

	set_eid_req = (struct mctp_ctrl_cmd_set_eid *)req;
	set_eid_resp = (struct mctp_ctrl_resp_set_eid *)&resp;

	rc = mctp_ctrl_cmd_set_endpoint_id(ctx->mctp, ctx->bus_owner_eid,
					   set_eid_req, set_eid_resp);

	assert(rc == 0);

	return 4;
}

static void discovery_handle_notify_resp(void)
{
	mctp_prdebug("Response for Discovery Notify");
}

static void rx_control_message(mctp_eid_t src, void *data, void *msg,
			       size_t len, bool tag_owner, uint8_t tag,
			       void *ext)
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
		ctx->discovered = false;
		pkt_prv->routing = PCIE_ROUTE_TO_RC;
		ctx->bus_owner_bdf = pkt_prv->remote_id;
		pkt_prv->remote_id = 0x00;
		resp_len += discovery_prepare_broadcast_resp();
		break;
	case MCTP_CTRL_CMD_ENDPOINT_DISCOVERY:
		if (ctx->discovered == true) {
			mctp_prwarn("Not handled: %d", cmd);
			return;
		}
		pkt_prv->routing = PCIE_ROUTE_TO_RC;
		ctx->bus_owner_bdf = pkt_prv->remote_id;
		pkt_prv->remote_id = 0x00;
		resp_len += discovery_prepare_broadcast_resp();
		break;
	case MCTP_CTRL_CMD_GET_ENDPOINT_ID:
		pkt_prv->routing = PCIE_ROUTE_BY_ID;
		resp_len += discovery_prepare_get_endpoint_id_resp(ctx);
		break;
	case MCTP_CTRL_CMD_SET_ENDPOINT_ID:
		ctx->discovered = true;
		ctx->eid = req->data[1];
		pkt_prv->routing = PCIE_ROUTE_BY_ID;
		resp_len += discovery_prepare_set_endpoint_id_resp(ctx, req);
		break;

	default:
		mctp_prwarn("Not handled: %d", cmd);
		return;
	}

	mctp_binding_set_tx_enabled(ctx->astpcie_binding, true);
	rc = mctp_message_tx(ctx->mctp, src, &resp, resp_len, false, tag,
			     (void *)pkt_prv);
	assert(rc == 0);
}

static void rx_message(mctp_eid_t src, void *data, void *msg, size_t len,
		       bool tag_owner, uint8_t tag, void *msg_binding_private)
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
	pkt_prv.remote_id = 0xffff;

	mctp_binding_set_tx_enabled(ctx->astpcie_binding, true);
	rc = mctp_message_tx(ctx->mctp, 0x00, &req,
			     sizeof(struct mctp_ctrl_msg_hdr), true, 0,
			     &pkt_prv);
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

	rc = mctp_register_bus_dynamic_eid(mctp, astpcie_binding);
	assert(rc == 0);

	ctx.mctp = mctp;
	ctx.astpcie_binding = astpcie_binding;
	ctx.discovered = false;
	ctx.bus_owner_eid = 8;

	mctp_set_rx_all(mctp, rx_message, &ctx);

	mctp_set_rx_ctrl(mctp, rx_control_message, &ctx);

	discovery_with_notify_flow(astpcie, &ctx);

	mctp_astpcie_free(astpcie);
	mctp_destroy(mctp);

	return 0;
}
