/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include "libmctp-astpcie.h"
#include "libmctp-cmds.h"
#include "libmctp-log.h"
#include "libmctp-msgtypes.h"

#include <poll.h>

struct mctp_ctrl_req {
	struct mctp_ctrl_msg_hdr hdr;
	uint8_t data[MCTP_BTU];
};

static void rx_control_message(mctp_eid_t src, void *data, void *msg,
			       size_t len, bool tag_owner, uint8_t tag,
			       void *ext)
{
	struct mctp_ctrl_req *req = (struct mctp_ctrl_req *)msg;
	uint8_t cmd = req->hdr.command_code;

	mctp_prdebug("Received Control Command: %d", cmd);
}

static void rx_message(mctp_eid_t src, void *data, void *msg, size_t len,
		       bool tag_owner, uint8_t tag, void *msg_binding_private)
{
	mctp_prdebug("Received a message");
}

static void wait_for_message(struct mctp_binding_astpcie *astpcie)
{
	int rc;
	bool received = false;

	while (!received) {
		rc = mctp_astpcie_poll(astpcie, 1000);
		if (rc & POLLIN) {
			rc = mctp_astpcie_rx(astpcie);
			assert(rc == 0);
			received = true;
		}
	}
}

int main(void)
{
	struct mctp_binding_astpcie *astpcie;
	struct mctp_binding *astpcie_binding;
	struct mctp *mctp;
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

	mctp_set_rx_all(mctp, rx_message, NULL);
	mctp_set_rx_ctrl(mctp, rx_control_message, NULL);

	mctp_prdebug("Register for MCTP Control");
	mctp_astpcie_register_type_handler(astpcie, MCTP_MESSAGE_TYPE_MCTP_CTRL,
					   0, 0, 0);
	wait_for_message(astpcie);
	mctp_prdebug("Unregister MCTP Control");
	mctp_astpcie_unregister_type_handler(
		astpcie, MCTP_MESSAGE_TYPE_MCTP_CTRL, 0, 0, 0);

	mctp_prdebug("Register for VDPCI; Waiting for a message...");
	mctp_astpcie_register_type_handler(astpcie, MCTP_MESSAGE_TYPE_VDPCI,
					   0x00FF, 0x00FF, 0x00FF);
	wait_for_message(astpcie);
	mctp_prdebug("Unregister VDPCI");
	mctp_astpcie_unregister_type_handler(astpcie, MCTP_MESSAGE_TYPE_VDPCI,
					     0x00FF, 0x00FF, 0x00FF);

	mctp_astpcie_free(astpcie);
	mctp_destroy(mctp);

	return 0;
}
