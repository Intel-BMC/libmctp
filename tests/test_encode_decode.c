/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "libmctp-cmds.h"

static void test_get_eid_encode()
{
	bool ret;
	uint8_t expected_instance_id = 0x01;
	uint8_t instance_id;
	uint8_t rq;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_ctrl_cmd_get_eid get_eid_cmd;

	ret = mctp_encode_ctrl_cmd_get_eid(&get_eid_cmd, rq_d_inst);
	assert(ret == true);
	assert(get_eid_cmd.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	assert(get_eid_cmd.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);

	instance_id = get_eid_cmd.ctrl_msg_hdr.rq_dgram_inst &
		      MCTP_CTRL_HDR_INSTANCE_ID_MASK;
	assert(expected_instance_id == instance_id);

	rq = get_eid_cmd.ctrl_msg_hdr.rq_dgram_inst &
	     MCTP_CTRL_HDR_FLAG_REQUEST;
	assert(rq == MCTP_CTRL_HDR_FLAG_REQUEST);
}

int main(int argc, char *argv[])
{
	test_get_eid_encode();

	return EXIT_SUCCESS;
}
