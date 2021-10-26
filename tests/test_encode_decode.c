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

static void test_encode_ctrl_cmd_req_update_routing_info(void)
{
	struct get_routing_table_entry_with_address entries[1];
	/* Array to hold routing info update request*/
	uint8_t buf[256];
	struct mctp_ctrl_cmd_routing_info_update *req =
		(struct mctp_ctrl_cmd_routing_info_update *)buf;
	size_t new_size = 0;
	const size_t exp_new_size =
		sizeof(struct mctp_ctrl_cmd_routing_info_update) + 4;

	entries[0].routing_info.eid_range_size = 1;
	entries[0].routing_info.starting_eid = 9;
	entries[0].routing_info.entry_type = 2;
	entries[0].routing_info.phys_transport_binding_id = 1;
	entries[0].routing_info.phys_media_type_id = 4;
	entries[0].routing_info.phys_address_size = 1;
	entries[0].phys_address[0] = 0x12;

	assert(mctp_encode_ctrl_cmd_routing_information_update(
		req, 0xFF, entries, 1, &new_size));

	assert(new_size == exp_new_size);
	assert(req->count == 1);

	assert(!mctp_encode_ctrl_cmd_routing_information_update(
		NULL, 0xFF, entries, 1, &new_size));
	assert(!mctp_encode_ctrl_cmd_routing_information_update(req, 0xFF, NULL,
								1, &new_size));
}

static void test_encode_ctrl_cmd_rsp_get_routing_table(void)
{
	struct get_routing_table_entry_with_address entries[1];
	entries[0].routing_info.eid_range_size = 1;
	entries[0].routing_info.starting_eid = 9;
	entries[0].routing_info.entry_type = 2;
	entries[0].routing_info.phys_transport_binding_id = 1;
	entries[0].routing_info.phys_media_type_id = 4;
	entries[0].routing_info.phys_address_size = 1;
	entries[0].phys_address[0] = 0x12;

	struct mctp_ctrl_resp_get_routing_table resp;

	size_t new_size = 0;
	assert(mctp_encode_ctrl_cmd_rsp_get_routing_table(&resp, entries, 1,
							  &new_size));

	size_t exp_new_size =
		sizeof(struct mctp_ctrl_resp_get_routing_table) +
		sizeof(struct get_routing_table_entry_with_address) +
		entries[0].routing_info.phys_address_size -
		sizeof(entries[0].phys_address);
	assert(new_size == exp_new_size);
	assert(resp.completion_code == MCTP_CTRL_CC_SUCCESS);
	assert(resp.next_entry_handle == 0xFF);
	assert(resp.number_of_entries == 0x01);

	assert(!mctp_encode_ctrl_cmd_rsp_get_routing_table(NULL, entries, 1,
							   &new_size));
	assert(!mctp_encode_ctrl_cmd_rsp_get_routing_table(&resp, NULL, 1,
							   &new_size));
	assert(!mctp_encode_ctrl_cmd_rsp_get_routing_table(&resp, entries, 1,
							   NULL));
	assert(mctp_encode_ctrl_cmd_rsp_get_routing_table(&resp, entries, 0,
							  &new_size));
}

int main(int argc, char *argv[])
{
	test_get_eid_encode();
	test_encode_ctrl_cmd_req_update_routing_info();
	test_encode_ctrl_cmd_rsp_get_routing_table();

	return EXIT_SUCCESS;
}
