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

void test_encode_ctrl_cmd_query_hop(void)
{
	struct mctp_ctrl_cmd_query_hop cmd_query_hop;
	uint8_t sample_eid = 8;
	uint8_t instance_id = 0x01;
	assert(mctp_encode_ctrl_cmd_query_hop(
		&cmd_query_hop, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		sample_eid, MCTP_CTRL_HDR_MSG_TYPE));

	assert(cmd_query_hop.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_QUERY_HOP);

	assert(cmd_query_hop.ctrl_msg_hdr.rq_dgram_inst ==
	       (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));

	assert(cmd_query_hop.ctrl_msg_hdr.ic_msg_type ==
	       MCTP_CTRL_HDR_MSG_TYPE);

	assert(cmd_query_hop.target_eid == sample_eid);
	assert(cmd_query_hop.mctp_ctrl_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
}

/*Negative Test cases for the commands*/

static void test_negative_encode_ctrl_cmd_query_hop()
{
	uint8_t sample_eid = 8;
	uint8_t instance_id = 0x01;
	struct mctp_ctrl_cmd_query_hop *query_hop = NULL;
	bool rc = true;
	rc = mctp_encode_ctrl_cmd_query_hop(
		query_hop, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		sample_eid, MCTP_CTRL_HDR_MSG_TYPE);
	assert(!rc);
}

static void test_allocate_eid_pool_encode()
{
	bool ret;
	const uint8_t first_eid = 9;
	const uint8_t eid_pool_size = 10;
	uint8_t expected_instance_id = 0x01;
	mctp_ctrl_cmd_allocate_eids_op operation = allocate_eids;
	struct mctp_ctrl_cmd_allocate_eids cmd_allocate_eid;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;

	ret = mctp_encode_ctrl_cmd_allocate_eids(&cmd_allocate_eid, rq_d_inst,
						 operation, eid_pool_size,
						 first_eid);
	assert(ret == true);
	assert(cmd_allocate_eid.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);
	assert(cmd_allocate_eid.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(cmd_allocate_eid.ctrl_msg_hdr.ic_msg_type ==
	       MCTP_CTRL_HDR_MSG_TYPE);

	assert(cmd_allocate_eid.operation == operation);

	assert(cmd_allocate_eid.eid_pool_size == eid_pool_size);
	assert(cmd_allocate_eid.first_eid == first_eid);
}

static void test_negation_allocate_eid_pool_encode()
{
	bool ret;
	uint8_t sample_eid = 10;
	const uint8_t eid_pool_size = 10;
	uint8_t expected_instance_id = 0x01;
	mctp_ctrl_cmd_allocate_eids_op operation = allocate_eids;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_ctrl_cmd_allocate_eids *cmd_allocate_eid = NULL;

	ret = mctp_encode_ctrl_cmd_allocate_eids(cmd_allocate_eid, rq_d_inst,
						 operation, eid_pool_size,
						 sample_eid);
	assert(ret == false);
}

int main(int argc, char *argv[])
{
	test_get_eid_encode();
	test_encode_ctrl_cmd_req_update_routing_info();
	test_encode_ctrl_cmd_rsp_get_routing_table();
	test_encode_ctrl_cmd_query_hop();
	test_allocate_eid_pool_encode();
	/*Negative test cases */
	test_negative_encode_ctrl_cmd_query_hop();
	test_negation_allocate_eid_pool_encode();

	return EXIT_SUCCESS;
}
