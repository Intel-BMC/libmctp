/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "libmctp-cmds.h"
#include "libmctp-alloc.h"

#include "test-utils.h"

static const mctp_eid_t eid_1 = 9;
static const mctp_eid_t eid_2 = 10;
/*arbitrary value taken*/
static const uint8_t _instance_id = 0x05;

struct msg_payload {
	struct mctp_hdr hdr;
	struct mctp_ctrl_msg_hdr ctl_hdr;
};

struct msg_response {
	struct mctp_ctrl_msg_hdr ctl_hdr;
	uint8_t completion_code;
};

void control_message_callback(mctp_eid_t src, void *data, void *buf, size_t len,
			      bool tag_owner, uint8_t tag, void *prv)
{
	struct mctp_ctrl_msg_hdr *msg_hdr = buf;
	printf("Control message received - command code: 0x%x\n",
	       msg_hdr->command_code);
	assert(msg_hdr->command_code == MCTP_CTRL_CMD_GET_ENDPOINT_ID ||
	       msg_hdr->command_code == MCTP_CTRL_CMD_RESERVED);
	(*(uint8_t *)data)++;
}

void control_message_transport_callback(mctp_eid_t src, void *data, void *buf,
					size_t len, bool tag_owner, uint8_t tag,
					void *prv)
{
	struct mctp_ctrl_msg_hdr *msg_hdr = buf;
	printf("Transport control message received - command code: 0x%X\n",
	       msg_hdr->command_code);
	assert(msg_hdr->command_code == 0xF2);
	(*(uint8_t *)data)++;
}

int mctp_test_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	struct msg_response *resp = mctp_pktbuf_data(pkt);
	printf("Control message response sent from 0x%X: completion code 0x%X\n",
	       mctp_pktbuf_hdr(pkt)->src, resp->completion_code);
	assert(resp->completion_code == MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD);
	(*(uint8_t *)b->control_rx_data)++;
	return 0;
}

void rcv_ctrl_msg(struct mctp_binding *b, void *buf, size_t len)
{
	struct mctp_pktbuf *pkt = mctp_pktbuf_alloc(b, len);
	assert(pkt);

	memcpy(mctp_pktbuf_hdr(pkt), buf, len);
	mctp_bus_rx(b, pkt);
}

void setup_test_binding(struct mctp_binding *test_binding,
			struct mctp *test_endpoint, uint8_t *callbacks_counter)
{
	assert(test_binding != NULL);
	assert(test_endpoint != NULL);
	assert(callbacks_counter != NULL);

	memset(test_binding, 0, sizeof(*test_binding));
	test_binding->name = "test";
	test_binding->version = MCTP_VERSION;
	test_binding->tx = mctp_test_tx;
	test_binding->pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	test_binding->pkt_pad = 0;
	mctp_register_bus(test_endpoint, test_binding, eid_1);
	mctp_binding_set_tx_enabled(test_binding, true);

	mctp_set_rx_ctrl(test_endpoint, control_message_callback,
			 callbacks_counter);
	test_binding->control_rx = control_message_transport_callback;
	test_binding->control_rx_data = callbacks_counter;
}

void send_control_message(struct mctp_binding *bin)
{
	struct msg_payload ctl_msg_to_send;
	memset(&ctl_msg_to_send, 0, sizeof(ctl_msg_to_send));
	ctl_msg_to_send.hdr.ver = MCTP_VERSION;
	ctl_msg_to_send.hdr.dest = eid_1;
	ctl_msg_to_send.hdr.src = eid_2;
	ctl_msg_to_send.hdr.flags_seq_tag =
		MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM;
	ctl_msg_to_send.ctl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	ctl_msg_to_send.ctl_hdr.rq_dgram_inst = MCTP_CTRL_HDR_FLAG_REQUEST;
	ctl_msg_to_send.ctl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_ID;
	printf("Sending control message: 0x%X\n",
	       ctl_msg_to_send.ctl_hdr.command_code);

	rcv_ctrl_msg(bin, &ctl_msg_to_send, sizeof(ctl_msg_to_send));
}

void send_control_message_with_reserved_command_code(struct mctp_binding *bin)
{
	struct msg_payload ctl_msg_to_send;
	memset(&ctl_msg_to_send, 0, sizeof(ctl_msg_to_send));
	ctl_msg_to_send.hdr.ver = MCTP_VERSION;
	ctl_msg_to_send.hdr.dest = eid_1;
	ctl_msg_to_send.hdr.src = eid_2;
	ctl_msg_to_send.hdr.flags_seq_tag =
		MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM;
	ctl_msg_to_send.ctl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	ctl_msg_to_send.ctl_hdr.rq_dgram_inst = MCTP_CTRL_HDR_FLAG_REQUEST;
	ctl_msg_to_send.ctl_hdr.command_code = MCTP_CTRL_CMD_RESERVED;
	printf("Sending reserved command code in control message: 0x%X\n",
	       ctl_msg_to_send.ctl_hdr.command_code);

	rcv_ctrl_msg(bin, &ctl_msg_to_send, sizeof(ctl_msg_to_send));
}

void send_transport_control_message(struct mctp_binding *bin)
{
	struct msg_payload ctl_msg_to_send;
	memset(&ctl_msg_to_send, 0, sizeof(ctl_msg_to_send));
	ctl_msg_to_send.hdr.ver = MCTP_VERSION;
	ctl_msg_to_send.hdr.dest = eid_1;
	ctl_msg_to_send.hdr.src = eid_2;
	ctl_msg_to_send.hdr.flags_seq_tag =
		MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM;
	ctl_msg_to_send.ctl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	ctl_msg_to_send.ctl_hdr.rq_dgram_inst = MCTP_CTRL_HDR_FLAG_REQUEST;
	ctl_msg_to_send.ctl_hdr.command_code = 0xF2;
	printf("Sending transport control message: 0x%X\n",
	       ctl_msg_to_send.ctl_hdr.command_code);

	rcv_ctrl_msg(bin, &ctl_msg_to_send, sizeof(ctl_msg_to_send));
}

void send_message_set_eid(const uint8_t eid)
{
	struct mctp_ctrl_cmd_set_eid cmd_set_eid;

	assert(mctp_encode_ctrl_cmd_set_eid(
		&cmd_set_eid, (_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		set_eid, eid));

	assert(cmd_set_eid.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	assert(cmd_set_eid.ctrl_msg_hdr.rq_dgram_inst ==
	       (_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(cmd_set_eid.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);

	assert(cmd_set_eid.eid == eid);
	assert(cmd_set_eid.operation == set_eid);
}

void send_message_get_eid(void)
{
	struct mctp_ctrl_cmd_get_eid cmd_get_eid;

	assert(mctp_encode_ctrl_cmd_get_eid(
		&cmd_get_eid, (_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST)));

	assert(cmd_get_eid.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	assert(cmd_get_eid.ctrl_msg_hdr.rq_dgram_inst ==
	       (_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(cmd_get_eid.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
}

void send_message_get_uuid(void)
{
	struct mctp_ctrl_cmd_get_uuid cmd_get_uuid;

	assert(mctp_encode_ctrl_cmd_get_uuid(
		&cmd_get_uuid, (_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST)));

	assert(cmd_get_uuid.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	assert(cmd_get_uuid.ctrl_msg_hdr.rq_dgram_inst ==
	       (_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(cmd_get_uuid.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
}

void send_message_get_version_ctrl(void)
{
	struct mctp_ctrl_cmd_get_mctp_ver_support cmd_version_support;

	assert(mctp_encode_ctrl_cmd_get_ver_support(
		&cmd_version_support,
		(_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		MCTP_CTRL_HDR_MSG_TYPE));

	assert(cmd_version_support.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_VERSION_SUPPORT);
	assert(cmd_version_support.ctrl_msg_hdr.rq_dgram_inst ==
	       (_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(cmd_version_support.ctrl_msg_hdr.ic_msg_type ==
	       MCTP_CTRL_HDR_MSG_TYPE);
}

void send_cmd_get_msg_type_support(void)
{
	struct mctp_ctrl_cmd_get_msg_type_support cmd_get_msg_type_support;

	assert(mctp_encode_ctrl_cmd_get_msg_type_support(
		&cmd_get_msg_type_support,
		(_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST)));

	assert(cmd_get_msg_type_support.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT);
	assert(cmd_get_msg_type_support.ctrl_msg_hdr.rq_dgram_inst ==
	       (_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(cmd_get_msg_type_support.ctrl_msg_hdr.ic_msg_type ==
	       MCTP_CTRL_HDR_MSG_TYPE);
}

void send_cmd_get_vdm_support(struct mctp_binding *test_binding,
			      const uint8_t val)
{
	struct mctp_ctrl_cmd_get_vdm_support cmd_get_vdm_support;

	assert(mctp_encode_ctrl_cmd_get_vdm_support(
		&cmd_get_vdm_support,
		(_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST), val));

	assert(cmd_get_vdm_support.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT);
	assert(cmd_get_vdm_support.ctrl_msg_hdr.rq_dgram_inst ==
	       (_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(cmd_get_vdm_support.ctrl_msg_hdr.ic_msg_type ==
	       MCTP_CTRL_HDR_MSG_TYPE);

	assert(cmd_get_vdm_support.vendor_id_set_selector == val);
}

void send_cmd_discover_notify(struct mctp_binding *test_binding)
{
	struct mctp_ctrl_cmd_discovery_notify discovery_notify_cmd;

	assert(mctp_encode_ctrl_cmd_discovery_notify(
		&discovery_notify_cmd,
		(_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST)));

	assert(discovery_notify_cmd.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_DISCOVERY_NOTIFY);
	assert(discovery_notify_cmd.ctrl_msg_hdr.rq_dgram_inst ==
	       (_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(discovery_notify_cmd.ctrl_msg_hdr.ic_msg_type ==
	       MCTP_CTRL_HDR_MSG_TYPE);
}

void send_cmd_routing_table(struct mctp_binding *test_binding,
			    const uint8_t val)
{
	struct mctp_ctrl_cmd_get_routing_table get_routing_table_cmd;

	assert(true == mctp_encode_ctrl_cmd_get_routing_table(
			       &get_routing_table_cmd,
			       (_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
			       val));

	assert(get_routing_table_cmd.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES);
	assert(get_routing_table_cmd.ctrl_msg_hdr.rq_dgram_inst ==
	       (_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(get_routing_table_cmd.ctrl_msg_hdr.ic_msg_type ==
	       MCTP_CTRL_HDR_MSG_TYPE);

	assert(get_routing_table_cmd.entry_handle == val);
}

void send_message_negative_get_version_ctrl(struct mctp_binding *test_binding)
{
	assert(false == mctp_encode_ctrl_cmd_get_ver_support(
				NULL,
				(_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
				MCTP_CTRL_HDR_MSG_TYPE));
}

int main(int argc, char *argv[])
{
	struct mctp *test_endpoint = mctp_init();
	struct mctp_binding test_binding;

	uint8_t callback_results = 0;
	const uint8_t expected_callback_results = 3;

	setup_test_binding(&test_binding, test_endpoint, &callback_results);

	send_control_message(&test_binding);

	send_control_message_with_reserved_command_code(&test_binding);

	send_transport_control_message(&test_binding);

	/* Transport control message: */
	assert(callback_results == expected_callback_results);

	send_message_set_eid(eid_1);

	send_message_get_eid();

	send_message_get_uuid();

	send_message_get_version_ctrl();

	send_cmd_get_msg_type_support();

	send_cmd_get_vdm_support(NULL, 5);

	send_cmd_discover_notify(NULL);

	send_cmd_routing_table(NULL, 10);

	/*negative test case for eid*/
	send_message_set_eid(1);

	send_message_negative_get_version_ctrl(NULL);

	__mctp_free(test_endpoint);
}
