/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_CMDS_H
#define _LIBMCTP_CMDS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libmctp.h"

/*
 * Helper structs and functions for MCTP control messages.
 * See DSP0236 v1.3.0 sec. 11 for reference.
 */

struct mctp_ctrl_msg_hdr {
	uint8_t ic_msg_type;
	uint8_t rq_dgram_inst;
	uint8_t command_code;
} __attribute__((__packed__));

typedef enum {
	set_eid,
	force_eid,
	reset_eid,
	set_discovered_flag
} mctp_ctrl_cmd_set_eid_op;

struct mctp_ctrl_cmd_set_eid {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	mctp_ctrl_cmd_set_eid_op operation : 2;
	uint8_t : 6;
	uint8_t eid;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_eid {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_uuid {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_mctp_ver_support {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	uint8_t msg_type_number;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_msg_type_support {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_vdm_support {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	uint8_t vendor_id_set_selector;
} __attribute__((__packed__));

#define MCTP_CTRL_HDR_MSG_TYPE 0
#define MCTP_CTRL_HDR_FLAG_REQUEST (1 << 7)
#define MCTP_CTRL_HDR_FLAG_DGRAM (1 << 6)
#define MCTP_CTRL_HDR_INSTANCE_ID_MASK 0x1F

/*
 * MCTP Control Command IDs
 * See DSP0236 v1.3.0 Table 12.
 */
#define MCTP_CTRL_CMD_RESERVED 0x00
#define MCTP_CTRL_CMD_SET_ENDPOINT_ID 0x01
#define MCTP_CTRL_CMD_GET_ENDPOINT_ID 0x02
#define MCTP_CTRL_CMD_GET_ENDPOINT_UUID 0x03
#define MCTP_CTRL_CMD_GET_VERSION_SUPPORT 0x04
#define MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT 0x05
#define MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT 0x06
#define MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID 0x07
#define MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS 0x08
#define MCTP_CTRL_CMD_ROUTING_INFO_UPDATE 0x09
#define MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES 0x0A
#define MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY 0x0B
#define MCTP_CTRL_CMD_ENDPOINT_DISCOVERY 0x0C
#define MCTP_CTRL_CMD_DISCOVERY_NOTIFY 0x0D
#define MCTP_CTRL_CMD_GET_NETWORK_ID 0x0E
#define MCTP_CTRL_CMD_QUERY_HOP 0x0F
#define MCTP_CTRL_CMD_RESOLVE_UUID 0x10
#define MCTP_CTRL_CMD_QUERY_RATE_LIMIT 0x11
#define MCTP_CTRL_CMD_REQUEST_TX_RATE_LIMIT 0x12
#define MCTP_CTRL_CMD_UPDATE_RATE_LIMIT 0x13
#define MCTP_CTRL_CMD_QUERY_SUPPORTED_INTERFACES 0x14
#define MCTP_CTRL_CMD_MAX 0x15
/* 0xF0 - 0xFF are transport specific */
#define MCTP_CTRL_CMD_FIRST_TRANSPORT 0xF0
#define MCTP_CTRL_CMD_LAST_TRANSPORT 0xFF

/*
 * MCTP Control Completion Codes
 * See DSP0236 v1.3.0 Table 13.
 */
#define MCTP_CTRL_CC_SUCCESS 0x00
#define MCTP_CTRL_CC_ERROR 0x01
#define MCTP_CTRL_CC_ERROR_INVALID_DATA 0x02
#define MCTP_CTRL_CC_ERROR_INVALID_LENGTH 0x03
#define MCTP_CTRL_CC_ERROR_NOT_READY 0x04
#define MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD 0x05
/* 0x80 - 0xFF are command specific */

/* MCTP Set Endpoint ID response fields
 * See DSP0236 v1.3.0 Table 14.
 */
#define MCTP_SET_EID_STATUS(status, field)                                     \
	field = ((field)&0xcf) | ((status) << 4)
#define MCTP_SET_EID_ACCEPTED 0x0
#define MCTP_SET_EID_REJECTED 0x1
typedef union {
	struct {
		uint32_t data0;
		uint16_t data1;
		uint16_t data2;
		uint16_t data3;
		uint8_t data4[6];
	} __attribute__((__packed__)) canonical;
	uint8_t raw[16];
} guid_t;

struct mctp_ctrl_resp_get_eid {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	mctp_eid_t eid;
	uint8_t eid_type;
	uint8_t medium_data;

} __attribute__((__packed__));

struct mctp_ctrl_resp_get_uuid {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	guid_t uuid;
} __attribute__((__packed__));

struct mctp_ctrl_resp_set_eid {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	uint8_t status;
	mctp_eid_t eid_set;
	uint8_t eid_pool_size;
} __attribute__((__packed__));

bool mctp_ctrl_handle_msg(struct mctp *mctp, struct mctp_bus *bus,
			  mctp_eid_t src, mctp_eid_t dest, void *buffer,
			  size_t length, void *msg_binding_private);

int mctp_set_rx_ctrl(struct mctp *mctp, mctp_rx_fn fn, void *data);

bool mctp_encode_ctrl_cmd_set_eid(struct mctp_ctrl_cmd_set_eid *set_eid_cmd,
				  uint8_t rq_dgram_inst,
				  mctp_ctrl_cmd_set_eid_op op, uint8_t eid);

bool mctp_encode_ctrl_cmd_get_eid(struct mctp_ctrl_cmd_get_eid *get_eid_cmd,
				  uint8_t rq_dgram_inst);

bool mctp_encode_ctrl_cmd_get_uuid(struct mctp_ctrl_cmd_get_uuid *get_uuid_cmd,
				   uint8_t rq_dgram_inst);

bool mctp_encode_ctrl_cmd_get_ver_support(
	struct mctp_ctrl_cmd_get_mctp_ver_support *mctp_ver_support_cmd,
	uint8_t rq_dgram_inst, uint8_t msg_type_number);

bool mctp_encode_ctrl_cmd_get_msg_type_support(
	struct mctp_ctrl_cmd_get_msg_type_support *msg_type_support_cmd,
	uint8_t rq_dgram_inst);

bool mctp_encode_ctrl_cmd_get_vdm_support(
	struct mctp_ctrl_cmd_get_vdm_support *vdm_support_cmd,
	uint8_t rq_dgram_inst, uint8_t v_id_set_selector);

void mctp_set_uuid(struct mctp *mctp, guid_t uuid);

bool mctp_is_mctp_ctrl_msg(void *buf, size_t len);

bool mctp_ctrl_msg_is_req(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_CMDS_H */
