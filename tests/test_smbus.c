/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <i2c/smbus.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "libmctp-smbus.h"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_EID 8
#define TEST_TARGET_EID 9

uint8_t fn_call_cnt;

uint8_t fn_call_cnt_pec;

struct smbus_test_ctx {
	int fd;
	struct mctp *mctp;
	struct mctp_binding_smbus *bind_smbus;
} __attribute__((packed));

uint8_t payload[] = { 0x01, TEST_EID, TEST_TARGET_EID, 0xB0, 0, 129, 0, 1, 2 };

uint8_t payload_neg[] = { 0x1e, 0x0f, 0x069, 0x11, 0x61, 0x08,
			  0x09, 0x8d, 0x00,  0x8e, 0x0f, 0x99 };

static struct smbus_test_ctx smbus_ctx = { .fd = -1,
					   .mctp = NULL,
					   .bind_smbus = NULL };

static int stubbed_smbus_fd = 5;
static int16_t pkt_index;

static uint8_t test_packet[][12] = {
	{ 0xE, 0x09, 0x11, 0x01, 0x00, 0x08, 0xC8, 0x00, 0x80, 0x04, 0x00,
	  0x22 },
	{ 0x0F, 0x09, 0x11, 0x01, 0x00, 0x08, 0xC8, 0x00, 0x83, 0x04, 0x00,
	  0x80 },
	{ 0x0F, 0x09, 0x11, 0x01, 0x00, 0x08, 0xC8, 0x00, 0x84, 0x04, 0x00,
	  0x96 },
	{ 0x0F, 0x09, 0x11, 0x01, 0x00, 0x08, 0xC8, 0x00, 0x85, 0x04, 0x00,
	  0xFD },
};

int open(const char *_pathname, int _flags)
{
	return stubbed_smbus_fd;
}

int close(int _fd)
{
	assert(_fd != stubbed_smbus_fd);
	return 0;
}

ssize_t read(int _fd, void *_buf, size_t _count)
{
	if (_fd != stubbed_smbus_fd)
		return -1;

	if (_count > sizeof(test_packet[pkt_index]))
		_count = sizeof(test_packet[pkt_index]);

	memcpy(_buf, &test_packet[pkt_index], _count);

	pkt_index++;

	if (pkt_index > 4)
		pkt_index = 0;

	return _count;
}

ssize_t write(int _fd, void *_data, size_t _data_size)
{
	if (_fd != stubbed_smbus_fd)
		return -1;

	return 0;
}

int ioctl(int _fd, unsigned long _request, void *_data)
{
	if (_fd != stubbed_smbus_fd)
		return -1;

	switch (_request) {
	case I2C_RDWR: {
		mctp_smbus_read(smbus_ctx.bind_smbus);
		break;
	}
	default:
		mctp_prdebug("Unrecognized ioctl");
		assert(0);
		break;
	}

	return 0;
}

static void init_smbus_test(struct smbus_test_ctx *p_ctx)
{
	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	p_ctx->mctp = mctp_init();
	assert(p_ctx->mctp);

	p_ctx->bind_smbus = mctp_smbus_init();

	assert(p_ctx->bind_smbus);

	assert(strcmp(p_ctx->bind_smbus->binding.name, "smbus") == 0);
	assert(p_ctx->bind_smbus->binding.version == 1);
	assert(p_ctx->bind_smbus->binding.tx);
}

static void test_smbus_rx(mctp_eid_t src, void *data, void *msg, size_t len,
			  bool tag_owner, uint8_t tag, void *ext)
{
	struct mctp_smbus_pkt_private *pkt_pvt =
		((struct mctp_smbus_pkt_private *)ext);

	uint8_t expected[] = { 0x8a, 0x0b, 0x51 };
	int rc;

	assert(src != 1);
	assert(pkt_pvt->fd != -1);

	assert(len == 3);

	rc = memcmp(expected, (uint8_t *)msg, len);
	assert(rc == 0);
}

static void destroy_smbus_test_ctx(struct smbus_test_ctx *p_ctx)
{
	mctp_smbus_free(p_ctx->bind_smbus);
	__mctp_free(p_ctx->mctp);
}

static void run_smbus_rx_test(mctp_rx_fn rx_fn)
{
	int rc;
	struct mctp_smbus_pkt_private ext_params;
	struct mctp_pktbuf pkt;

	init_smbus_test(&smbus_ctx);

	ext_params.fd = stubbed_smbus_fd;
	ext_params.mux_flags = IS_MUX_PORT;
	ext_params.mux_hold_timeout = 1000;
	ext_params.slave_addr = 0x11;

	pkt.msg_binding_private = (void *)&ext_params;
	pkt.next = NULL;

	smbus_ctx.bind_smbus->rx_pkt = &pkt;

	rc = mctp_smbus_register_bus(smbus_ctx.bind_smbus, smbus_ctx.mctp,
				     TEST_EID);
	assert(rc == 0);

	mctp_set_rx_all(smbus_ctx.mctp, rx_fn, NULL);

	mctp_smbus_read(smbus_ctx.bind_smbus);

	destroy_smbus_test_ctx(&smbus_ctx);
}

static void negative_test_smbus_rx(mctp_eid_t src, void *data, void *msg,
				   size_t len, bool tag_owner, uint8_t tag,
				   void *ext)
{
	/*change function call count*/
	fn_call_cnt++;
}

static void run_smbus_tx_test(mctp_rx_fn rx_fn)
{
	int rc;
	struct mctp_smbus_pkt_private ext_params;
	struct mctp_pktbuf pkt;

	init_smbus_test(&smbus_ctx);

	ext_params.fd = stubbed_smbus_fd;
	ext_params.mux_flags = IS_MUX_PORT;
	ext_params.mux_hold_timeout = 1000;
	ext_params.slave_addr = 0x11;

	pkt.msg_binding_private = (void *)&ext_params;
	pkt.next = NULL;

	smbus_ctx.bind_smbus->rx_pkt = &pkt;

	mctp_set_rx_all(smbus_ctx.mctp, rx_fn, NULL);

	rc = mctp_smbus_register_bus(smbus_ctx.bind_smbus, smbus_ctx.mctp,
				     TEST_EID);
	assert(rc == 0);

	assert(mctp_message_tx(smbus_ctx.mctp, TEST_EID, (void *)payload,
			       sizeof(payload), true, 0,
			       (void *)&ext_params) == 0);
}

static void run_smbus_rx_test_negative(mctp_rx_fn rx_fn)
{
	int rc;
	struct mctp_smbus_pkt_private ext_params;
	struct mctp_pktbuf pkt;

	init_smbus_test(&smbus_ctx);

	ext_params.fd = -1;
	ext_params.mux_flags = IS_MUX_PORT;
	ext_params.mux_hold_timeout = 1000;
	ext_params.slave_addr = 0x11;

	pkt.msg_binding_private = (void *)&ext_params;
	pkt.next = NULL;

	smbus_ctx.bind_smbus->rx_pkt = &pkt;

	rc = mctp_smbus_register_bus(smbus_ctx.bind_smbus, smbus_ctx.mctp,
				     TEST_EID);
	assert(rc == 0);

	mctp_set_rx_all(smbus_ctx.mctp, rx_fn, NULL);

	mctp_smbus_read(smbus_ctx.bind_smbus);

	/*calling again to access the call.*/
	mctp_smbus_read(smbus_ctx.bind_smbus);

	/*
     * since for negative cases the call should not happen
     * so this counter wont be incremented
     */
	assert(fn_call_cnt == 0);

	destroy_smbus_test_ctx(&smbus_ctx);
}

static void run_smbus_rx_test_pec(mctp_rx_fn rx_fn)
{
	int rc;
	struct mctp_smbus_pkt_private ext_params;
	struct mctp_pktbuf pkt;

	init_smbus_test(&smbus_ctx);

	ext_params.fd = stubbed_smbus_fd;
	ext_params.mux_flags = IS_MUX_PORT;
	ext_params.mux_hold_timeout = 1000;
	ext_params.slave_addr = 0x11;

	pkt.msg_binding_private = (void *)&ext_params;
	pkt.next = NULL;

	smbus_ctx.bind_smbus->rx_pkt = &pkt;

	memcpy(smbus_ctx.bind_smbus->rxbuf, &test_packet[0],
	       sizeof(test_packet[0]));

	rc = mctp_smbus_register_bus(smbus_ctx.bind_smbus, smbus_ctx.mctp,
				     TEST_EID);
	assert(rc == 0);

	mctp_set_rx_all(smbus_ctx.mctp, rx_fn, NULL);

	mctp_smbus_read(smbus_ctx.bind_smbus);

	destroy_smbus_test_ctx(&smbus_ctx);
}

static void test_smbus_rx_pec(mctp_eid_t src, void *data, void *msg, size_t len,
			      bool tag_owner, uint8_t tag, void *ext)
{
	struct mctp_smbus_pkt_private *pkt_pvt =
		((struct mctp_smbus_pkt_private *)ext);

	uint8_t expected[] = { 0x04, 0x00, 0x22 };
	int rc;

	assert(src != 1);
	assert(pkt_pvt->fd != -1);

	assert(len == 3);

	rc = memcmp(expected, (uint8_t *)msg, len);
	assert(rc == 0);
}

static void run_smbus_rx_test_negative_pec(mctp_rx_fn rx_fn)
{
	int rc;
	struct mctp_smbus_pkt_private ext_params;
	struct mctp_pktbuf pkt;

	init_smbus_test(&smbus_ctx);

	ext_params.fd = -1;
	ext_params.mux_flags = IS_MUX_PORT;
	ext_params.mux_hold_timeout = 1000;
	ext_params.slave_addr = 0x11;

	pkt.msg_binding_private = (void *)&ext_params;
	pkt.next = NULL;

	smbus_ctx.bind_smbus->rx_pkt = &pkt;

	memcpy(smbus_ctx.bind_smbus->rxbuf, &payload_neg, sizeof(payload_neg));

	rc = mctp_smbus_register_bus(smbus_ctx.bind_smbus, smbus_ctx.mctp,
				     TEST_EID);
	assert(rc == 0);

	mctp_set_rx_all(smbus_ctx.mctp, rx_fn, NULL);

	assert(mctp_smbus_read(smbus_ctx.bind_smbus) == -1);

	/*
     * since for negative cases the call should not happen
     * so this counter wont be incremented
     */
	assert(fn_call_cnt_pec == 0);

	destroy_smbus_test_ctx(&smbus_ctx);
}

static void negative_test_smbus_rx_pec(mctp_eid_t src, void *data, void *msg,
				       size_t len, bool tag_owner, uint8_t tag,
				       void *ext)
{
	/*change function call count*/
	fn_call_cnt_pec++;
}

int main(void)
{
	run_smbus_tx_test(NULL);
	run_smbus_rx_test(test_smbus_rx);

	run_smbus_rx_test_pec(test_smbus_rx_pec);

	/*Negetive test case*/
	run_smbus_rx_test_negative(negative_test_smbus_rx);

	run_smbus_rx_test_negative_pec(negative_test_smbus_rx_pec);

	return 0;
}
