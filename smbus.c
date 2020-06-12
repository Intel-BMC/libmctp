/* SPDX-License-Identifier: Apache-2.0 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef MCTP_HAVE_FILEIO
#include <fcntl.h>
#endif

#define pr_fmt(x) "smbus: " x

#include <i2c/smbus.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <sys/ioctl.h>

#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "libmctp-smbus.h"
#include "libmctp.h"

#ifndef container_of
#define container_of(ptr, type, member)                                        \
	(type *)((char *)(ptr) - (char *)&((type *)0)->member)
#endif

#define binding_to_smbus(b) container_of(b, struct mctp_binding_smbus, binding)

#define MCTP_COMMAND_CODE 0x0F
#define MCTP_SLAVE_ADDR_INDEX 0
#define MCTP_SOURCE_SLAVE_ADDRESS 0x11

#define SMBUS_COMMAND_CODE_SIZE 1
#define SMBUS_LENGTH_FIELD_SIZE 1
#define SMBUS_ADDR_OFFSET_SLAVE 0x1000

struct mctp_smbus_header_tx {
	uint8_t command_code;
	uint8_t byte_count;
	uint8_t source_slave_address;
};

struct mctp_smbus_header_rx {
	uint8_t destination_slave_address;
	uint8_t command_code;
	uint8_t byte_count;
	uint8_t source_slave_address;
};

static uint8_t crc8_calculate(uint16_t d)
{
	const uint32_t polyCheck = 0x1070 << 3;
	int i;

	for (i = 0; i < 8; i++) {
		if (d & 0x8000) {
			d = d ^ polyCheck;
		}
		d = d << 1;
	}

	return (uint8_t)(d >> 8);
}

/* Incremental CRC8 over count bytes in the array pointed to by p */
static uint8_t pec_calculate(uint8_t crc, uint8_t *p, size_t count)
{
	int i;

	for (i = 0; i < count; i++) {
		crc = crc8_calculate((crc ^ p[i]) << 8);
	}
	return crc;
}

static uint8_t calculate_pec_byte(uint8_t *buf, size_t len, uint8_t address)
{
	uint8_t pec = pec_calculate(0, &address, 1);
	pec = pec_calculate(pec, buf, len);

	return pec;
}

static int mctp_smbus_tx(const uint8_t destSlaveAddr,
			 struct mctp_binding_smbus *smbus, uint8_t len)
{
#ifdef I2C_M_HOLD
	/* Hold message */
	uint16_t holdtimeout = 1000; // timeout in ms.
	struct i2c_msg msg[2] =
#else // !I2C_M_HOLD
	struct i2c_msg msg[1] =
#endif // I2C_M_HOLD
		{ { .addr = destSlaveAddr >> 1, // seven bit address
		    .flags = 0,
		    .len = len,
		    .buf = smbus->txbuf }
#ifdef I2C_M_HOLD
		  ,
		  { .addr = 0,
		    .flags = I2C_M_HOLD,
		    .len = sizeof(holdtimeout),
		    .buf = (uint8_t *)&holdtimeout }
#endif // I2C_M_HOLD
		};

#ifdef I2C_M_HOLD
	struct i2c_rdwr_ioctl_data msgrdwr = { &msg[0], 2 };
#else // !I2C_M_HOLD
	struct i2c_rdwr_ioctl_data msgrdwr = { &msg[0], 1 };
#endif // I2C_M_HOLD
	return ioctl(smbus->out_fd, I2C_RDWR, &msgrdwr);
}

#ifdef I2C_M_HOLD
static int mctp_smbus_unhold_bus(struct mctp_binding_smbus *smbus)
{
	/* Unhold message */
	uint16_t holdtimeout = 0; // unhold
	struct i2c_msg holdmsg = { 0, I2C_M_HOLD, sizeof(holdtimeout),
				   (uint8_t *)&holdtimeout };

	struct i2c_rdwr_ioctl_data msgrdwr = { &holdmsg, 1 };

	return ioctl(smbus->out_fd, I2C_RDWR, &msgrdwr);
}
#endif // I2C_M_HOLD

int (*getSlaveAddrCallback)(uint8_t, uint8_t *) = 0;
void mctp_binding_set_slave_addr_callback(int (*slaveAddrCallback)(uint8_t,
								   uint8_t *))
{
	getSlaveAddrCallback = slaveAddrCallback;
}

static int mctp_binding_smbus_tx(struct mctp_binding *b,
				 struct mctp_pktbuf *pkt)
{
	struct mctp_binding_smbus *smbus = binding_to_smbus(b);
	struct mctp_smbus_header_tx *smbus_hdr_tx = (void *)smbus->txbuf;
	struct mctp_hdr *mctp_hdr = (void *)(&pkt->data[pkt->start]);
	uint8_t destSlaveAddr = 0;

	//TODO: Deprecate callback mechanism and handle message binding pvt
	// get destination slave addr using destination eid(hdr->sest)
	if (!getSlaveAddrCallback ||
	    getSlaveAddrCallback(mctp_hdr->dest, &destSlaveAddr) < 0) {
		mctp_prerr(
			"get slave address callbcack not set or error in getting "
			"destination slave address");
		return -1;
	}

	smbus_hdr_tx->command_code = MCTP_COMMAND_CODE;

	/* the length field in the header excludes smbus framing
     * and escape sequences */
	size_t pkt_length = mctp_pktbuf_size(pkt);
	smbus_hdr_tx->byte_count = pkt_length + 1;
	smbus_hdr_tx->source_slave_address = MCTP_SOURCE_SLAVE_ADDRESS;

	size_t txBufLen = sizeof(*smbus_hdr_tx);
	uint8_t i2c_message_len = txBufLen + pkt_length + SMBUS_PEC_BYTE_SIZE;
	if (i2c_message_len > sizeof(smbus->txbuf)) {
		mctp_prerr(
			"tx message length exceeds max smbus message lenght");
		return -1;
	}

	memcpy(smbus->txbuf + txBufLen, &pkt->data[pkt->start], pkt_length);
	txBufLen += pkt_length;

	smbus->txbuf[txBufLen] =
		calculate_pec_byte(smbus->txbuf, txBufLen, destSlaveAddr);

	if (mctp_smbus_tx(destSlaveAddr, smbus, i2c_message_len) < 0) {
		mctp_prerr("can't tx smbus message");
		return -1;
	}

	return 0;
}

#ifdef MCTP_HAVE_FILEIO
int mctp_smbus_read(struct mctp_binding_smbus *smbus)
{
	ssize_t len = 0;
	struct mctp_smbus_header_rx *smbus_hdr_rx;

	int ret = lseek(smbus->in_fd, 0, SEEK_SET);
	if (ret < 0) {
		mctp_prerr("Failed to seek");
		return -1;
	}

	len = read(smbus->in_fd, smbus->rxbuf, sizeof(smbus->rxbuf));
	if (len < sizeof(*smbus_hdr_rx)) {
		// This condition hits from from time to time, even with
		// a properly written poll loop, although it's not clear
		// why. Return an error so that the upper layer can
		// retry.
		return 0;
	}

	smbus_hdr_rx = (void *)smbus->rxbuf;

	if (smbus_hdr_rx->destination_slave_address !=
	    (MCTP_SOURCE_SLAVE_ADDRESS & ~1)) {
		mctp_prerr("Got bad slave address %d",
			   smbus_hdr_rx->destination_slave_address);
		return 0;
	}

	if (smbus_hdr_rx->command_code != MCTP_COMMAND_CODE) {
		mctp_prerr("Got bad command code %d",
			   smbus_hdr_rx->command_code);
		// Not a payload intended for us
		return 0;
	}

	if (smbus_hdr_rx->byte_count != (len - sizeof(*smbus_hdr_rx))) {
		// Got an incorrectly sized payload
		mctp_prerr("Got smbus payload sized %d, expecting %d",
			   smbus_hdr_rx->byte_count,
			   len - sizeof(*smbus_hdr_rx));
		return 0;
	}

	if (len < 0) {
		mctp_prerr("can't read from smbus device: %m");
		return -1;
	}

	smbus->rx_pkt = mctp_pktbuf_alloc(&(smbus->binding), 0);
	assert(smbus->rx_pkt);

	if (mctp_pktbuf_push(
		    smbus->rx_pkt, &smbus->rxbuf[sizeof(*smbus_hdr_rx)],
		    len - sizeof(*smbus_hdr_rx) - SMBUS_PEC_BYTE_SIZE) != 0) {
		mctp_prerr("Can't push tok pktbuf: %m");
		return -1;
	}

	mctp_bus_rx(&(smbus->binding), smbus->rx_pkt);

	smbus->rx_pkt = NULL;

#ifdef I2C_M_HOLD
	if (mctp_smbus_unhold_bus(smbus)) {
		mctp_prerr("Can't hold mux");
		return -1;
	}
#endif // I2C_M_HOLD

	return 0;
}

int mctp_smbus_set_in_fd(struct mctp_binding_smbus *smbus, int fd)
{
	smbus->in_fd = fd;
}

int mctp_smbus_set_out_fd(struct mctp_binding_smbus *smbus, int fd)
{
	smbus->out_fd = fd;
}
#endif

void mctp_smbus_register_bus(struct mctp_binding_smbus *smbus,
			     struct mctp *mctp, mctp_eid_t eid)
{
	smbus->bus_id = mctp_register_bus(mctp, &smbus->binding, eid);
	mctp_binding_set_tx_enabled(&smbus->binding, true);
}

struct mctp_binding_smbus *mctp_smbus_init(void)
{
	struct mctp_binding_smbus *smbus;

	smbus = __mctp_alloc(sizeof(*smbus));
	memset(&(smbus->binding), 0, sizeof(smbus->binding));

	smbus->in_fd = -1;
	smbus->out_fd = -1;

	smbus->rx_pkt = NULL;
	smbus->binding.name = "smbus";
	smbus->binding.version = 1;
	smbus->binding.pkt_size = sizeof(smbus->rxbuf);

	smbus->binding.tx = mctp_binding_smbus_tx;
	return smbus;
}

void mctp_smbus_free(struct mctp_binding_smbus *smbus)
{
	if (!(smbus->in_fd < 0)) {
		close(smbus->in_fd);
	}
	if (!(smbus->out_fd < 0)) {
		close(smbus->out_fd);
	}

	__mctp_free(smbus);
}
