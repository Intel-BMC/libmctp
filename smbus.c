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
#define DEFAULT_SLAVE_ADDRESS 0x21

#define SMBUS_COMMAND_CODE_SIZE 1
#define SMBUS_LENGTH_FIELD_SIZE 1
#define SMBUS_ADDR_OFFSET_SLAVE 0x1000

#ifdef I2C_M_HOLD
static struct mctp_smbus_pkt_private active_mux_info = { .fd = -1,
							 .mux_hold_timeout = 0,
							 .mux_flags = 0,
							 .slave_addr = 0 };
static struct mctp_smbus_pkt_private reserve_mux_info = { .fd = -1,
							  .mux_hold_timeout = 0,
							  .mux_flags = 0,
							  .slave_addr = 0 };
#endif

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
	const uint32_t poly_check = 0x1070 << 3;
	int i;

	for (i = 0; i < 8; i++) {
		if (d & 0x8000) {
			d = d ^ poly_check;
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

#ifdef I2C_M_HOLD
static void cleanup_reserve_mux_info(void)
{
	reserve_mux_info.fd = -1;
	reserve_mux_info.mux_hold_timeout = 0;
	reserve_mux_info.mux_flags = 0;
	reserve_mux_info.slave_addr = 0;
}
#endif

int mctp_smbus_close_mux(const int fd, const int address)
{
	uint8_t txbuf[2] = { 0 };
	struct i2c_msg msg[1] = {
		{ .addr = address, .flags = 0, .len = 2, .buf = txbuf }
	};
	struct i2c_rdwr_ioctl_data msgrdwr = { &msg[0], 1 };

	return ioctl(fd, I2C_RDWR, &msgrdwr);
}

static int smbus_model_mux(const uint16_t holdtimeout)
{
#ifdef I2C_M_HOLD

	struct i2c_msg holdmsg = { 0, I2C_M_HOLD, sizeof(holdtimeout),
				   (uint8_t *)&holdtimeout };

	struct i2c_rdwr_ioctl_data msgrdwr = { &holdmsg, 1 };

	return ioctl(reserve_mux_info.fd, I2C_RDWR, &msgrdwr);
#else
	return 0;
#endif
}

static int smbus_pull_model_hold_mux(void)
{
	/*taking max hold time as 0xFFFF seconds*/
	return smbus_model_mux(0xFFFF);
}

static int smbus_pull_model_unhold_mux(void)
{
	return smbus_model_mux(0);
}

static bool pull_model_active;
int mctp_smbus_init_pull_model(const struct mctp_smbus_pkt_private *prvt)
{
#ifdef I2C_M_HOLD
	int rc = -1;

	if (pull_model_active) {
		mctp_prerr("%s: pull model is already active.", __func__);
		return rc;
	}
	reserve_mux_info.fd = prvt->fd;
	reserve_mux_info.mux_flags = prvt->mux_flags;
	reserve_mux_info.slave_addr = prvt->slave_addr;
	rc = smbus_pull_model_hold_mux();
	if (rc < 0) {
		cleanup_reserve_mux_info();
		mctp_prerr(
			"%s: Failed to hold the bus for device address: 0X%x",
			__func__, prvt->slave_addr);
		return rc;
	}
	pull_model_active = true;
	return rc;
#else
	return 0;
#endif
}

int mctp_smbus_exit_pull_model(const struct mctp_smbus_pkt_private *prvt)
{
#ifdef I2C_M_HOLD
	int rc = -1;

	if (!(pull_model_active &&
	      reserve_mux_info.slave_addr == prvt->slave_addr &&
	      reserve_mux_info.fd == prvt->fd)) {
		mctp_prerr(
			"%s: pull model is not active for device address: 0X%x.",
			__func__, prvt->slave_addr);
		return rc;
	}
	rc = smbus_pull_model_unhold_mux();
	if (rc < 0) {
		mctp_prerr(
			"%s: Failed to unhold the bus for device address: 0X%x",
			__func__, prvt->slave_addr);
		return rc;
	}
	pull_model_active = false;
	cleanup_reserve_mux_info();
	return rc;
#else
	return 0;
#endif
}

static int mctp_smbus_tx(struct mctp_binding_smbus *smbus, const uint8_t len,
			 struct mctp_smbus_pkt_private *pkt_pvt)
{
#ifdef I2C_M_HOLD
	int rc;

	if (pull_model_active && (smbus_pull_model_unhold_mux() < 0)) {
		mctp_prerr("%s: Failed to unhold the bus.", __func__);
		return -1;
	}
	if (pkt_pvt->mux_flags) {
		uint16_t holdtimeout =
			pkt_pvt->mux_hold_timeout; /*timeout in ms. */
		struct i2c_msg msg[2] = { { .addr = pkt_pvt->slave_addr >>
						    1, /* seven bit address */
					    .flags = 0,
					    .len = len,
					    .buf = smbus->txbuf },
					  { .addr = 0,
					    .flags = I2C_M_HOLD,
					    .len = sizeof(holdtimeout),
					    .buf = (uint8_t *)&holdtimeout } };

		struct i2c_rdwr_ioctl_data msgrdwr = { &msg[0], 2 };
		mctp_trace_tx(smbus->txbuf, len);
		rc = ioctl(pkt_pvt->fd, I2C_RDWR, &msgrdwr);

		/* Store active mux info */
		active_mux_info.fd = pkt_pvt->fd;
		active_mux_info.mux_flags = pkt_pvt->mux_flags;
		active_mux_info.slave_addr = pkt_pvt->slave_addr;

		return rc;
	}

#endif
	mctp_trace_tx(smbus->txbuf, len);

	struct i2c_msg msg[1] = { { .addr = pkt_pvt->slave_addr >>
					    1, /* seven bit address */
				    .flags = 0,
				    .len = len,
				    .buf = smbus->txbuf } };
	struct i2c_rdwr_ioctl_data msgrdwr = { &msg[0], 1 };
	return ioctl(pkt_pvt->fd, I2C_RDWR, &msgrdwr);
}

#ifdef I2C_M_HOLD
static int mctp_smbus_unhold_bus(const uint8_t source_addr)
{
	/* If we received a packet from a different slave, don't unhold mux */
	if (active_mux_info.slave_addr != source_addr)
		return 0;
	/* Unhold message */
	uint16_t holdtimeout = 0;
	struct i2c_msg holdmsg = { 0, I2C_M_HOLD, sizeof(holdtimeout),
				   (uint8_t *)&holdtimeout };

	struct i2c_rdwr_ioctl_data msgrdwr = { &holdmsg, 1 };

	return ioctl(active_mux_info.fd, I2C_RDWR, &msgrdwr);
}
#endif /* I2C_M_HOLD */

static int mctp_binding_smbus_tx(struct mctp_binding *b,
				 struct mctp_pktbuf *pkt)
{
	struct mctp_binding_smbus *smbus = binding_to_smbus(b);
	struct mctp_smbus_header_tx *smbus_hdr_tx = (void *)smbus->txbuf;
	struct mctp_smbus_pkt_private *pkt_pvt =
		(struct mctp_smbus_pkt_private *)pkt->msg_binding_private;
	struct mctp_hdr *mctp_hdr = (void *)(&pkt->data[pkt->start]);

#ifdef I2C_M_HOLD
	/* Set mux_flags only for EOM packets */
	if (!(mctp_hdr->flags_seq_tag & MCTP_HDR_FLAG_EOM)) {
		pkt_pvt->mux_flags = 0;
	}
#endif

	smbus_hdr_tx->command_code = MCTP_COMMAND_CODE;
	if (!pkt_pvt) {
		mctp_prerr("Binding private information not available");
		return -1;
	}
	/* the length field in the header excludes smbus framing
	* and escape sequences.
	*/
	size_t pkt_length = mctp_pktbuf_size(pkt);
	smbus_hdr_tx->byte_count = pkt_length + 1;
	smbus_hdr_tx->source_slave_address = smbus->src_slave_addr;

	size_t tx_buf_len = sizeof(*smbus_hdr_tx);
	uint8_t i2c_message_len = tx_buf_len + pkt_length + SMBUS_PEC_BYTE_SIZE;
	if (i2c_message_len > sizeof(smbus->txbuf)) {
		mctp_prerr(
			"tx message length exceeds max smbus message length");
		return -1;
	}

	memcpy(smbus->txbuf + tx_buf_len, &pkt->data[pkt->start], pkt_length);
	tx_buf_len += pkt_length;

	smbus->txbuf[tx_buf_len] = calculate_pec_byte(smbus->txbuf, tx_buf_len,
						      pkt_pvt->slave_addr);

	if (mctp_smbus_tx(smbus, i2c_message_len, pkt_pvt) < 0) {
		mctp_prerr("Error in tx of smbus message");
		return -1;
	}

	return 0;
}

#ifdef MCTP_HAVE_FILEIO
int mctp_smbus_read(struct mctp_binding_smbus *smbus)
{
	ssize_t len = 0;
	struct mctp_smbus_header_rx *smbus_hdr_rx;
	struct mctp_smbus_pkt_private pvt_data;
	uint8_t rx_pec;
#ifdef I2C_M_HOLD
	struct mctp_hdr *mctp_hdr;
	bool eom = false;
#endif

	smbus_hdr_rx = (void *)smbus->rxbuf;
	int ret = lseek(smbus->in_fd, 0, SEEK_SET);
	if (ret < 0) {
		mctp_prerr("Failed to seek");
		return -1;
	}

	len = read(smbus->in_fd, smbus->rxbuf, sizeof(smbus->rxbuf));

	if (len < 0) {
		mctp_prerr("Failed to read");
		return -1;
	}

	mctp_trace_rx(smbus->rxbuf, len);

	if (len < sizeof(*smbus_hdr_rx)) {
		/* This condition hits from time to time, even with
		 *  a properly written poll loop, although it's not clear
		 *  why. Return an error so that the upper layer can
		 *  retry.
		 */
		mctp_prerr("Invalid packet size");
		return 0;
	}

	else if (smbus_hdr_rx->byte_count != (len - sizeof(*smbus_hdr_rx))) {
		/* Got an incorrectly sized payload */
		mctp_prerr("Got smbus payload sized %lu, expecting %d",
			   len - sizeof(*smbus_hdr_rx),
			   smbus_hdr_rx->byte_count);
		return 0;
	}

	if (smbus_hdr_rx->destination_slave_address !=
	    (smbus->src_slave_addr & ~1)) {
		mctp_prerr("Got bad slave address %d",
			   smbus_hdr_rx->destination_slave_address);
		return 0;
	}

	if (smbus_hdr_rx->command_code != MCTP_COMMAND_CODE) {
		mctp_prerr("Got bad command code %d",
			   smbus_hdr_rx->command_code);
		/* Not a payload intended for us */
		return 0;
	}

	rx_pec = pec_calculate(0, smbus->rxbuf, len - 1);
	if (rx_pec != smbus->rxbuf[len - 1]) {
		mctp_prerr("Invalid PEC value: expected: 0x%02x, found 0x%02x",
			   rx_pec, smbus->rxbuf[len - 1]);

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

#ifdef I2C_M_HOLD
	mctp_hdr = mctp_pktbuf_hdr(smbus->rx_pkt);
	if (mctp_hdr->flags_seq_tag & MCTP_HDR_FLAG_EOM) {
		eom = true;
	}
#endif

	memset(&pvt_data, 0, sizeof(struct mctp_smbus_pkt_private));

	pvt_data.slave_addr = (smbus_hdr_rx->source_slave_address & ~1);

	pvt_data.fd = smbus->out_fd;

	memcpy(smbus->rx_pkt->msg_binding_private, &pvt_data, sizeof(pvt_data));

	mctp_bus_rx(&(smbus->binding), smbus->rx_pkt);

#ifdef I2C_M_HOLD
	/* Unhold mux only for packets with EOM */
	if (eom && mctp_smbus_unhold_bus(pvt_data.slave_addr)) {
		mctp_prerr("Can't hold mux");
		return -1;
	}
#endif // I2C_M_HOLD

	smbus->rx_pkt = NULL;
	return 0;
}

void mctp_smbus_set_in_fd(struct mctp_binding_smbus *smbus, int fd)
{
	smbus->in_fd = fd;
}

void mctp_smbus_set_out_fd(struct mctp_binding_smbus *smbus, int fd)
{
	smbus->out_fd = fd;
}
#endif

int mctp_smbus_register_bus(struct mctp_binding_smbus *smbus, struct mctp *mctp,
			    mctp_eid_t eid)
{
	int rc = mctp_register_bus(mctp, &smbus->binding, eid);

	if (rc == 0) {
		/* TODO: Can we drop bus_id from mctp_binding_smbus? */
		smbus->bus_id = 0;
		mctp_binding_set_tx_enabled(&smbus->binding, true);
	}

	return rc;
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
	smbus->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	smbus->binding.pkt_pad = SMBUS_HEADER_SIZE;
	smbus->binding.pkt_priv_size = sizeof(struct mctp_smbus_pkt_private);

	smbus->binding.tx = mctp_binding_smbus_tx;

	/* Setting the default slave address */
	smbus->src_slave_addr = DEFAULT_SLAVE_ADDRESS;

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

void mctp_smbus_set_src_slave_addr(struct mctp_binding_smbus *smbus,
				   uint8_t slave_addr)
{
	smbus->src_slave_addr = slave_addr;
}
