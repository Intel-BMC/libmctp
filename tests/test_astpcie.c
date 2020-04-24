/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "libmctp-astpcie.h"
#include "libmctp-log.h"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <linux/aspeed-mctp.h>

#include "astpcie.h"

#ifndef MCTP_HAVE_FILEIO
#error PCIe requires FILEIO.
#endif

#define TEST_EID 10
#define TEST_OUT_EID 11

static int file_descriptor = 3;
int open(char *filename, int opts)
{
	fprintf(stderr, "MOCK: %s\n", __func__);
	return file_descriptor;
}

/* clang-format off */
static uint8_t data_0[16+4] = { 0x70, 0x00, 0x10, 0x05
			      , 0x11, 0x23, 0x20, 0x7F
			      , 0x00, 0x00, 0xB4, 0x1A
			      , 0x00, 0x0a, 0x0b, 0xc0 /* mctp_hdr */
			      , 0xAD, 0xDE, 0x00, 0x00 /* payload + 2 pad */
};

static uint8_t data_1a[16+64] = { 0x70, 0x00, 0x10, 0x14
				, 0x11, 0x23, 0x00, 0x7F
				, 0x00, 0x00, 0xB4, 0x1A
				, 0x00, 0x0a, 0x0b, 0x80 /* mctp_hdr */
};
static uint8_t data_1b[16+16] = { 0x70, 0x00, 0x10, 0x08
				, 0x11, 0x23, 0x10, 0x7F
				, 0x00, 0x00, 0xB4, 0x1A
				, 0x00, 0x0a, 0x0b, 0x50 /* mctp_hdr */
};

static uint8_t data_2[16] = { 0x60, 0x00, 0x10, 0x14
			    , 0x00, 0x00, 0x10, 0x7F
			    , 0x00, 0x00, 0xB4, 0x1A
			    , 0x01, 0x0B, 0x0a, 0xC8
};

static uint8_t data_3a[16] = { 0x63, 0x00, 0x10, 0x14
			     , 0x01, 0x02, 0x00, 0x7F
			     , 0x03, 0x04, 0xB4, 0x1A
			     , 0x01, 0x0B, 0x0a, 0x88
};

static uint8_t data_3b[16] = { 0x63, 0x00, 0x10, 0x14
			     , 0x01, 0x02, 0x20, 0x7F
			     , 0x03, 0x04, 0xB4, 0x1A
			     , 0x01, 0x0B, 0x0a, 0x58
};
/* clang-format on */

/* payload ubuffer for test */
static uint8_t payload[128];
static size_t payload_size = sizeof(payload);

static int rx_runs;
static void mctp_rx_test(uint8_t src_eid, void *data, void *msg, size_t len,
			 void *msg_binding_private)
{
	uint8_t *buffer = msg;
	printf("RX handler: Eid: %d, len: %zd, data: %p, msg: %p, %x\n",
	       src_eid, len, data, msg, *(int *)msg);
	switch (rx_runs++) {
	case 0:
		assert(len == 2);
		assert(*buffer++ == 0xad);
		assert(*buffer++ == 0xde);
		break;
	case 1:
		assert(len == 79);
		/* check boundaries */
		assert(buffer[0] == 0);
		assert(buffer[1] == 1);
		assert(buffer[63] == 63);
		assert(buffer[64] == 64);
		assert(buffer[78] == 78);
		break;
	};
}

static void prepare_payload1()
{
	size_t i;
	for (i = 16; i < sizeof(data_1a); i++) {
		data_1a[i] = i - 16;
	}
	/* leave one for padding */
	for (i = 16; i < sizeof(data_1b) - 1; i++) {
		data_1b[i] = i - 16 + 64;
	}
	memset(payload, 0, sizeof(payload));
}

static void fill_payload2(int size)
{
	size_t i;
	payload_size = size;

	for (i = 0; i < payload_size; i++) {
		payload[i] = (uint8_t)i;
	}
}

/* asserts on error */
static void check_header(uint8_t *msg, uint8_t *data)
{
	size_t i;
	fprintf(stderr, "Entering %s()\n", __func__);
	fprintf(stderr,
		"mgs[ 0]:%02x == data[ 0]:%02x,\n"
		"mgs[15]:%02x == data[15]:%02x.\n",
		msg[0], data[0], msg[15], data[15]);

	/* check boundaries */
	assert(msg[0] == data[0]);
	assert(msg[15] == data[15]);

	for (i = 0; i < 16; i++) {
		if (msg[i] != data[i]) {
			fprintf(stderr,
				"Data mismatch: msg[%zd] != data_1[%zd] "
				"(%02x vs %02x)",
				i, i, msg[i], data[i]);
			assert(msg[i] == data[i]);
		}
	}
}

static void check_header2(uint8_t *msg)
{
	fprintf(stderr, "Entering %s()\n", __func__);
	assert(sizeof(data_2) == 16);
	check_header(msg, data_2);
}

/* asserts on error */
static void check_payload2(uint8_t *msg)
{
	fprintf(stderr, "Entering %s()\n", __func__);
	assert(payload_size == 63);
	fprintf(stderr,
		"mgs[ 0]:%02x == payload[ 0]:%02x,\n"
		"mgs[62]:%02x == payload[62]:%02x,\n"
		"padding: msg[63]:%02x.\n",
		msg[0], payload[0], msg[62], payload[62], msg[63]);
	/* check boundaries */
	assert(msg[0] == payload[0]);
	assert(msg[62] == payload[62]);
	assert(msg[63] == 0x00);
}

/* asserts on error */
static void check_header3a(uint8_t *msg)
{
	fprintf(stderr, "Entering %s()\n", __func__);
	assert(sizeof(data_3a) == 16);

	check_header(msg, data_3a);
}

/* asserts on error */
static void check_header3b(uint8_t *msg)
{
	fprintf(stderr, "Entering %s()\n", __func__);
	assert(sizeof(data_3b) == 16);

	check_header(msg, data_3b);
}

/* asserts on error */
static void check_payload3a(uint8_t *msg)
{
	fprintf(stderr, "Entering %s()\n", __func__);
	assert(payload_size == 126);
	fprintf(stderr,
		"mgs[ 0]:%02x == payload[ 0]:%02x,\n"
		"mgs[63]:%02x == payload[63]:%02x,\n",
		msg[0], payload[0], msg[63], payload[63]);
	/* check boundaries */
	assert(msg[0] == payload[0]);
	assert(msg[63] == payload[63]);
}

/* asserts on error */
static void check_payload3b(uint8_t *msg)
{
	fprintf(stderr, "Entering %s()\n", __func__);
	assert(payload_size == 126);
	fprintf(stderr,
		"mgs[ 0]:%02x == payload[64]:%02x,\n"
		"mgs[61]:%02x == payload[64 + 61]:%02x,\n"
		"padding: msg[62]:%02x.\n",
		msg[0], payload[64], msg[61], payload[64 + 61], msg[62]);
	/* check boundaries */
	assert(msg[0] == payload[64]);
	assert(msg[61] == payload[64 + 61]);
}

static int ioctl_index = 0;
int ioctl(int __fd, unsigned long int __request, ...)
{
	va_list args;
	fprintf(stderr, "MOCK: %s, ioctl_index = %d\n", __func__, ioctl_index);
	assert(__fd == file_descriptor);
	va_start(args, __request);
	struct ioctl_interface *io = va_arg(args, struct ioctl_interface *);
	switch (ioctl_index++) {
	case 0:
		assert(0);
	}

	va_end(args);
	return 0;
}

int close(int __fd)
{
	fprintf(stderr, "MOCK: %s\n", __func__);
	assert(__fd == file_descriptor);
	return 0;
}

static int read_index;
ssize_t read(int __fd, void *data, size_t data_size)
{
	fprintf(stderr, "MOCK: %s\n", __func__);
	assert(__fd == file_descriptor);
	switch (read_index++) {
	case 0:
		printf("\n");
		assert(data != NULL);
		memcpy(data, &data_0, sizeof(data_0));
		return sizeof(data_0);
	case 1:
		printf("\n");
		assert(data != NULL);
		memcpy(data, &data_1a, sizeof(data_1a));
		return sizeof(data_1a);
	case 2:
		printf("\n");
		assert(data != NULL);
		memcpy(data, &data_1b, sizeof(data_1b));
		return sizeof(data_1b);
	}
	return 0;
}

static int write_index;
ssize_t write(int __fd, void *data, size_t data_size)
{
	fprintf(stderr, "MOCK: %s\n", __func__);
	assert(__fd == file_descriptor);
	switch (write_index++) {
	case 0:
		check_header2(data);
		check_payload2((uint8_t *)data + 16);
		return (ssize_t)data_size;
	case 1:
		check_header3a(data);
		check_payload3a((uint8_t *)data + 16);
		return (ssize_t)data_size;
	case 2:
		check_header3b(data);
		check_payload3b((uint8_t *)data + 16);
		return (ssize_t)data_size;
	}
	return 0;
}

int main(void)
{
	int res;
	struct mctp *mctp;
	struct mctp_binding *binding;
	struct mctp_binding_astpcie *pcie;

	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	mctp = mctp_init();
	assert(mctp);

	pcie = mctp_binding_astpcie_init();
	assert(pcie);

	binding = mctp_binding_astpcie_core(pcie);
	assert(binding);

	assert(strcmp(pcie->binding.name, "astpcie") == 0);
	assert(pcie->binding.version == 1);
	assert(pcie->binding.tx != NULL);
	assert(pcie->binding.start != NULL);

	mctp_set_rx_all(mctp, mctp_rx_test, NULL);
	res = mctp_register_bus(mctp, &pcie->binding, TEST_EID);
	assert(res == 0);

	res = mctp_binding_astpcie_rx(&pcie->binding, TEST_EID, payload,
				      sizeof(payload));
	assert(res == 0);
	assert(rx_runs == 1);

	/* prepare data */
	prepare_payload1();

	res = mctp_binding_astpcie_rx(&pcie->binding, TEST_EID, payload,
				      sizeof(payload));
	assert(res == 0);
	assert(rx_runs == 1);

	res = mctp_binding_astpcie_rx(&pcie->binding, TEST_EID, payload,
				      sizeof(payload));
	assert(res == 0);
	assert(rx_runs == 2);

	/* prepare data */
	fill_payload2(63);

	/* queue */
	res = mctp_message_tx(mctp, TEST_OUT_EID, payload, payload_size, NULL);

	/* flush */
	mctp_binding_set_tx_enabled(&pcie->binding, true);

	/* prepare data */
	fill_payload2(126);

	struct pcie_request_extra extra = { PCIE_BROADCAST_FROM_ROOT,
					    { 0x01, 0x02 },
					    { 0x03, 0x04 } };
	/* queue and then flush */
	res = mctp_message_tx(mctp, TEST_OUT_EID, payload, payload_size,
			      &extra);

	/* cleanup */
	mctp_binding_astpcie_free(pcie);
	mctp_destroy(mctp);

	return 0;
}
