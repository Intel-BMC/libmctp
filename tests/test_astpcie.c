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

/* clang-format on */

/* payload ubuffer for test */
static uint8_t payload[64];
static size_t payload_size = sizeof(payload);

static int rx_runs;
static void mctp_rx_test(uint8_t src_eid, void *data, void *msg, size_t len)
{
	uint8_t *buffer = msg;
	printf("RX handler: Eid: %d, len: %zd, data: %p, msg: %p, %x\n",
	       src_eid, len, data, msg, *(int *)msg);
	assert(len == 2);
	assert(*buffer++ == 0xad);
	assert(*buffer++ == 0xde);
	rx_runs++;
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

	/* cleanup */
	mctp_binding_astpcie_free(pcie);
	mctp_destroy(mctp);

	return 0;
}
