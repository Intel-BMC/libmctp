/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <linux/aspeed-mctp.h>

#include "container_of.h"
#include "libmctp-alloc.h"
#include "libmctp-astpcie.h"
#include "libmctp-log.h"
#include "libmctp.h"

#include "astpcie.h"

#undef pr_fmt
#define pr_fmt(fmt) "astpcie: " fmt

/*
 * Start function. Opens driver and stores file descriptor
 */
static int mctp_binding_astpcie_start(struct mctp_binding *binding)
{
	struct mctp_binding_astpcie *pcie = binding_to_astpcie(binding);
	int fd = open(AST_DRV_FILE, O_RDWR, O_EXCL);

	if (fd < 0) {
		mctp_prerr(AST_DRV_FILE
			   "/ast_mctp device open error: reason = %d",
			   errno);

		return fd;
	}

	// store file descriptor for further use
	pcie->fd = fd;
	return 0;
}

/*
 * Tx function which writes single packet to device driver
 */
static int mctp_binding_astpcie_tx(struct mctp_binding *binding,
				   struct mctp_pktbuf *pkt)
{
	return 0;
}

/*
 * Simple poll implementation for use
 */
int mctp_binding_astpcie_poll(struct mctp_binding *binding, int timeout)
{
	struct mctp_binding_astpcie *pcie = binding_to_astpcie(binding);
	struct pollfd fds[1];
	int res;

	fds[0].fd = pcie->fd;
	fds[0].events = POLLIN | POLLOUT;

	res = poll(fds, 1, timeout);

	if (res > 0)
		return fds[0].events;

	if (res < 0) {
		mctp_prerr("Poll returned error status (errno=%d)", errno);

		return -1;
	}

	return 0;
}

/*
 * Function reads packet from driver and passes it to
 * mctp core handler.
 */
int mctp_binding_astpcie_rx(struct mctp_binding *binding, mctp_eid_t dest,
			    void *payload, size_t payload_size)
{
	struct mctp_binding_astpcie *pcie = binding_to_astpcie(binding);
	struct mctp_pktbuf *pkt;
	struct pcie_header *header;
	uint8_t data[MCTP_ASTPCIE_BINDING_DEFAULT_BUFFER];
	ssize_t data_len;
	ssize_t data_read;
	int res;

#ifndef MCTP_HAVE_FILEIO
	mctp_prerr("MCTP_HAVE_FILEIO required for PCIe binding");
	return -1;
#endif

	data_read = read(pcie->fd, &data, sizeof(data));
	if (data_read < 0) {
		mctp_prerr("Reading RX data failed (reason = %d)", errno);

		return -1;
	}

	mctp_prdebug("Data read: %zd", data_read);

	header = (struct pcie_header *)data;
	/* calculate length of payload from PCIe header */
	data_len = PCIE_GET_LEN(header) * sizeof(uint32_t);
	/* check if frame is not truncated */
	if (data_read != data_len) {
		mctp_prerr("Sizeof of data read (%zd) differs "
			   "from header info (%zd)",
			   data_read, data_len);

		return -1;
	}

	data_len -= PCIE_GET_PAD(header);
	data_len -= sizeof(struct pcie_header);
	mctp_prdebug("Payload len: %zd, tearl: %d, len2 %d.",
		     data_len - sizeof(struct mctp_hdr),
		     header->td_ep_attr_r_l1, header->len2);

	pkt = mctp_pktbuf_alloc(binding, 0);
	if (!pkt) {
		mctp_prerr("pktbuf allocation failed");

		return -1;
	}

	/* copy mctp_hdr and payload */
	res = mctp_pktbuf_push(pkt, data + sizeof(struct pcie_header),
			       (size_t)data_len);

	if (res) {
		mctp_prerr("Can't push to pktbuf");
		mctp_pktbuf_free(pkt);

		return -1;
	}

	mctp_prdebug("dest: %x, src: %x", (mctp_pktbuf_hdr(pkt))->dest,
		     (mctp_pktbuf_hdr(pkt))->src);

	mctp_bus_rx(binding, pkt);

	return 0;
}

/*
 * Initializes PCIe binding structure
 */
struct mctp_binding_astpcie *mctp_binding_astpcie_init(void)
{
	struct mctp_binding_astpcie *pcie = __mctp_alloc(sizeof(*pcie));

	if (!pcie)
		return NULL;

	memset(pcie, 0, sizeof(*pcie));

	pcie->binding.name = "astpcie";
	pcie->binding.version = 1;
	pcie->binding.tx = mctp_binding_astpcie_tx;
	pcie->binding.start = mctp_binding_astpcie_start;
	pcie->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);

	/* where mctp_hdr starts in in/out comming data
	 * note: there are two approaches: first (used here) that core
	 * allocates pktbuf to contain all binding metadata or this is handled
	 * other way by only by binding.
	 * This might change as smbus binding implements support for medium
	 * specific layer */
	pcie->binding.pkt_pad = sizeof(struct pcie_header);

	return pcie;
}

/*
 * Closes file descriptor and releases binding memory
 */
void mctp_binding_astpcie_free(struct mctp_binding_astpcie *b)
{
	close(b->fd);
	__mctp_free(b);
}

/*
 * Returns generic binder handler from PCIe binding handler
 */
struct mctp_binding *mctp_binding_astpcie_core(struct mctp_binding_astpcie *b)
{
	return &b->binding;
}
