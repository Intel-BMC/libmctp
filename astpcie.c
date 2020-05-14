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
 * Initialize medium specific header with defaults
 */
static int mctp_astpcie_medium_specific_initialize(struct mctp_pktbuf *pkt)
{
	struct pcie_header *header = (struct pcie_header *)pkt->data;
	size_t len = mctp_pktbuf_end_index(pkt);
	size_t dword_len;
	size_t pad_len;
	memset(header, 0, sizeof(*header));

	header->r_fmt_type_rout =
		(PCIE_HEADER_FMT << PCIE_FTR_FMT_SHIFT |
		 PCIE_HEADER_TYPE << PCIE_FTR_TYPE_SHIFT |
		 PCIE_HEADER_ROUTING << PCIE_FTR_ROUTING_SHIFT);

	header->r_trcl_r = PCIE_HEADER_TC << PCIE_TR_TRCL_SHIFT;

	header->td_ep_attr_r_l1 = (PCIE_HEADER_TD << PCIE_TEARL_SHIFT_TD |
				   PCIE_HEADER_EP << PCIE_TEARL_SHIFT_EP |
				   PCIE_HEADER_ATTR << PCIE_TEARL_ATTR_SHIFT);

	/* calculate number of padding bytes to align to uint32_t */
	pad_len = PCIE_COUNT_PAD(len);

	/* Length of the PCIe VDM Data in dwords */
	dword_len = (len + pad_len) / sizeof(uint32_t);
	header->td_ep_attr_r_l1 |=
		(uint8_t)(UCHAR_MAX & (dword_len >> CHAR_BIT));
	header->len2 = (uint8_t)(dword_len);

	/* store padding together with VDM code */
	header->pcitag =
		(uint8_t)(PCIE_HEADER_MCTP_VDM_CODE << PCIE_PCITAG_MVC_SHIFT |
			  pad_len << PCIE_PCITAG_PADLEN_SHIFT);
	header->message_code = PCIE_HEADER_MESSAGE_CODE;
	header->vendor_id = PCIE_HEADER_VENDOR_ID;

	if (len + pad_len > MCTP_ASTPCIE_BINDING_DEFAULT_BUFFER) {
		mctp_prerr("incorrect payload size (actual: %zd > max: %d)",
			   len + pad_len, MCTP_ASTPCIE_BINDING_DEFAULT_BUFFER);

		return -1;
	}

	return 0;
}

/*
 * Fill medium specific part of header
 */
static int fill_medium_specific_header(struct mctp_pktbuf *pkt)
{
	struct pcie_request_extra *extra = pkt->msg_binding_private;
	struct pcie_header *header = (struct pcie_header *)pkt->data;

	/* initialize header, extend length with padding */
	if (mctp_astpcie_medium_specific_initialize(pkt) < 0)
		return -1;

	if (!header)
		return -1;

	/* use defaults */
	if (!extra)
		return 0;

	if (extra->routing < PCIE_ROUTE_TO_ROOT_COMPLEX ||
	    extra->routing == PCIE_RESERVED ||
	    extra->routing > PCIE_BROADCAST_FROM_ROOT)
		return -1;

	header->r_fmt_type_rout |=
		(uint8_t)(extra->routing << PCIE_FTR_TYPE_SHIFT);

	memcpy(&header->pci_target_id, &extra->remote_id,
	       sizeof(extra->remote_id));

	memcpy(&header->pci_requester_id, &extra->local_id,
	       sizeof(extra->local_id));

	return 0;
}

/*
 * Tx function which writes single packet to device driver
 */
static int mctp_binding_astpcie_tx(struct mctp_binding *binding,
				   struct mctp_pktbuf *pkt)
{
	int res = -1;
	/* full mctp packet with all headers and padding */
	ssize_t padded_pkt_len = mctp_pktbuf_end_index(pkt);
	ssize_t num_written;
	int i;

#ifndef MCTP_HAVE_FILEIO
	mctp_prerr("MCTP_HAVE_FILEIO required for PCIe binding");
	return -1;
#endif

	padded_pkt_len += PCIE_COUNT_PAD(padded_pkt_len);
	/* adjust header according to requester needs */
	res = fill_medium_specific_header(pkt);
	if (res < 0) {
		mctp_prerr("medium specific header error, reason = %d", res);

		return -1;
	}

	/* fill padding with 0x00 (if any) */
	for (i = mctp_pktbuf_end_index(pkt); i < padded_pkt_len; i++)
		pkt->data[i] = 0x00;

	num_written = write((binding_to_astpcie(binding))->fd, pkt->data,
			    padded_pkt_len);
	if (num_written < 0 || num_written > (ssize_t)padded_pkt_len) {
		mctp_prerr("incorrect size of data written (actual: %zd, "
			   "requested: %zd)",
			   num_written, padded_pkt_len);

		return -1;
	}

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
	struct pcie_request_extra extra;
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

	memcpy(&extra.remote_id, &header->pci_requester_id,
	       sizeof(extra.remote_id));
	memcpy(&extra.local_id, &header->pci_target_id, sizeof(extra.local_id));
	extra.routing = header->r_fmt_type_rout & PCIE_FTR_ROUTING_MASK;

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

	pkt->msg_binding_private = &extra;

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
