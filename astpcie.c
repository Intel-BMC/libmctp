/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/aspeed-mctp.h>

#include "container_of.h"
#include "libmctp-alloc.h"
#include "libmctp-astpcie.h"
#include "libmctp-log.h"
#include "astpcie.h"

#undef pr_fmt
#define pr_fmt(fmt) "astpcie: " fmt

/*
 * PCIe header template in "network format" - Big Endian
 */
static const struct mctp_pcie_hdr mctp_pcie_hdr_template_be = {
	.fmt_type = MSG_4DW_HDR,
	.mbz_attr_length = MCTP_PCIE_VDM_ATTR,
	.code = MSG_CODE_VDM_TYPE_1,
	.vendor = VENDOR_ID_DMTF_VDM
};

static int mctp_astpcie_get_bdf_ioctl(struct mctp_binding_astpcie *astpcie)
{
	struct aspeed_mctp_get_bdf bdf;
	int rc;

	rc = ioctl(astpcie->fd, ASPEED_MCTP_IOCTL_GET_BDF, &bdf);
	if (!rc)
		astpcie->bdf = bdf.bdf;

	return rc;
}

int mctp_astpcie_get_bdf(struct mctp_binding_astpcie *astpcie, uint16_t *bdf)
{
	int rc;

	rc = mctp_astpcie_get_bdf_ioctl(astpcie);
	if (!rc)
		*bdf = astpcie->bdf;

	return rc;
}

static int
mctp_astpcie_get_medium_id_ioctl(struct mctp_binding_astpcie *astpcie)
{
	struct aspeed_mctp_get_medium_id get_medium_id;
	int rc;

	rc = ioctl(astpcie->fd, ASPEED_MCTP_IOCTL_GET_MEDIUM_ID,
		   &get_medium_id);
	if (!rc)
		astpcie->medium_id = get_medium_id.medium_id;

	return rc;
}

uint8_t mctp_astpcie_get_medium_id(struct mctp_binding_astpcie *astpcie)
{
	return astpcie->medium_id;
}

static int mctp_astpcie_open(struct mctp_binding_astpcie *astpcie)
{
	int fd = open(AST_DRV_FILE, O_RDWR);

	if (fd < 0) {
		mctp_prerr("Cannot open: %s, errno = %d", AST_DRV_FILE, errno);

		return fd;
	}

	astpcie->fd = fd;
	return 0;
}

static void mctp_astpcie_close(struct mctp_binding_astpcie *astpcie)
{
	close(astpcie->fd);
	astpcie->fd = -1;
}

/*
 * Start function. Opens driver, read bdf and medium_id
 */
static int mctp_astpcie_start(struct mctp_binding *b)
{
	struct mctp_binding_astpcie *astpcie = binding_to_astpcie(b);
	int rc;

	assert(astpcie);

	rc = mctp_astpcie_open(astpcie);
	if (rc)
		return -errno;

	rc = mctp_astpcie_get_bdf_ioctl(astpcie);
	if (rc)
		goto out_close;

	rc = mctp_astpcie_get_medium_id_ioctl(astpcie);
	if (rc)
		goto out_close;

	return 0;

out_close:
	mctp_astpcie_close(astpcie);
	return -errno;
}

static uint8_t mctp_astpcie_tx_get_pad_len(struct mctp_pktbuf *pkt)
{
	size_t sz = mctp_pktbuf_size(pkt);

	return PCIE_PKT_ALIGN(sz) - sz;
}

static uint16_t mctp_astpcie_tx_get_payload_size_dw(struct mctp_pktbuf *pkt)
{
	size_t sz = mctp_pktbuf_size(pkt);

	return PCIE_PKT_ALIGN(sz) / sizeof(uint32_t) - MCTP_HDR_SIZE_DW;
}
/*
 * Tx function which writes single packet to device driver
 */
static int mctp_astpcie_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	struct mctp_astpcie_pkt_private *pkt_prv =
		(struct mctp_astpcie_pkt_private *)pkt->msg_binding_private;
	struct mctp_binding_astpcie *astpcie = binding_to_astpcie(b);
	struct mctp_pcie_hdr *hdr = (struct mctp_pcie_hdr *)pkt->data;
	struct mctp_hdr *mctp_hdr = mctp_pktbuf_hdr(pkt);
	uint16_t payload_len_dw = mctp_astpcie_tx_get_payload_size_dw(pkt);
	uint8_t pad = mctp_astpcie_tx_get_pad_len(pkt);
	ssize_t write_len, len;

	memcpy(hdr, &mctp_pcie_hdr_template_be, sizeof(*hdr));

	mctp_prdebug("TX, len: %d, pad: %d", payload_len_dw, pad);

	PCIE_SET_ROUTING(hdr, pkt_prv->routing);
	PCIE_SET_DATA_LEN(hdr, payload_len_dw);
	PCIE_SET_REQ_ID(hdr, astpcie->bdf);
	PCIE_SET_TARGET_ID(hdr, pkt_prv->remote_id);
	PCIE_SET_PAD_LEN(hdr, pad);

	len = (payload_len_dw * sizeof(uint32_t)) +
	      ASPEED_MCTP_PCIE_VDM_HDR_SIZE;

	mctp_trace_tx(pkt->data, len);

	write_len = write(astpcie->fd, pkt->data, len);
	if (write_len < 0) {
		mctp_prerr("TX error");
		return -1;
	}

	return 0;
}

static size_t mctp_astpcie_rx_get_payload_size(struct mctp_pcie_hdr *hdr)
{
	size_t len = PCIE_GET_DATA_LEN(hdr) * sizeof(uint32_t);
	uint8_t pad = PCIE_GET_PAD_LEN(hdr);

	return len - pad;
}

/*
 * Simple poll implementation for use
 */
int mctp_astpcie_poll(struct mctp_binding_astpcie *astpcie, int timeout)
{
	struct pollfd fds[1];
	int rc;

	fds[0].fd = astpcie->fd;
	fds[0].events = POLLIN | POLLOUT;

	rc = poll(fds, 1, timeout);

	if (rc > 0)
		return fds[0].revents;

	if (rc < 0) {
		mctp_prwarn("Poll returned error status (errno=%d)", errno);

		return -1;
	}

	return 0;
}

static bool mctp_astpcie_is_routing_supported(int routing)
{
	switch (routing) {
	case PCIE_ROUTE_TO_RC:
	case PCIE_ROUTE_BY_ID:
	case PCIE_BROADCAST_FROM_RC:
		return true;
	default:
		return false;
	}
}

int mctp_astpcie_rx(struct mctp_binding_astpcie *astpcie)
{
	uint32_t data[MCTP_ASTPCIE_BINDING_DEFAULT_BUFFER];
	struct mctp_astpcie_pkt_private pkt_prv;
	struct mctp_pktbuf *pkt;
	struct mctp_pcie_hdr *hdr;
	struct mctp_hdr *mctp_hdr;
	size_t read_len, payload_len;
	int rc;

	read_len = read(astpcie->fd, &data, sizeof(data));
	if (read_len < 0) {
		mctp_prerr("Reading RX data failed (errno = %d)", errno);
		return -1;
	}

	mctp_trace_rx(&data, read_len);

	if (read_len != ASTPCIE_PACKET_SIZE(MCTP_BTU)) {
		mctp_prerr("Incorrect packet size: %zd", read_len);
		return -1;
	}

	hdr = (struct mctp_pcie_hdr *)data;
	payload_len = mctp_astpcie_rx_get_payload_size(hdr);

	pkt_prv.routing = PCIE_GET_ROUTING(hdr);

	if (!mctp_astpcie_is_routing_supported(pkt_prv.routing)) {
		mctp_prerr("unsupported routing value: %d", pkt_prv.routing);
		return -1;
	}

	pkt_prv.remote_id = PCIE_GET_REQ_ID(hdr);

	pkt = mctp_pktbuf_alloc(&astpcie->binding, 0);
	if (!pkt) {
		mctp_prerr("pktbuf allocation failed");
		return -1;
	}

	rc = mctp_pktbuf_push(pkt, data + PCIE_HDR_SIZE_DW,
			      payload_len + sizeof(struct mctp_hdr));

	if (rc) {
		mctp_prerr("Cannot push to pktbuf");
		mctp_pktbuf_free(pkt);
		return -1;
	}

	mctp_hdr = mctp_pktbuf_hdr(pkt);
	memcpy(pkt->msg_binding_private, &pkt_prv, sizeof(pkt_prv));

	mctp_bus_rx(&astpcie->binding, pkt);

	return 0;
}

/*
 * Initializes PCIe binding structure
 */
struct mctp_binding_astpcie *mctp_astpcie_init(void)
{
	struct mctp_binding_astpcie *astpcie;

	astpcie = __mctp_alloc(sizeof(*astpcie));
	if (!astpcie)
		return NULL;

	memset(astpcie, 0, sizeof(*astpcie));

	astpcie->binding.name = "astpcie";
	astpcie->binding.version = 1;
	astpcie->binding.tx = mctp_astpcie_tx;
	astpcie->binding.start = mctp_astpcie_start;
	astpcie->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);

	/* where mctp_hdr starts in in/out comming data
	 * note: there are two approaches: first (used here) that core
	 * allocates pktbuf to contain all binding metadata or this is handled
	 * other way by only by binding.
	 * This might change as smbus binding implements support for medium
	 * specific layer */
	astpcie->binding.pkt_pad = sizeof(struct mctp_pcie_hdr);
	astpcie->binding.pkt_priv_size =
		sizeof(struct mctp_astpcie_pkt_private);

	return astpcie;
}

/*
 * Closes file descriptor and releases binding memory
 */
void mctp_astpcie_free(struct mctp_binding_astpcie *astpcie)
{
	mctp_astpcie_close(astpcie);
	__mctp_free(astpcie);
}

/*
 * Returns generic binder handler from PCIe binding handler
 */
struct mctp_binding *mctp_astpcie_core(struct mctp_binding_astpcie *astpcie)
{
	return &astpcie->binding;
}

int mctp_astpcie_get_fd(struct mctp_binding_astpcie *astpcie)
{
	return astpcie->fd;
}
