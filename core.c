/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef pr_fmt
#define pr_fmt(fmt) "core: " fmt

#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "libmctp-cmds.h"

/* Internal data structures */

struct mctp_bus {
	mctp_eid_t eid;
	bool has_static_eid;
	struct mctp_binding *binding;
	bool tx_enabled;

	struct mctp_pktbuf *tx_queue_head;
	struct mctp_pktbuf *tx_queue_tail;

	/* todo: routing */
};

struct mctp_msg_ctx {
	uint8_t src;
	uint8_t dest;
	bool tag_owner;
	uint8_t tag;
	uint8_t last_seq;
	void *buf;
	size_t buf_size;
	size_t buf_alloc_size;
};

struct mctp {
	int n_busses;
	struct mctp_bus *busses;

	/* Message RX callback */
	mctp_rx_fn message_rx;
	void *message_rx_data;

	/* Message reassembly.
	 * @todo: flexible context count
	 */
	struct mctp_msg_ctx msg_ctxs[16];

	enum { ROUTE_ENDPOINT,
	       ROUTE_BRIDGE,
	} route_policy;
	/* Control message RX callback. */
	mctp_rx_fn control_rx;
	void *control_rx_data;

	/* Endpoint UUID */
	guid_t uuid;
};

#ifndef BUILD_ASSERT
#define BUILD_ASSERT(x)                                                        \
	do {                                                                   \
		(void)sizeof(char[0 - (!(x))]);                                \
	} while (0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

static int mctp_message_tx_on_bus(struct mctp *mctp, struct mctp_bus *bus,
				  mctp_eid_t src, mctp_eid_t dest, void *msg,
				  size_t len, bool tag_owner, uint8_t tag,
				  void *msg_binding_private);

/*
 * Receive the complete MCTP message and route it.
 * Asserts:
 *     'buf' is not NULL.
 */
static void mctp_rx(struct mctp *mctp, struct mctp_bus *bus, mctp_eid_t src,
		    mctp_eid_t dest, void *buf, size_t len, bool tag_owner,
		    uint8_t tag, void *msg_binding_private);

struct mctp_pktbuf *mctp_pktbuf_alloc(struct mctp_binding *binding, size_t len)
{
	struct mctp_pktbuf *buf;
	size_t size;

	size = binding->pkt_size + binding->pkt_pad;

	/* todo: pools */
	buf = __mctp_alloc(sizeof(*buf) + size);
	if (!buf)
		return NULL;

	buf->size = size;
	buf->start = binding->pkt_pad;
	buf->end = buf->start + len;
	buf->mctp_hdr_off = buf->start;
	buf->next = NULL;
	buf->msg_binding_private = NULL;
	if (binding->pkt_priv_size) {
		buf->msg_binding_private = __mctp_alloc(binding->pkt_priv_size);
		if (!buf->msg_binding_private) {
			__mctp_free(buf);
			return NULL;
		}
	}

	return buf;
}

void mctp_pktbuf_free(struct mctp_pktbuf *pkt)
{
	if (pkt->msg_binding_private)
		__mctp_free(pkt->msg_binding_private);
	__mctp_free(pkt);
}

struct mctp_hdr *mctp_pktbuf_hdr(struct mctp_pktbuf *pkt)
{
	return (void *)(pkt->data + pkt->mctp_hdr_off);
}

void *mctp_pktbuf_data(struct mctp_pktbuf *pkt)
{
	return (void *)(pkt->data + pkt->mctp_hdr_off +
			sizeof(struct mctp_hdr));
}

uint8_t mctp_pktbuf_size(struct mctp_pktbuf *pkt)
{
	return (uint8_t)(pkt->end - pkt->start);
}

/*
 * Get Return size of header, payload and medium specific data
 */
uint8_t mctp_pktbuf_end_index(struct mctp_pktbuf *pkt)
{
	return (uint8_t)(pkt->end);
}

void *mctp_pktbuf_alloc_start(struct mctp_pktbuf *pkt, size_t size)
{
	assert(size <= pkt->start);
	pkt->start -= size;
	return pkt->data + pkt->start;
}

void *mctp_pktbuf_alloc_end(struct mctp_pktbuf *pkt, size_t size)
{
	void *buf;

	assert(size < (pkt->size - pkt->end));
	buf = pkt->data + pkt->end;
	pkt->end += size;
	return buf;
}

int mctp_pktbuf_push(struct mctp_pktbuf *pkt, void *data, size_t len)
{
	void *p;

	if (pkt->end + len > pkt->size)
		return -1;

	p = pkt->data + pkt->end;

	pkt->end += len;
	memcpy(p, data, len);

	return 0;
}

static bool mctp_msg_ctx_match(struct mctp_msg_ctx *ctx1,
			       struct mctp_msg_ctx *ctx2)
{
	return ctx1->src == ctx2->src && ctx1->dest == ctx2->dest &&
	       ctx1->tag == ctx2->tag;
}

/* Message reassembly */
static struct mctp_msg_ctx *mctp_msg_ctx_lookup(struct mctp *mctp, uint8_t src,
						uint8_t dest, bool tag_owner,
						uint8_t tag)
{
	struct mctp_msg_ctx ctx = {
		.src = src, .dest = dest, .tag_owner = tag_owner, .tag = tag
	};
	unsigned int i;

	/* @todo: better lookup, if we add support for more outstanding
	 * message contexts */

	for (i = 0; i < ARRAY_SIZE(mctp->msg_ctxs); i++) {
		struct mctp_msg_ctx *it = &mctp->msg_ctxs[i];
		if (mctp_msg_ctx_match(&ctx, it))
			return it;
	}

	return NULL;
}

static struct mctp_msg_ctx *mctp_msg_ctx_find_free(struct mctp *mctp)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(mctp->msg_ctxs); i++) {
		struct mctp_msg_ctx *it = &mctp->msg_ctxs[i];
		if (!it->src)
			return it;
	}

	return NULL;
}

static struct mctp_msg_ctx *mctp_msg_ctx_create(struct mctp *mctp, uint8_t src,
						uint8_t dest, bool tag_owner,
						uint8_t tag)
{
	struct mctp_msg_ctx *ctx = mctp_msg_ctx_find_free(mctp);

	if (ctx) {
		ctx->src = src;
		ctx->dest = dest;
		ctx->tag_owner = tag_owner;
		ctx->tag = tag;
		ctx->buf_size = 0;
	}

	return ctx;
}

static void mctp_msg_ctx_drop(struct mctp_msg_ctx *ctx)
{
	ctx->src = 0;
}

static void mctp_msg_ctx_reset(struct mctp_msg_ctx *ctx)
{
	ctx->buf_size = 0;
}

static int mctp_msg_ctx_add_pkt(struct mctp_msg_ctx *ctx,
				struct mctp_pktbuf *pkt)
{
	size_t len;

	len = mctp_pktbuf_size(pkt) - sizeof(struct mctp_hdr);

	if (ctx->buf_size + len > ctx->buf_alloc_size) {
		size_t new_alloc_size;
		void *lbuf;

		/* @todo: finer-grained allocation, size limits */
		if (!ctx->buf_alloc_size) {
			new_alloc_size = 4096;
		} else {
			new_alloc_size = ctx->buf_alloc_size * 2;
		}

		lbuf = __mctp_realloc(ctx->buf, new_alloc_size);
		if (lbuf) {
			ctx->buf = lbuf;
			ctx->buf_alloc_size = new_alloc_size;
		} else {
			__mctp_free(ctx->buf);
			return -1;
		}
	}

	memcpy((uint8_t *)ctx->buf + ctx->buf_size, mctp_pktbuf_data(pkt), len);
	ctx->buf_size += len;

	return 0;
}

/* Core API functions */
struct mctp *mctp_init(void)
{
	struct mctp *mctp;

	mctp = __mctp_alloc(sizeof(*mctp));
	memset(mctp, 0, sizeof(*mctp));

	return mctp;
}

void mctp_destroy(struct mctp *mctp)
{
	int i;

	/* Cleanup message assembly contexts */
	for (i = 0; i < ARRAY_SIZE(mctp->msg_ctxs); i++) {
		struct mctp_msg_ctx *tmp = &mctp->msg_ctxs[i];
		if (tmp->buf)
			__mctp_free(tmp->buf);
	}

	__mctp_free(mctp->busses);
	__mctp_free(mctp);
}

int mctp_set_rx_all(struct mctp *mctp, mctp_rx_fn fn, void *data)
{
	mctp->message_rx = fn;
	mctp->message_rx_data = data;
	return 0;
}

static struct mctp_bus *find_bus_for_eid(struct mctp *mctp, mctp_eid_t dest
					 __attribute__((unused)))
{
	/* for now, just use the first bus. For full routing support,
	 * we will need a table of neighbours */
	return &mctp->busses[0];
}

static int register_bus(struct mctp *mctp, struct mctp_binding *binding)
{
	int res = 0;
	/* todo: multiple busses */
	assert(mctp->n_busses == 0);
	mctp->n_busses = 1;
	mctp->busses = __mctp_alloc(sizeof(struct mctp_bus));
	memset(mctp->busses, 0, sizeof(struct mctp_bus));
	mctp->busses[0].binding = binding;
	binding->bus = &mctp->busses[0];
	binding->mctp = mctp;
	mctp->route_policy = ROUTE_ENDPOINT;

	if (binding->start)
		res = binding->start(binding);

	return res;
}

int mctp_register_bus_dynamic_eid(struct mctp *mctp,
				  struct mctp_binding *binding)
{
	return register_bus(mctp, binding);
}

static bool mctp_eid_is_special(mctp_eid_t eid)
{
	return eid == MCTP_EID_NULL || eid == MCTP_EID_BROADCAST;
}

/*
 * According to section 8.2 of DSP0236, the special and reserved EIDs should
 * not be used for assignment and allocation to endpoints.
 */
static bool mctp_eid_is_valid(mctp_eid_t eid)
{
	return !mctp_eid_is_special(eid) && eid >= 8;
}

int mctp_register_bus(struct mctp *mctp, struct mctp_binding *binding,
		      mctp_eid_t eid)
{
	int res;

	if (!mctp_eid_is_valid(eid))
		return -1;

	res = register_bus(mctp, binding);

	if (res)
		goto out;

	mctp->busses[0].has_static_eid = true;
	mctp->busses[0].eid = eid;
out:
	return res;
}

int mctp_bridge_busses(struct mctp *mctp, struct mctp_binding *b1,
		       struct mctp_binding *b2)
{
	assert(mctp->n_busses == 0);
	mctp->busses = __mctp_alloc(2 * sizeof(struct mctp_bus));
	memset(mctp->busses, 0, 2 * sizeof(struct mctp_bus));
	mctp->n_busses = 2;
	mctp->busses[0].binding = b1;
	b1->bus = &mctp->busses[0];
	b1->mctp = mctp;
	mctp->busses[1].binding = b2;
	b2->bus = &mctp->busses[1];
	b2->mctp = mctp;

	mctp->route_policy = ROUTE_BRIDGE;

	if (b1->start)
		b1->start(b1);

	if (b2->start)
		b2->start(b2);

	return 0;
}

static inline bool mctp_is_mctp_ctrl_message(void *buf, size_t len)
{
	assert(buf != NULL);

	/* Length check will help to identify the packet which is not control
	 * control command but initilized to zero*/
	return len >= sizeof(struct mctp_ctrl_msg_hdr) &&
	       *(uint8_t *)buf == MCTP_CTRL_HDR_MSG_TYPE;
}

static inline bool mctp_ctrl_msg_is_request(void *buf, size_t len)
{
	assert(buf != NULL);
	assert(len >= sizeof(struct mctp_ctrl_msg_hdr));

	struct mctp_ctrl_msg_hdr *hdr = buf;

	return hdr->ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE &&
	       hdr->rq_dgram_inst & MCTP_CTRL_HDR_FLAG_REQUEST;
}

static void mctp_rx(struct mctp *mctp, struct mctp_bus *bus, mctp_eid_t src,
		    mctp_eid_t dest, void *buf, size_t len, bool tag_owner,
		    uint8_t tag, void *msg_binding_private)
{
	assert(buf != NULL);

	if (mctp->route_policy == ROUTE_ENDPOINT &&
	    (dest == bus->eid || dest == MCTP_EID_NULL ||
	     dest == MCTP_EID_BROADCAST)) {
		/*
		 * Identify if this is a control request message.
		 * See DSP0236 v1.3.0 sec. 11.5.
		 */
		if (mctp_is_mctp_ctrl_message(buf, len)) {
			if (mctp_ctrl_msg_is_request(buf, len)) {
				/*
			 * mctp_ctrl_handle_msg returning true means that the message
			 * was handled by the control callbacks. There is no need to
			 * handle it in the default callback.
			 */
				if (mctp_ctrl_handle_msg(mctp, bus, src, dest,
							 buf, len, tag_owner,
							 tag,
							 msg_binding_private))
					return;
			}
		}
		if (mctp->message_rx)
			mctp->message_rx(src, mctp->message_rx_data, buf, len,
					 tag_owner, tag, msg_binding_private);
		return;
	}

	if (mctp->route_policy == ROUTE_BRIDGE) {
		int i;

		for (i = 0; i < mctp->n_busses; i++) {
			struct mctp_bus *dest_bus = &mctp->busses[i];
			if (dest_bus == bus)
				continue;

			mctp_message_tx_on_bus(mctp, dest_bus, src, dest, buf,
					       len, tag_owner, tag, NULL);
		}
	}
}

void mctp_bus_rx(struct mctp_binding *binding, struct mctp_pktbuf *pkt)
{
	struct mctp_bus *bus = binding->bus;
	struct mctp *mctp = binding->mctp;
	uint8_t flags, exp_seq, seq, tag;
	struct mctp_msg_ctx *ctx;
	struct mctp_hdr *hdr;
	bool tag_owner;
	size_t len;
	void *p;
	int rc;

	assert(bus);

	hdr = mctp_pktbuf_hdr(pkt);

	/* small optimisation: don't bother reassembly if we're going to
	 * drop the packet in mctp_rx anyway */
	if (mctp->route_policy == ROUTE_ENDPOINT && hdr->dest != bus->eid &&
	    hdr->dest != MCTP_EID_NULL && hdr->dest != MCTP_EID_BROADCAST)
		goto out;

	tag_owner = hdr->flags_seq_tag & MCTP_HDR_FLAG_TO;
	flags = hdr->flags_seq_tag & (MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM);
	tag = MCTP_HDR_GET_TAG(hdr->flags_seq_tag);
	seq = MCTP_HDR_GET_SEQ(hdr->flags_seq_tag);

	switch (flags) {
	case MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM:
		/* single-packet message - send straight up to rx function,
		 * no need to create a message context */
		len = pkt->end - pkt->mctp_hdr_off - sizeof(struct mctp_hdr);
		p = pkt->data + pkt->mctp_hdr_off + sizeof(struct mctp_hdr);
		mctp_rx(mctp, bus, hdr->src, hdr->dest, p, len, tag_owner, tag,
			pkt->msg_binding_private);
		break;

	case MCTP_HDR_FLAG_SOM:
		/* start of a new message - start the new context for
		 * future message reception. If an existing context is
		 * already present, drop it. */
		/* TODO: add test if physical addressing matches for sequential
		 * packets */
		ctx = mctp_msg_ctx_lookup(mctp, hdr->src, hdr->dest, tag_owner,
					  tag);
		if (ctx) {
			mctp_msg_ctx_reset(ctx);
		} else {
			ctx = mctp_msg_ctx_create(mctp, hdr->src, hdr->dest,
						  tag_owner, tag);
		}

		rc = mctp_msg_ctx_add_pkt(ctx, pkt);
		if (rc) {
			mctp_msg_ctx_drop(ctx);
		} else {
			ctx->last_seq = seq;
		}

		break;

	case MCTP_HDR_FLAG_EOM:
		ctx = mctp_msg_ctx_lookup(mctp, hdr->src, hdr->dest, tag_owner,
					  tag);
		if (!ctx)
			goto out;

		exp_seq = (ctx->last_seq + 1) % 4;

		if (exp_seq != seq) {
			mctp_prdebug(
				"Sequence number %d does not match expected %d",
				seq, exp_seq);
			mctp_msg_ctx_drop(ctx);
			goto out;
		}

		rc = mctp_msg_ctx_add_pkt(ctx, pkt);
		if (!rc)
			mctp_rx(mctp, bus, ctx->src, ctx->dest, ctx->buf,
				ctx->buf_size, tag_owner, tag,
				pkt->msg_binding_private);

		mctp_msg_ctx_drop(ctx);
		break;

	case 0:
		/* Neither SOM nor EOM */
		ctx = mctp_msg_ctx_lookup(mctp, hdr->src, hdr->dest, tag_owner,
					  tag);
		if (!ctx)
			goto out;

		exp_seq = (ctx->last_seq + 1) % 4;
		if (exp_seq != seq) {
			mctp_prdebug(
				"Sequence number %d does not match expected %d",
				seq, exp_seq);
			mctp_msg_ctx_drop(ctx);
			goto out;
		}

		rc = mctp_msg_ctx_add_pkt(ctx, pkt);
		if (rc) {
			mctp_msg_ctx_drop(ctx);
			goto out;
		}
		ctx->last_seq = seq;

		break;
	}
out:
	mctp_pktbuf_free(pkt);
}

static void flush_message(struct mctp_bus *bus)
{
	struct mctp_pktbuf *pkt;

	while ((pkt = bus->tx_queue_head)) {
		bus->tx_queue_head = pkt->next;
		//If EOM of the message is reached then stop flushing
		if (mctp_pktbuf_hdr(pkt)->flags_seq_tag & MCTP_HDR_FLAG_EOM) {
			mctp_pktbuf_free(pkt);
			break;
		}
		mctp_pktbuf_free(pkt);
	}
}

static int mctp_packet_tx(struct mctp_bus *bus, struct mctp_pktbuf *pkt)
{
	if (!bus->tx_enabled)
		return TX_DISABLED_ERR;

	return bus->binding->tx(bus->binding, pkt);
}

static int mctp_send_tx_queue(struct mctp_bus *bus)
{
	struct mctp_pktbuf *pkt;
	int rc = 0;

	while ((pkt = bus->tx_queue_head)) {
		rc = mctp_packet_tx(bus, pkt);

		if (rc < 0) {
			if (rc == TX_DISABLED_ERR)
				break;
			else {
				mctp_prerr(
					"Failed to tx mctp packet;flushing message");
				flush_message(bus);
				continue;
			}
		}
		bus->tx_queue_head = pkt->next;

		mctp_pktbuf_free(pkt);
	}

	if (!bus->tx_queue_head)
		bus->tx_queue_tail = NULL;
	return rc;
}

void mctp_binding_set_tx_enabled(struct mctp_binding *binding, bool enable)
{
	struct mctp_bus *bus = binding->bus;
	bus->tx_enabled = enable;
	if (enable)
		mctp_send_tx_queue(bus);
}

static int mctp_message_tx_on_bus(struct mctp *mctp, struct mctp_bus *bus,
				  mctp_eid_t src, mctp_eid_t dest, void *msg,
				  size_t msg_len, bool tag_owner, uint8_t tag,
				  void *msg_binding_private)
{
	size_t max_payload_len, payload_len, p;
	struct mctp_pktbuf *pkt;
	struct mctp_hdr *hdr;
	int i;

	max_payload_len = bus->binding->pkt_size - sizeof(*hdr);

	mctp_prdebug(
		"Generating packets for transmission of %zu byte message from %hhu to %hhu",
		msg_len, src, dest);

	/* queue up packets, each of max MCTP_MTU size */
	for (p = 0, i = 0; p < msg_len; i++) {
		payload_len = msg_len - p;
		if (payload_len > max_payload_len)
			payload_len = max_payload_len;

		pkt = mctp_pktbuf_alloc(bus->binding,
					payload_len + sizeof(*hdr));
		hdr = mctp_pktbuf_hdr(pkt);

		/* store binding specific private data */
		if (msg_binding_private)
			memcpy(pkt->msg_binding_private, msg_binding_private,
			       bus->binding->pkt_priv_size);

		/* todo: tags */
		hdr->ver = bus->binding->version & 0xf;
		hdr->dest = dest;
		hdr->src = src;
		hdr->flags_seq_tag = 0;
		MCTP_HDR_SET_TAG(hdr->flags_seq_tag, tag);
		if (tag_owner)
			hdr->flags_seq_tag |= MCTP_HDR_FLAG_TO;

		if (i == 0)
			hdr->flags_seq_tag |= MCTP_HDR_FLAG_SOM;
		if (p + payload_len >= msg_len)
			hdr->flags_seq_tag |= MCTP_HDR_FLAG_EOM;
		hdr->flags_seq_tag |= (i & MCTP_HDR_SEQ_MASK)
				      << MCTP_HDR_SEQ_SHIFT;

		memcpy(mctp_pktbuf_data(pkt), (uint8_t *)msg + p, payload_len);

		/* add to tx queue */
		if (bus->tx_queue_tail)
			bus->tx_queue_tail->next = pkt;
		else
			bus->tx_queue_head = pkt;
		bus->tx_queue_tail = pkt;

		p += payload_len;
	}

	mctp_prdebug("Enqueued %d packets", i);

	return mctp_send_tx_queue(bus);
}

int mctp_message_tx(struct mctp *mctp, mctp_eid_t eid, void *msg, size_t len,
		    bool tag_owner, uint8_t tag, void *msg_binding_private)
{
	struct mctp_bus *bus;

	bus = find_bus_for_eid(mctp, eid);
	return mctp_message_tx_on_bus(mctp, bus, bus->eid, eid, msg, len,
				      tag_owner, tag, msg_binding_private);
}

static inline bool mctp_ctrl_cmd_is_control(struct mctp_ctrl_msg_hdr *hdr)
{
	return ((hdr->command_code > MCTP_CTRL_CMD_RESERVED) &&
		(hdr->command_code < MCTP_CTRL_CMD_MAX));
}

static inline bool mctp_ctrl_cmd_is_transport(struct mctp_ctrl_msg_hdr *hdr)
{
	return ((hdr->command_code >= MCTP_CTRL_CMD_FIRST_TRANSPORT) &&
		(hdr->command_code <= MCTP_CTRL_CMD_LAST_TRANSPORT));
}

bool mctp_ctrl_handle_msg(struct mctp *mctp, struct mctp_bus *bus,
			  mctp_eid_t src, mctp_eid_t dest, void *buffer,
			  size_t length, bool tag_owner, uint8_t tag,
			  void *msg_binding_private)
{
	struct mctp_ctrl_msg_hdr *msg_hdr = (struct mctp_ctrl_msg_hdr *)buffer;
	/* Control message is received.
	 * If dedicated control messages handler is provided, it will be used.
	 * If there is no dedicated handler, this function returns false and data
	 * can be handled by the generic message handler. If the control command
	 * is not transport specific it will be handled by registered callback. */
	if (mctp_ctrl_cmd_is_transport(msg_hdr)) {
		if (bus->binding->control_rx != NULL) {
			/* MCTP bus binding handler */
			bus->binding->control_rx(src,
						 bus->binding->control_rx_data,
						 buffer, length, tag_owner, tag,
						 msg_binding_private);
			return true;
		}
	} else {
		if (mctp->control_rx != NULL) {
			/* MCTP endpoint handler */
			mctp->control_rx(src, mctp->control_rx_data, buffer,
					 length, tag_owner, tag,
					 msg_binding_private);
			return true;
		}
	}
	/*
	 * Command was not handled, due to lack of specific callback.
	 * It will be passed to regular message_rx handler.
	 */
	return false;
}

int mctp_set_rx_ctrl(struct mctp *mctp, mctp_rx_fn fn, void *data)
{
	mctp->control_rx = fn;
	mctp->control_rx_data = data;
	return 0;
}

/* TODO: Will be revisiting the instance id management is done by upper
 * layer or the control command by itself.
 */
static void encode_ctrl_cmd_header(struct mctp_ctrl_msg_hdr *mctp_ctrl_hdr,
				   uint8_t rq_dgram_inst, uint8_t cmd_code)
{
	mctp_ctrl_hdr->ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	mctp_ctrl_hdr->rq_dgram_inst = rq_dgram_inst;
	mctp_ctrl_hdr->command_code = cmd_code;
}

bool mctp_encode_ctrl_cmd_set_eid(struct mctp_ctrl_cmd_set_eid *set_eid_cmd,
				  uint8_t rq_dgram_inst,
				  mctp_ctrl_cmd_set_eid_op op, uint8_t eid)
{
	if (!set_eid_cmd)
		return false;

	encode_ctrl_cmd_header(&set_eid_cmd->ctrl_msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	set_eid_cmd->operation = op;
	set_eid_cmd->eid = eid;
	return true;
}

bool mctp_encode_ctrl_cmd_get_eid(struct mctp_ctrl_cmd_get_eid *get_eid_cmd,
				  uint8_t rq_dgram_inst)
{
	if (!get_eid_cmd)
		return false;

	encode_ctrl_cmd_header(&get_eid_cmd->ctrl_msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	return true;
}

bool mctp_encode_ctrl_cmd_get_uuid(struct mctp_ctrl_cmd_get_uuid *get_uuid_cmd,
				   uint8_t rq_dgram_inst)
{
	if (!get_uuid_cmd)
		return false;

	encode_ctrl_cmd_header(&get_uuid_cmd->ctrl_msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	return true;
}

bool mctp_encode_ctrl_cmd_get_ver_support(
	struct mctp_ctrl_cmd_get_mctp_ver_support *mctp_ver_support_cmd,
	uint8_t rq_dgram_inst, uint8_t msg_type_number)
{
	if (!mctp_ver_support_cmd)
		return false;

	encode_ctrl_cmd_header(&mctp_ver_support_cmd->ctrl_msg_hdr,
			       rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_VERSION_SUPPORT);
	mctp_ver_support_cmd->msg_type_number = msg_type_number;
	return true;
}

bool mctp_encode_ctrl_cmd_get_msg_type_support(
	struct mctp_ctrl_cmd_get_msg_type_support *msg_type_support_cmd,
	uint8_t rq_dgram_inst)
{
	if (!msg_type_support_cmd)
		return false;

	encode_ctrl_cmd_header(&msg_type_support_cmd->ctrl_msg_hdr,
			       rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT);
	return true;
}

bool mctp_encode_ctrl_cmd_get_vdm_support(
	struct mctp_ctrl_cmd_get_vdm_support *vdm_support_cmd,
	uint8_t rq_dgram_inst, uint8_t v_id_set_selector)
{
	if (!vdm_support_cmd)
		return false;

	encode_ctrl_cmd_header(&vdm_support_cmd->ctrl_msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT);
	vdm_support_cmd->vendor_id_set_selector = v_id_set_selector;
	return true;
}

bool mctp_encode_ctrl_cmd_discovery_notify(
	struct mctp_ctrl_cmd_discovery_notify *discovery_notify_cmd,
	uint8_t rq_dgram_inst)
{
	if (!discovery_notify_cmd)
		return false;

	encode_ctrl_cmd_header(&discovery_notify_cmd->ctrl_msg_hdr,
			       rq_dgram_inst, MCTP_CTRL_CMD_DISCOVERY_NOTIFY);
	return true;
}

bool mctp_encode_ctrl_cmd_get_routing_table(
	struct mctp_ctrl_cmd_get_routing_table *get_routing_table_cmd,
	uint8_t rq_dgram_inst, uint8_t entry_handle)
{
	if (!get_routing_table_cmd)
		return false;

	encode_ctrl_cmd_header(&get_routing_table_cmd->ctrl_msg_hdr,
			       rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES);
	get_routing_table_cmd->entry_handle = entry_handle;
	return true;
}

static inline mctp_eid_t mctp_bus_get_eid(struct mctp_bus *bus)
{
	return bus->eid;
}

static inline void mctp_bus_set_eid(struct mctp_bus *bus, mctp_eid_t eid)
{
	bus->eid = eid;
}

/*
 * @brief Sets the EID accordingly to the provided policy and creates response.
 * See DSP0236 1.3.0 12.3
 */
int mctp_ctrl_cmd_set_endpoint_id(struct mctp *mctp, mctp_eid_t dest_eid,
				  struct mctp_ctrl_cmd_set_eid *request,
				  struct mctp_ctrl_resp_set_eid *response)
{
	struct mctp_bus *bus = find_bus_for_eid(mctp, dest_eid);

	if (!request || !response)
		return -1;
	if (request->eid == MCTP_EID_BROADCAST ||
	    request->eid == MCTP_EID_NULL) {
		response->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
		response->eid_set = mctp_bus_get_eid(bus);
		return 0;
	}

	switch (request->operation) {
	case 0: /* Set EID */
		/* TODO: Add tracking for bus owner and static reassignment. */
		if (mctp->n_busses == 1 || bus->eid == 0x0) {
			mctp_bus_set_eid(bus, request->eid);
			response->eid_set = request->eid;
			SET_MCTP_EID_ASSIGNMENT_STATUS(response->status,
						       MCTP_SET_EID_ACCEPTED);
		} else {
			response->eid_set = bus->eid;
			SET_MCTP_EID_ASSIGNMENT_STATUS(response->status,
						       MCTP_SET_EID_REJECTED);
		}
		response->completion_code = MCTP_CTRL_CC_SUCCESS;
		break;
	case 1: /* Force EID */
		/* TODO: Need to figure out for static EID devices */
		mctp_bus_set_eid(bus, request->eid);
		response->completion_code = MCTP_CTRL_CC_SUCCESS;
		response->eid_set = request->eid;
		break;
	default: /* Reset EID and Set Discovered Flag */
		response->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
	}
	return 0;
}

/*
 * @brief Retrieves a byte of medium-specific data from the binding.
 * See DSP0236 1.3.0 12.4 (byte 4).
 */
uint8_t mctp_binding_get_medium_info(struct mctp_binding *binding)
{
	return binding->info;
}

/*
 * @brief Creates control message response for Get Endpoint ID.
 * See DSP0236 1.3.0 12.4.
 */
int mctp_ctrl_cmd_get_endpoint_id(struct mctp *mctp, mctp_eid_t dest_eid,
				  bool bus_owner,
				  struct mctp_ctrl_resp_get_eid *response)
{
	struct mctp_bus *bus = find_bus_for_eid(mctp, dest_eid);

	if (response == NULL)
		return -1;

	response->eid = mctp_bus_get_eid(bus);
	response->eid_type = 0;

	if (mctp->route_policy == ROUTE_BRIDGE || bus_owner)
		SET_ENDPOINT_TYPE(response->eid_type, MCTP_BUS_OWNER_BRIDGE);

	if (bus->has_static_eid)
		SET_ENDPOINT_ID_TYPE(response->eid_type, MCTP_STATIC_EID);

	response->medium_data = mctp_binding_get_medium_info(bus->binding);
	response->completion_code = MCTP_CTRL_CC_SUCCESS;

	return 0;
}

/*
 * @brief Creates control message response for Get Endpoint UUID.
 * See DSP0236 1.3.0 12.5.
 */
int mctp_ctrl_cmd_get_endpoint_uuid(struct mctp *mctp,
				    struct mctp_ctrl_resp_get_uuid *response)
{
	if (response == NULL)
		return -1;
	response->completion_code = MCTP_CTRL_CC_SUCCESS;
	response->uuid = mctp->uuid;
	return 0;
}

void mctp_set_uuid(struct mctp *mctp, guid_t uuid)
{
	mctp->uuid = uuid;
}

bool mctp_is_mctp_ctrl_msg(void *buf, size_t len)
{
	return mctp_is_mctp_ctrl_message(buf, len);
}

bool mctp_ctrl_msg_is_req(void *buf, size_t len)
{
	return mctp_ctrl_msg_is_request(buf, len);
}

int mctp_ctrl_cmd_get_vdm_support(
	struct mctp *mctp, mctp_eid_t src_eid,
	struct mctp_ctrl_resp_get_vdm_support *response)
{
	if (!response)
		return -1;

	response->completion_code = MCTP_CTRL_CC_SUCCESS;
	/* no more capabiliy sets (default) */
	return 0;
}
