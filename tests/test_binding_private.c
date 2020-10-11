/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <string.h>
#include <assert.h>
#include <stdio.h>

#include <libmctp.h>
#include <libmctp-alloc.h>

#ifdef NDEBUG
#undef NDEBUG
#endif

#define TEST_EID 8
#define TEST_TARGET_EID 9

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

/* Placeholder to hold private data */
uint8_t *test_binding_pvt;

uint8_t payload[] = { 0x01, TEST_EID, TEST_TARGET_EID, 0xB0, 0, 129, 0, 1, 2 };

void fill_test_binding_pvt_data(uint8_t *ptest_binding_pvt, size_t len)
{
	for (size_t i = 0; i < len; i++)
		ptest_binding_pvt[i] = i;
}

int mctp_binding_test_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	if (pkt->msg_binding_private) {
		for (size_t i = 0; i < b->pkt_priv_size; i++) {
			assert(test_binding_pvt[i] ==
			       *((uint8_t *)pkt->msg_binding_private + i));
		}
	}
	return 0;
}

void mctp_rx_message(uint8_t src_eid, void *data, void *msg, size_t len,
		     bool tag_owner, uint8_t tag, void *binding_pvt)
{
	assert(src_eid == TEST_TARGET_EID);

	if (binding_pvt) {
		size_t binding_pvt_size = sizeof(test_binding_pvt);
		for (size_t i = 0; i < binding_pvt_size; i++) {
			assert(test_binding_pvt[i] ==
			       *((uint8_t *)binding_pvt + i));
		}
	}
}

struct mctp_binding *mctp_binding_test_init(size_t pkt_priv_size)
{
	struct mctp_binding *test;

	test = __mctp_alloc(sizeof(*test));
	memset(test, '\0', sizeof(*test));
	test->name = "test";
	test->version = 1;
	test->tx = mctp_binding_test_tx;
	test->pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	test->pkt_pad = 0;
	test->pkt_priv_size = pkt_priv_size;
	return test;
}

void mctp_binding_test_destroy(struct mctp_binding *test)
{
	__mctp_free(test);
}

void mctp_binding_test_rx_raw(struct mctp_binding *test, void *buf, size_t len,
			      void *msg_binding_pvt)
{
	struct mctp_pktbuf *pkt;

	pkt = mctp_pktbuf_alloc(test, len);
	assert(pkt);
	memcpy(mctp_pktbuf_hdr(pkt), buf, len);
	if (msg_binding_pvt) {
		memcpy(pkt->msg_binding_private, msg_binding_pvt,
		       test->pkt_priv_size);
	}
	mctp_bus_rx(test, pkt);
}

void mctp_binding_test_register_bus(struct mctp_binding *binding,
				    struct mctp *mctp, mctp_eid_t eid)
{
	mctp_register_bus(mctp, binding, eid);
}

void test_null_prv_data(void)
{
	struct mctp *mctp;
	struct mctp_binding *b1;
	mctp = mctp_init();
	assert(mctp);
	mctp_set_rx_all(mctp, mctp_rx_message, NULL);

	b1 = mctp_binding_test_init(0);
	assert(b1);

	mctp_binding_test_register_bus(b1, mctp, TEST_EID);
	mctp_message_tx(mctp, TEST_EID, (void *)payload, sizeof(payload), true,
			0, NULL);
	mctp_binding_test_rx_raw(b1, payload, sizeof(payload), NULL);

	mctp_binding_test_destroy(b1);
	mctp_destroy(mctp);
}

void test_typical_prv_data(void)
{
	struct mctp *mctp;
	struct mctp_binding *b2;
	size_t binding_pvt_size = 5;

	mctp = mctp_init();
	assert(mctp);
	mctp_set_rx_all(mctp, mctp_rx_message, NULL);

	b2 = mctp_binding_test_init(binding_pvt_size);
	assert(b2);

	test_binding_pvt = (uint8_t *)__mctp_alloc(binding_pvt_size);

	fill_test_binding_pvt_data(test_binding_pvt, binding_pvt_size);

	mctp_binding_test_register_bus(b2, mctp, TEST_EID);
	mctp_message_tx(mctp, TEST_EID, (void *)payload, sizeof(payload), true,
			0, test_binding_pvt);
	mctp_binding_test_rx_raw(b2, payload, sizeof(payload),
				 test_binding_pvt);

	mctp_binding_test_destroy(b2);
	__mctp_free(test_binding_pvt);
	mctp_destroy(mctp);
}

void test_prv_data_deallocated(void)
{
	struct mctp *mctp;
	struct mctp_binding *b3;
	bool enable_tx = false;
	size_t binding_pvt_size = 10;

	mctp = mctp_init();
	assert(mctp);
	mctp_set_rx_all(mctp, mctp_rx_message, NULL);

	b3 = mctp_binding_test_init(binding_pvt_size);
	assert(b3);

	test_binding_pvt = (uint8_t *)__mctp_alloc(binding_pvt_size);

	fill_test_binding_pvt_data(test_binding_pvt, binding_pvt_size);

	mctp_binding_test_register_bus(b3, mctp, TEST_EID);

	/* Disable TX initially */
	mctp_binding_set_tx_enabled(b3, enable_tx);

	if (!enable_tx) {
		enable_tx = true;
		uint8_t local_binding_pvt[binding_pvt_size];
		for (size_t i = 0; i < binding_pvt_size; i++)
			local_binding_pvt[i] = test_binding_pvt[i];

		mctp_message_tx(mctp, TEST_EID, (void *)payload,
				sizeof(payload), true, 0, local_binding_pvt);

		/* local_binding_pvt goes out of scope here */
	}

	/* Enable tx and push out the queue */
	mctp_binding_set_tx_enabled(b3, enable_tx);
	mctp_binding_test_rx_raw(b3, payload, sizeof(payload),
				 test_binding_pvt);

	mctp_binding_test_destroy(b3);
	__mctp_free(test_binding_pvt);
	mctp_destroy(mctp);
}

static const struct {
	void (*test)(void);
} msg_binding_private_tests[] = { test_null_prv_data, test_typical_prv_data,
				  test_prv_data_deallocated };

int main()
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(msg_binding_private_tests); i++) {
		msg_binding_private_tests[i].test();
	}

	return 0;
}
