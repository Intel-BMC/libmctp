#include <stdio.h>
#include <assert.h>
#include <poll.h>

#include "libmctp-asti3c.h"
#include "libmctp-log.h"

#define i3c_one_packet_read_payload                                            \
	0x01, 0x00, 0x00, 0xC8, 0x00, 0x81, 0x04, 0x00

#define i3c_one_packet_read_payload_expected 0x00, 0x81, 0x04, 0x00

#define i3c_one_packet_btu_read_payload                                        \
	0x01, 0x00, 0x00, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x20, 0x09, 0xC8,      \
		0x00, 0x81, 0x04, 0x00, 0x01, 0x09, 0xC8, 0x00, 0x81, 0x04,    \
		0x00, 0x01, 0x20, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20,    \
		0x09, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x81,    \
		0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00, 0x04, 0x00, 0x01,    \
		0x20, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09,    \
		0xC8, 0x00, 0x81, 0x00, 0x01, 0x20, 0x09

#define i3c_one_packet_btu_read_payload_expected                               \
	0x00, 0x81, 0x04, 0x00, 0x20, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00,      \
		0x01, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0xC8,    \
		0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0x00, 0x81, 0x04,    \
		0x00, 0x01, 0x20, 0x09, 0xC8, 0x81, 0x04, 0x00, 0x01, 0x20,    \
		0x09, 0xC8, 0x00, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00,    \
		0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00, 0x81, 0x00,    \
		0x01, 0x20, 0x09

#define i3c_rx_fragment1_payload                                               \
	0x01, 0x00, 0x00, 0x88, 0x00, 0x81, 0x04, 0x00, 0x20, 0x09, 0xC8,      \
		0x00, 0x81, 0x04, 0x00, 0x01, 0x09, 0xC8, 0x00, 0x81, 0x04,    \
		0x00, 0x01, 0x20, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20,    \
		0x09, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x81,    \
		0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00, 0x04, 0x00, 0x01,    \
		0x20, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09,    \
		0xC8, 0x00, 0x81, 0x00, 0x01, 0x20, 0x09

#define i3c_rx_fragment2_payload                                               \
	0x01, 0x00, 0x00, 0x18, 0x00, 0x81, 0x04, 0x00, 0x20, 0x09, 0xC8,      \
		0x00, 0x81, 0x04, 0x00, 0x01, 0x09, 0xC8, 0x00, 0x81, 0x04,    \
		0x00, 0x01, 0x20, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20,    \
		0x09, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x81,    \
		0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00, 0x04, 0x00, 0x01,    \
		0x20, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09,    \
		0xC8, 0x00, 0x81, 0x00, 0x01, 0x20, 0x09

#define i3c_rx_fragment3_payload 0x01, 0x00, 0x00, 0x68, 0x00, 0x81, 0x04, 0x00

#define i3c_rx_assembled_fragments_expected                                    \
	0x00, 0x81, 0x04, 0x00, 0x20, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00,      \
		0x01, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0xC8,    \
		0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0x00, 0x81, 0x04,    \
		0x00, 0x01, 0x20, 0x09, 0xC8, 0x81, 0x04, 0x00, 0x01, 0x20,    \
		0x09, 0xC8, 0x00, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00,    \
		0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00, 0x81, 0x00,    \
		0x01, 0x20, 0x09, 0x00, 0x81, 0x04, 0x00, 0x20, 0x09, 0xC8,    \
		0x00, 0x81, 0x04, 0x00, 0x01, 0x09, 0xC8, 0x00, 0x81, 0x04,    \
		0x00, 0x01, 0x20, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20,    \
		0x09, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x81,    \
		0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00, 0x04, 0x00, 0x01,    \
		0x20, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09,    \
		0xC8, 0x00, 0x81, 0x00, 0x01, 0x20, 0x09, 0x00, 0x81, 0x04,    \
		0x00

#define i3c_one_packet_bad_btu_read_payload                                    \
	0x01, 0x00, 0x00, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x20, 0x09, 0xC8,      \
		0x00, 0x81, 0x04, 0x00, 0x01, 0x09, 0xC8, 0x00, 0x81, 0x04,    \
		0x00, 0x01, 0x20, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20,    \
		0x09, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x81,    \
		0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00, 0x04, 0x00, 0x01,    \
		0x20, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09,    \
		0xC8, 0x00, 0x81, 0x00, 0x01, 0x20, 0x09, 0xC8

static const int stubbed_fd = 3;

typedef enum testcase {
	i3c_poll_test_pollin = 0,
	i3c_poll_test_pollout,
	i3c_poll_test_poll_timeout,
	i3c_poll_test_invalid_fd,
	i3c_one_packet_read,
	i3c_one_packet_btu_read,
	i3c_bad_btu_read,
	i3c_rx_fragment_1,
	i3c_rx_fragment_2,
	i3c_rx_fragment_3,
	i3c_bad_fd_read
} testcase;

testcase test;

/* Mock system calls */

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	int rc = 0;
	/* mctp_asti3c_poll always has nfds = 1 */
	assert(nfds == 1);

	if (fds[0].fd != stubbed_fd)
		return -1;

	switch (test) {
	case i3c_poll_test_pollin:
		fds[0].revents = (rc | POLLIN);
		return 1;

	case i3c_poll_test_pollout:
		fds[0].revents = (rc | POLLOUT);
		return 1;

	case i3c_poll_test_poll_timeout:
		return 0;

	default:
		return -1;
	}
	return -1;
}

ssize_t read(int fd, void *buf, size_t count)
{
	if (fd != stubbed_fd) {
		/* invalid fd, respond with error code */
		return -1;
	}

	switch (test) {
	case i3c_one_packet_read: {
		uint8_t test_payload[] = { i3c_one_packet_read_payload };
		memcpy(buf, test_payload, sizeof(test_payload));
		count = sizeof(test_payload);
		break;
	}

	case i3c_one_packet_btu_read: {
		/* 69 byte MCTP Message */
		uint8_t test_payload[] = { i3c_one_packet_btu_read_payload };
		memcpy(buf, test_payload, sizeof(test_payload));
		count = sizeof(test_payload);
		break;
	}

	case i3c_bad_btu_read: {
		/* 70 byte MCTP Message */
		uint8_t test_payload[] = { i3c_one_packet_bad_btu_read_payload };
		memcpy(buf, test_payload, sizeof(test_payload));
		count = sizeof(test_payload);
		break;
	}

	case i3c_rx_fragment_1: {
		/* 69 byte SOM Message */
		uint8_t test_payload[] = { i3c_rx_fragment1_payload };
		memcpy(buf, test_payload, sizeof(test_payload));
		count = sizeof(test_payload);
		break;
	}

	case i3c_rx_fragment_2: {
		/* 69 byte Middle message */
		uint8_t test_payload[] = { i3c_rx_fragment2_payload };
		memcpy(buf, test_payload, sizeof(test_payload));
		count = sizeof(test_payload);
		break;
	}

	case i3c_rx_fragment_3: {
		/* 4 byte EOM message */
		uint8_t test_payload[] = { i3c_rx_fragment3_payload };
		memcpy(buf, test_payload, sizeof(test_payload));
		count = sizeof(test_payload);
		break;
	}

	default:
		mctp_prerr("Invalid test case");
		return -1;
	}
	return count;
}

static void setup_test_case(struct mctp **mctp,
			    struct mctp_binding_asti3c **asti3c)
{
	*mctp = mctp_init();
	assert(mctp != NULL);

	*asti3c = mctp_asti3c_init();
	assert(asti3c != NULL);

	mctp_register_bus_dynamic_eid(*mctp, &((*asti3c)->binding));
}

static void destroy_test_case(struct mctp **mctp,
			      struct mctp_binding_asti3c **asti3c)
{
	mctp_asti3c_free(*asti3c);
	mctp_destroy(*mctp);
}

static void test_asti3c_pollin(void)
{
	int rc = 0, timeout = 100;

	test = i3c_poll_test_pollin;

	rc = mctp_asti3c_poll(stubbed_fd, timeout);
	assert((rc & POLLIN) == POLLIN);
}

static void test_asti3c_pollout(void)
{
	int rc = 0, timeout = 100;

	test = i3c_poll_test_pollout;

	rc = mctp_asti3c_poll(stubbed_fd, timeout);
	assert((rc & POLLOUT) == POLLOUT);
}

static void test_asti3c_poll_invalid_fd(void)
{
	int rc = -1, timeout = 100, fd = -1;

	test = i3c_poll_test_invalid_fd;

	rc = mctp_asti3c_poll(fd, timeout);
	assert(rc == -1);
}

static void test_asti3c_poll_timeout(void)
{
	int rc = -1, timeout = 100;

	test = i3c_poll_test_poll_timeout;

	rc = mctp_asti3c_poll(stubbed_fd, timeout);
	assert(rc == 0);
}

static void test_asti3c_init(void)
{
	struct mctp_binding_asti3c *asti3c;

	asti3c = mctp_asti3c_init();
	assert(asti3c != NULL);
}

static void test_asti3c_rx(void)
{
	struct mctp_binding_asti3c *asti3c = NULL;
	struct mctp *mctp = NULL;

	test = i3c_one_packet_read;
	setup_test_case(&mctp, &asti3c);

	void test_rx_verify_payload(mctp_eid_t src, void *data, void *msg,
				    size_t len, bool tag_owner, uint8_t tag,
				    void *ext)
	{
		uint8_t expected_data[] = {
			i3c_one_packet_read_payload_expected
		};
		int rc;

		mctp_prdebug("rx payload len: %#zx", len);

		assert(sizeof(expected_data) == len);

		rc = memcmp(expected_data, msg, len);

		assert(rc == 0);
	}

	mctp_set_rx_all(mctp, test_rx_verify_payload, NULL);
	mctp_asti3c_rx(asti3c, stubbed_fd);

	destroy_test_case(&mctp, &asti3c);
}

static void test_asti3c_rx_btu(void)
{
	struct mctp_binding_asti3c *asti3c = NULL;
	struct mctp *mctp = NULL;

	test = i3c_one_packet_btu_read;
	setup_test_case(&mctp, &asti3c);

	void test_rx_verify_payload(mctp_eid_t src, void *data, void *msg,
				    size_t len, bool tag_owner, uint8_t tag,
				    void *ext)
	{
		uint8_t expected_data[] = {
			i3c_one_packet_btu_read_payload_expected
		};
		int rc;

		mctp_prdebug("rx payload len: %#zx", len);

		assert(sizeof(expected_data) == len);

		rc = memcmp(expected_data, msg, len);

		assert(rc == 0);
	}

	mctp_set_rx_all(mctp, test_rx_verify_payload, NULL);
	mctp_asti3c_rx(asti3c, stubbed_fd);

	destroy_test_case(&mctp, &asti3c);
}

static void test_asti3c_rx_fragmented_messages(void)
{
	struct mctp_binding_asti3c *asti3c = NULL;
	struct mctp *mctp = NULL;

	test = i3c_rx_fragment_1;
	setup_test_case(&mctp, &asti3c);

	void test_rx_verify_payload(mctp_eid_t src, void *data, void *msg,
				    size_t len, bool tag_owner, uint8_t tag,
				    void *ext)
	{
		uint8_t expected_data[] = {
			i3c_rx_assembled_fragments_expected
		};

		int rc;

		mctp_prdebug("rx payload len: %#zx", len);

		assert(sizeof(expected_data) == len);

		rc = memcmp(expected_data, msg, len);

		assert(rc == 0);
	}

	mctp_set_rx_all(mctp, test_rx_verify_payload, NULL);
	mctp_asti3c_rx(asti3c, stubbed_fd);
	test = i3c_rx_fragment_2;
	mctp_asti3c_rx(asti3c, stubbed_fd);
	test = i3c_rx_fragment_3;
	mctp_asti3c_rx(asti3c, stubbed_fd);

	destroy_test_case(&mctp, &asti3c);
}

static void test_asti3c_rx_bad_btu(void)
{
	struct mctp_binding_asti3c *asti3c = NULL;
	struct mctp *mctp = NULL;
	bool packet_seen = false;

	test = i3c_bad_btu_read;
	setup_test_case(&mctp, &asti3c);

	void test_rx_verify_payload(mctp_eid_t src, void *data, void *msg,
				    size_t len, bool tag_owner, uint8_t tag,
				    void *ext)
	{
		packet_seen = true;
	}

	mctp_set_rx_all(mctp, test_rx_verify_payload, NULL);
	mctp_asti3c_rx(asti3c, stubbed_fd);

	assert(!packet_seen);

	destroy_test_case(&mctp, &asti3c);
}

static void test_asti3c_rx_bad_fd(void)
{
	struct mctp_binding_asti3c *asti3c = NULL;
	struct mctp *mctp = NULL;
	bool packet_seen = false;
	int bad_fd = -2;

	test = i3c_bad_fd_read;

	setup_test_case(&mctp, &asti3c);

	void test_rx_verify_payload(mctp_eid_t src, void *data, void *msg,
				    size_t len, bool tag_owner, uint8_t tag,
				    void *ext)
	{
		packet_seen = true;
	}

	mctp_set_rx_all(mctp, test_rx_verify_payload, NULL);
	mctp_asti3c_rx(asti3c, bad_fd);

	assert(!packet_seen);

	destroy_test_case(&mctp, &asti3c);
}

int main(void)
{
	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	test_asti3c_init();

	/* Poll tests */
	test_asti3c_pollin();
	test_asti3c_pollout();
	test_asti3c_poll_timeout();
	test_asti3c_poll_invalid_fd();

	/* RX tests */
	test_asti3c_rx();
	test_asti3c_rx_btu();
	test_asti3c_rx_fragmented_messages();
	test_asti3c_rx_bad_btu();
	test_asti3c_rx_bad_fd();

	return 0;
}
