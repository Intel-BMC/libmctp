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

#define i3c_tx_packet 0x00, 0x81, 0x04, 0x00

#define i3c_tx_packet_expected 0x01, 0x20, 0x00, 0xC8, 0x00, 0x81, 0x04, 0x00

#define i3c_one_packet_btu_write_payload                                       \
	0x00, 0x81, 0x04, 0x00, 0x20, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00,      \
		0x01, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0xC8,    \
		0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0x00, 0x81, 0x04,    \
		0x00, 0x01, 0x20, 0x09, 0xC8, 0x81, 0x04, 0x00, 0x01, 0x20,    \
		0x09, 0xC8, 0x00, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00,    \
		0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00, 0x81, 0x00,    \
		0x01, 0x20, 0x09

#define i3c_one_packet_btu_write_expected                                      \
	0x01, 0x20, 0x00, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x20, 0x09, 0xC8,      \
		0x00, 0x81, 0x04, 0x00, 0x01, 0x09, 0xC8, 0x00, 0x81, 0x04,    \
		0x00, 0x01, 0x20, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20,    \
		0x09, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x81,    \
		0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00, 0x04, 0x00, 0x01,    \
		0x20, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09,    \
		0xC8, 0x00, 0x81, 0x00, 0x01, 0x20, 0x09

#define i3c_multifragment_write                                                \
	0x00, 0x81, 0x04, 0x00, 0x20, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00,      \
		0x01, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0xC8,    \
		0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0x00, 0x81, 0x04,    \
		0x00, 0x01, 0x20, 0x09, 0xC8, 0x81, 0x04, 0x00, 0x01, 0x20,    \
		0x09, 0xC8, 0x00, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00,    \
		0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00, 0x81, 0x00,    \
		0x01, 0x20, 0x09, 0x01, 0x81, 0x04, 0x00, 0x20, 0x09, 0xC8,    \
		0x00, 0x81, 0x04, 0x00, 0x01, 0x09, 0xC8, 0x00, 0x81, 0x04,    \
		0x00, 0x01, 0x20, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20,    \
		0x09, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x81,    \
		0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00, 0x04, 0x00, 0x01,    \
		0x20, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09,    \
		0xC8, 0x00, 0x81, 0x00, 0x01, 0x20, 0x09, 0x00, 0x81, 0x04,    \
		0x00, 0x20, 0x09, 0xC8, 0x00

#define i3c_fragment1_write_expected                                           \
	0x01, 0x20, 0x00, 0x88, 0x00, 0x81, 0x04, 0x00, 0x20, 0x09, 0xC8,      \
		0x00, 0x81, 0x04, 0x00, 0x01, 0x09, 0xC8, 0x00, 0x81, 0x04,    \
		0x00, 0x01, 0x20, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20,    \
		0x09, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x81,    \
		0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00, 0x04, 0x00, 0x01,    \
		0x20, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09,    \
		0xC8, 0x00, 0x81, 0x00, 0x01, 0x20, 0x09

#define i3c_fragment2_write_expected                                           \
	0x01, 0x20, 0x00, 0x18, 0x01, 0x81, 0x04, 0x00, 0x20, 0x09, 0xC8,      \
		0x00, 0x81, 0x04, 0x00, 0x01, 0x09, 0xC8, 0x00, 0x81, 0x04,    \
		0x00, 0x01, 0x20, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20,    \
		0x09, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x81,    \
		0x04, 0x00, 0x01, 0x20, 0x09, 0xC8, 0x00, 0x04, 0x00, 0x01,    \
		0x20, 0x09, 0xC8, 0x00, 0x81, 0x04, 0x00, 0x01, 0x20, 0x09,    \
		0xC8, 0x00, 0x81, 0x00, 0x01, 0x20, 0x09

#define i3c_fragment3_write_expected                                           \
	0x01, 0x20, 0x00, 0x68, 0x00, 0x81, 0x04, 0x00, 0x20, 0x09, 0xC8, 0x00

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
	i3c_bad_fd_read,
	i3c_one_packet_write,
	i3c_one_packet_btu_write,
	i3c_fragmented_packet_write,
	i3c_one_packet_write_bad_fd
} testcase;

testcase test;

static void test_payload(uint8_t *expected_payload,
			 size_t expected_payload_size, uint8_t *test_payload,
			 size_t test_payload_size)
{
	int rc = 0;

	assert(expected_payload_size == test_payload_size);
	rc = memcmp(expected_payload, test_payload, expected_payload_size);
	assert(rc == 0);
}

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

ssize_t write(int fd, void *buf, size_t count)
{
	ssize_t write_count = count;

	if (fd != stubbed_fd) {
		/* invalid fd, respond with error code */
		return -1;
	}

	/* In real hardware, PECs are generated and appended
	   to the packets. Ignore them for test cases  */

	switch (test) {
	case i3c_one_packet_write: {
		mctp_prdebug("Test: i3c_one_packet_write");
		uint8_t expected_payload[] = { i3c_tx_packet_expected };
		test_payload(expected_payload, sizeof(expected_payload), buf,
			     count);
		break;
	}

	case i3c_one_packet_btu_write: {
		mctp_prdebug("Test: i3c_one_packet_btu_write");
		uint8_t expected_payload[] = {
			i3c_one_packet_btu_write_expected
		};
		test_payload(expected_payload, sizeof(expected_payload), buf,
			     count);
		break;
	}

	case i3c_fragmented_packet_write: {
		static uint8_t packet_count = 1;

		mctp_prdebug("Test: i3c_fragmented_packet_write. Packet = %u",
			     packet_count);

		if (packet_count == 1) {
			uint8_t expected_payload_1[] = {
				i3c_fragment1_write_expected
			};
			test_payload(expected_payload_1,
				     sizeof(expected_payload_1), buf, count);
		}

		else if (packet_count == 2) {
			uint8_t expected_payload_2[] = {
				i3c_fragment2_write_expected
			};
			test_payload(expected_payload_2,
				     sizeof(expected_payload_2), buf, count);
		}

		else if (packet_count == 3) {
			uint8_t expected_payload_3[] = {
				i3c_fragment3_write_expected
			};
			test_payload(expected_payload_3,
				     sizeof(expected_payload_3), buf, count);
		}

		packet_count++;
		break;
	}

	default: {
		mctp_prerr("Invalid test case");
		assert(0);
	}
	}

	return write_count;
}

static void setup_test_case(struct mctp **mctp,
			    struct mctp_binding_asti3c **asti3c)
{
	*mctp = mctp_init();
	assert(mctp != NULL);

	*asti3c = mctp_asti3c_init();
	assert(asti3c != NULL);

	mctp_register_bus_dynamic_eid(*mctp, &((*asti3c)->binding));

	mctp_binding_set_tx_enabled(&((*asti3c)->binding), true);
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

static void test_asti3c_tx(void)
{
	struct mctp_asti3c_pkt_private pkt_private = { .fd = stubbed_fd };
	uint8_t test_payload[] = { i3c_tx_packet };
	struct mctp_binding_asti3c *asti3c = NULL;
	struct mctp *mctp = NULL;
	uint8_t dst_eid = 0x20;
	bool tag_owner = true;
	uint8_t tag = 0;
	int rc = 0;

	test = i3c_one_packet_write;
	setup_test_case(&mctp, &asti3c);

	rc = mctp_message_tx(mctp, dst_eid, test_payload, sizeof(test_payload),
			     tag_owner, tag, &pkt_private);
	assert(rc == 0);

	destroy_test_case(&mctp, &asti3c);
}

static void test_asti3c_tx_btu(void)
{
	struct mctp_asti3c_pkt_private pkt_private = { .fd = stubbed_fd };
	struct mctp_binding_asti3c *asti3c = NULL;
	struct mctp *mctp = NULL;
	uint8_t dst_eid = 0x20;
	bool tag_owner = true;
	uint8_t tag = 0;
	int rc = 0;

	uint8_t test_payload[] = { i3c_one_packet_btu_write_payload };

	test = i3c_one_packet_btu_write;
	setup_test_case(&mctp, &asti3c);

	rc = mctp_message_tx(mctp, dst_eid, test_payload, sizeof(test_payload),
			     tag_owner, tag, &pkt_private);
	assert(rc == 0);

	destroy_test_case(&mctp, &asti3c);
}

static void test_asti3c_tx_fragmented_messages(void)
{
	struct mctp_asti3c_pkt_private pkt_private = { .fd = stubbed_fd };
	struct mctp_binding_asti3c *asti3c = NULL;
	struct mctp *mctp = NULL;
	uint8_t dst_eid = 0x20;
	bool tag_owner = true;
	uint8_t tag = 0;
	int rc = 0;

	uint8_t test_payload[] = { i3c_multifragment_write };

	test = i3c_fragmented_packet_write;
	setup_test_case(&mctp, &asti3c);

	rc = mctp_message_tx(mctp, dst_eid, test_payload, sizeof(test_payload),
			     tag_owner, tag, &pkt_private);

	assert(rc == 0);

	destroy_test_case(&mctp, &asti3c);
}

static void test_asti3c_tx_bad_fd(void)
{
	struct mctp_asti3c_pkt_private pkt_private = { .fd = -2 };
	uint8_t test_payload[] = { i3c_tx_packet };
	struct mctp_binding_asti3c *asti3c = NULL;
	struct mctp *mctp = NULL;
	uint8_t dst_eid = 0x20;
	bool tag_owner = true;
	uint8_t tag = 0;
	int rc = 0;

	test = i3c_one_packet_write_bad_fd;
	setup_test_case(&mctp, &asti3c);

	rc = mctp_message_tx(mctp, dst_eid, test_payload, sizeof(test_payload),
			     tag_owner, tag, &pkt_private);
	assert(rc != 0);

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

	/* TX tests */
	test_asti3c_tx();
	test_asti3c_tx_btu();
	test_asti3c_tx_fragmented_messages();
	test_asti3c_tx_bad_fd();

	return 0;
}
