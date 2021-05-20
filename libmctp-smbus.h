#ifndef LIBMCTP_SMBUS_H
#define LIBMCTP_SMBUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libmctp.h"

#define MCTP_HEADER_SIZE 4
#define MCTP_PAYLOAD_SIZE 64

#define SMBUS_HEADER_SIZE 4
#define SMBUS_PEC_BYTE_SIZE 1

#define SMBUS_TX_BUFF_SIZE                                                     \
	((MCTP_HEADER_SIZE) + (SMBUS_HEADER_SIZE) + (MCTP_PAYLOAD_SIZE) +      \
	 (SMBUS_PEC_BYTE_SIZE))

#define IS_MUX_PORT 0x80
#define PULL_MODEL_HOLD 0x40
#define CLOSE_AFTER_RESPONSE 0x20
#define CLOSE_IMMEDIATE 0x10

struct mctp_binding_smbus {
	struct mctp_binding binding;
	int in_fd;
	int out_fd;

	unsigned long bus_id;

	/* receive buffer */
	uint8_t rxbuf[1024];
	struct mctp_pktbuf *rx_pkt;

	/* temporary transmit buffer */
	uint8_t txbuf[SMBUS_TX_BUFF_SIZE];

	/* slave address */
	uint8_t src_slave_addr;
};

struct mctp_smbus_pkt_private {
	int fd;
	uint32_t mux_hold_timeout;
	uint8_t mux_flags;
	uint8_t slave_addr;
} __attribute__((packed));

struct mctp_binding_smbus *mctp_smbus_init(void);
int mctp_smbus_register_bus(struct mctp_binding_smbus *smbus, struct mctp *mctp,
			    mctp_eid_t eid);
int mctp_smbus_read(struct mctp_binding_smbus *smbus);
int mctp_smbus_init_pull_model(const struct mctp_smbus_pkt_private *prvt);
int mctp_smbus_exit_pull_model(const struct mctp_smbus_pkt_private *prvt);
void mctp_smbus_free(struct mctp_binding_smbus *smbus);
int mctp_smbus_close_mux(const int fd, const int address);
void mctp_smbus_set_in_fd(struct mctp_binding_smbus *smbus, int fd);
void mctp_smbus_set_out_fd(struct mctp_binding_smbus *smbus, int fd);
void mctp_smbus_set_src_slave_addr(struct mctp_binding_smbus *smbus,
				   uint8_t slave_addr);
#ifdef __cplusplus
}
#endif
#endif /*LIBMCTP_SMBUS_H */
