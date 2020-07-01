/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_VDPCI_H
#define _LIBMCTP_VDPCI_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libmctp.h"

/*
 * Helper structs for MCTP VDPCI messages.
 */

struct mctp_vdpci_hdr {
	uint8_t ic_msg_type;
	uint16_t vendor_id;
} __attribute__((__packed__));

struct mctp_vdpci_intel_hdr {
	struct mctp_vdpci_hdr vdpci_hdr;
	uint8_t reserved;
	uint8_t vendor_type_code;
} __attribute__((__packed__));

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_VDPCI_H */
