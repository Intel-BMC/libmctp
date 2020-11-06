/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

/* This is a private header file defining binding structure for PCIe binding */

#ifndef _ASTPCIE_H
#define _ASTPCIE_H

#include "libmctp.h"

#define MCTP_ASTPCIE_BINDING_DEFAULT_BUFFER 1024

struct mctp_binding_astpcie {
	struct mctp_binding binding;
	uint16_t bdf;
	uint8_t medium_id;
	int fd;
};

/* returns pointer to structure holding this generic binding */
#define binding_to_astpcie(b)                                                  \
	container_of(b, struct mctp_binding_astpcie, binding)

#define ASTPCIE_PACKET_SIZE(x) (ASPEED_MCTP_PCIE_VDM_HDR_SIZE + x)

/* driver device file */
#define AST_DRV_FILE "/dev/aspeed-mctp"

struct mctp_pcie_hdr {
	uint8_t fmt_type;
	uint8_t mbz;
	uint16_t mbz_attr_length;
	uint16_t requester;
	uint8_t tag;
	uint8_t code;
	uint16_t target;
	uint16_t vendor;
} __attribute__((packed));

/*
 * MCTP PCIe template values
 * The following non-zero values are defined by DSP0238 DMTF Spec as constants:
 * .fmt_type:
 * ----------
 * [4:0]: Type[4:3] = 10b to indicate a message.
 * [6:5]: Fmt = 11b to indicate 4 dword header with data.
 * ----------
 * .mbz_attr_length:
 * [5:4]: Attr[1:0] = 01b for all MCTP over PCIe VDM
 * ----------
 * .code
 * ----------
 * [7:0]: Message Code = 0111_1111b to indicate a Type 1 VDM
 * ----------
 * .vendor
 * ----------
 * byte2[7:0]: Vendor ID MSB = 0x1a - DMTF VDMs
 * byte3[7:0]: Vendor ID LSB = 0xb4 - DMTF VDMs
 *
 * See more details in Table 1 of DSP0238 DMTF Spec.
 */
#define MSG_4DW_HDR 0x70
#define MCTP_PCIE_VDM_ATTR 0x0010
#define MSG_CODE_VDM_TYPE_1 0x7f
#define VENDOR_ID_DMTF_VDM 0xb41a

#define PCIE_HDR_ROUTING_SHIFT 0
#define PCIE_HDR_ROUTING_MASK 0x7

#define PCIE_GET_ROUTING(x)                                                    \
	((x->fmt_type >> PCIE_HDR_ROUTING_SHIFT) & PCIE_HDR_ROUTING_MASK)
#define PCIE_SET_ROUTING(x, val)                                               \
	(x->fmt_type |=                                                        \
	 (((val)&PCIE_HDR_ROUTING_MASK) << PCIE_HDR_ROUTING_SHIFT))

#define PCIE_HDR_DATA_LEN_SHIFT 0
#define PCIE_HDR_DATA_LEN_MASK 0xff03

#define PCIE_GET_DATA_LEN(x)                                                   \
	be16toh(((x->mbz_attr_length >> PCIE_HDR_DATA_LEN_SHIFT) &             \
		 PCIE_HDR_DATA_LEN_MASK))

#define PCIE_SET_DATA_LEN(x, val)                                              \
	(x->mbz_attr_length |=                                                 \
	 ((htobe16(val) & PCIE_HDR_DATA_LEN_MASK) << PCIE_HDR_DATA_LEN_SHIFT))

#define PCIE_GET_REQ_ID(x) (be16toh(x->requester))
#define PCIE_SET_REQ_ID(x, val) (x->requester |= (htobe16(val)))

#define PCIE_HDR_PAD_LEN_SHIFT 4
#define PCIE_HDR_PAD_LEN_MASK 0x3
#define PCIE_GET_PAD_LEN(x)                                                    \
	((x->tag >> PCIE_HDR_PAD_LEN_SHIFT) & PCIE_HDR_PAD_LEN_MASK)
#define PCIE_SET_PAD_LEN(x, val)                                               \
	(x->tag |= (((val)&PCIE_HDR_PAD_LEN_MASK) << PCIE_HDR_PAD_LEN_SHIFT))

#define PCIE_GET_TARGET_ID(x) (be16toh(x->target))
#define PCIE_SET_TARGET_ID(x, val) (x->target |= (htobe16(val)))

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (a)-1)
/* All PCIe packets are dword aligned */
#define PCIE_PKT_ALIGN(x) ALIGN(x, sizeof(uint32_t))

#define PCIE_HDR_SIZE_DW (sizeof(struct mctp_pcie_hdr) / sizeof(uint32_t))
#define MCTP_HDR_SIZE_DW (sizeof(struct mctp_hdr) / sizeof(uint32_t))
#define PCIE_VDM_HDR_SIZE_DW (PCIE_HDR_SIZE_DW + MCTP_HDR_SIZE_DW)

#endif
