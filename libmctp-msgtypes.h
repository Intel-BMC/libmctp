/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_MSGTYPES_H
#define _LIBMCTP_MSGTYPES_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * MCTP Message Type codes
 * See DSP0239 v1.3.0 Table 1.
 */
#define MCTP_MESSAGE_TYPE_MCTP_CTRL 0x00
#define MCTP_MESSAGE_TYPE_PLDM 0x01
#define MCTP_MESSAGE_TYPE_NCSI 0x02
#define MCTP_MESSAGE_TYPE_ETHERNET 0x03
#define MCTP_MESSAGE_TYPE_NVME 0x04
#define MCTP_MESSAGE_TYPE_SPDM 0x05
#define MCTP_MESSAGE_TYPE_VDPCI 0x7E
#define MCTP_MESSAGE_TYPE_VDIANA 0x7F

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_MSGTYPES_H */
