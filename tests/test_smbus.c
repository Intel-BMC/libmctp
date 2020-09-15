/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "libmctp-smbus.h"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_EID 8

int main(void)
{
	struct mctp *mctp;
	struct mctp_binding *binding;
	struct mctp_pktbuf pkt;
	struct mctp_binding_smbus *smbus;
	int rc;

	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	mctp = mctp_init();
	assert(mctp);
	smbus = mctp_smbus_init();
	assert(smbus);

	assert(strcmp(smbus->binding.name, "smbus") == 0);
	assert(smbus->binding.version == 1);
	assert(smbus->binding.tx != NULL);

	rc = mctp_smbus_register_bus(smbus, mctp, TEST_EID);
	assert(rc == 0);

	/* cleanup */
	mctp_smbus_free(smbus);
	__mctp_free(mctp);

	return 0;
}
