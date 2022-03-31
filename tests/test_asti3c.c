#include <stdio.h>

#include "libmctp-asti3c.h"

static void test_asti3c_init(void)
{
    struct mctp_binding_asti3c* asti3c;

    asti3c = mctp_asti3c_init();
    assert(asti3c != NULL);
}

int main(void)
{
    mctp_set_log_stdio(MCTP_LOG_DEBUG);

    test_asti3c_init();

    return 0;
}