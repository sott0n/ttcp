#include <stdio.h>
#include <pthread.h>
#include "ttcp.h"
#include "util.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"

int ttcp_init(void)
{
    if (ethernet_init() == -1) {
        ttcp_cleanup();
        return -1;
    }
    if (arp_init() == -1) {
        ttcp_cleanup();
        return -1;
    }
    if (ip_init() == -1) {
        ttcp_cleanup();
        return -1;
    }
    if (icmp_init() == -1) {
        ttcp_cleanup();
        return -1;
    }
    if (udp_init() == -1) {
        ttcp_cleanup();
        return -1;
    }
    if (tcp_init() == -1) {
        ttcp_cleanup();
        return -1;
    }
    return 0;
}

void ttcp_cleanup(void)
{
    //ethernet_device_close();
}