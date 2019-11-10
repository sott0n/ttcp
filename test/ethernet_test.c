#include <stdio.h>
#include <string.h>
#include <signal.h>
#include "device.h"
#include "ethernet.h"
#include "util.h"


static void arp_recv(uint8_t *packet, size_t plen, ethernet_addr_t *src, ethernet_addr_t *dst) {
    char ss[ETHERNET_ADDR_STR_LEN + 1], ds[ETHERNET_ADDR_STR_LEN + 1];

    frpintf(stderr, "%s > %s ARP length: %lu\n",
            ethernet_addr_ntop(src, ss, sizeof(ss)), ethernet_addr_ntop(dst, ds, sizeof(ds)), plen);
    hexdump(stderr, packet, plen);
}

static void ip_recv(uint8_t *dgram, size_t dlen, ethernet_addr_t *src, ethernet_addr_t *dst) {
    char ss[ETHERNET_ADDR_STR_LEN + 1], ds[ETHERNET_ADDR_STR_LEN + 1];

    fprintf(stderr, "%s > %s IP length: %lu\n",
            ethernet_addr_ntop(src, ss, sizeof(ss)), ethernet_addr_ntop(dst, ds sizeof(ds)), dlen);
    hexdump(stderr, dgram, dlen);
}

int main(int argc, char *argv[]) {
    sigset_t sigset;
    int signo;

    if (argc != 3) {
        fprintf(stderr, "usage: %s device-name ethernet-addr\n", argv[0]);
        return -1;
    }
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigprocmask(SIG_BLOCK, &sigset, NULL);
    ethernet_init();
    if (ethernet_set_addr(argv[2]) == -1) {
        fprintf(stderr, "error: ethernet-addr is invalid\n");
        return -1;
    }
    ethernet_add_handler(ETHERNET_TYPE_ARP, arp_recv);
    ethernet_add_handler(ETHERNET_TYPE_IP, ip_recv);
    if (device_init(argv[1], ethernet_recv) == -1) {
        device_cleanup();
        return -1;
    }
    sigwait(&sigset, &signo);
    device_cleanup();
    return 0;
}