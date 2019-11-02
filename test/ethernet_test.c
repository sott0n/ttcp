#include <stdio.h>
#include <string.h>
#include "device.h"
#include "ethernet.h"


static void arp_recv(uint8_t *buf, ssize_t len, int bcast) {
    fprintf(stderr, "ARP: %ld, %s\n", len, bcast ? "broadcast" : "unicast");
}

static void ip_recv(uint8_t *buf, ssize_t len, int bcast) {
    fprintf(stderr, "IP: %ld, %s\n", len, bcast ? "broadcast" : "unicast");
}

int main(int argc, char *argv[]) {
    char device[] = "en0";
    char ethernet_addr[] = "58:55:ca:fb:6e:9f";

    ethernet_set_addr(ethernet_addr);
    ethernet_add_handler(ETHERNET_TYPE_ARP, arp_recv);
    ethernet_add_handler(ETHERNET_TYPE_IP, ip_recv);
    if (device_init(device, ethernet_recv) == -1) {
        device_cleanup();
        return -1;
    }
    sleep(10);
    device_cleanup();
    return 0;
}