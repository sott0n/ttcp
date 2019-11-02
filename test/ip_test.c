#include <stdio.h>
#include "device.h"
#include "ip.h"

void icmp_recv(uint8_t *buf, ssize_t len) {}

void udp_recv(uint8_t *buf, ssize_t len) {}

void tcp_recv(uint8_t *buf, ssize_t len) {}

int main(int argc, char *argv[]) {
    char device[] = "en0";
    char ethernet_addr[] = "58:55:ca:fb:6e:9f";
        char ip_addr[] = "10.13.100.100";
        ip_addr_t addr;
        char buf[128];

        ip_set_addr(ip_addr);
        ip_add_handler(IP_PROTOCOL_ICMP, icmp_recv);
        ip_add_handler(IP_PROTOCOL_UDP, udp_recv);
        ip_add_handler(IP_PROTOCOL_TCP, tcp_recv);
    ethernet_set_addr(ethernet_addr);
    ethernet_add_handler(ETHERNET_TYPE_IP, ip_recv);
    ethernet_add_handler(ETHERNET_TYPE_ARP, arp_recv);

    if (device_init(device, ethernet_recv) == -1) {
        device_cleanup();
        return -1;
    }

        sleep(10);

    device_cleanup();
    return 0;
}