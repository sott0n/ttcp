#include <stdio.h>
#include "device.h"
#include "ip.h"

void icmp_recv(uint8_t *packet, size_t plen, in_addr_t *src, in_addr_t *dst) {
    char ss[IP_ADDR_STR_LEN + 1], ds[IP_ADDR_STR_LEN + 1];

    fprintf(stderr, "%s > %s ICMP %ul\n",
            ip_addr_ntop(src, ss, sizeof(ss)),
            ip_addr_ntop(dst, ds, sizeof(ds)),
            plen);
    hexdump(stderr, packet, plen);
}

void udp_recv(uint8_t *dgram, ssize_t dlen, in_addr_t *src, in_addr_t *dst) {
    char ss[IP_ADDR_STR_LEN + 1], ds[IP_ADDR_STR_LEN + 1];

    fprintf(stderr, "%s > %s UDP %lu\n",
            ip_addr_ntop(src, ss, sizeof(ss)),
            ip_addr_ntop(dst, ds, sizeof(ds)),
            dlen);
    hexdump(stderr, dgram, dlen);
}

void tcp_recv(uint8_t *segment, ssize_t slen, in_addr_t *src, in_addr_t *dst) {
    char ss[IP_ADDR_STR_LEN + 1], ds[IP_ADDR_STR_LEN + 1];

    fprintf(stderr, "%s > %s TCP %ul\n",
            ip_addr_ntop(src, ss, sizeof(ss)),
            ip_addr_ntop(dst, ds, sizeof(ds)),
            slen);
    hexdump(stderr, segment, slen);
}

int main(int argc, char *argv[]) {
        sigset_t sigset;
        int signo;

        if (argc != 6) {
            fprintf(stderr, "usage: %s device-name ethernet-addr ip-addr netmask default-gw\n", argv[0]);
            return -1;
        }
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigprocmask(SIG_BLOCK, &sigset, NULL);
        if (ip_set_addr(argv[3], argv[4]) == -1) {
            fprintf(stderr, "error: ip-addr/netmast is invalid\n");
            return -1;
        }
        if (ip_set_gw(argv[5]) == -1) {
            fprintf(stderr, "error: default-gw is invalid\n");
            return -1;
        }
        ip_add_handler(IP_PROTOCOL_ICMP, icmp_recv);
        ip_add_handler(IP_PROTOCOL_UDP, udp_recv);
        ip_add_handler(IP_PROTOCOL_TCP, tcp_recv);
        arp_init();
    if (ethernet_set_addr(argv[2]) == -1) {
        fprintf(stderr, "error: ethernet-addr is invalid\n");
        return -1;
    }
    ethernet_add_handler(ETHERNET_TYPE_IP, ip_recv);
    ethernet_add_handler(ETHERNET_TYPE_ARP, arp_recv);

    if (device_init(argv[1], ethernet_recv) == -1) {
        fprintf(stderr, "error: device-name is invalid\n");
        return -1;
    }
        sigwait(&sigset, &signo);

    device_cleanup();
    return 0;
}