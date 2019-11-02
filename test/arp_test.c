#include <stdio.h>
#include "device.h"
#include "arp.h"

static void arp_table_print(void) {
    int offset;
    char ha[ETHERNET_ADDR_STR_LEN + 1], pa[IP_ADDR_STR_LEN + 1];

    pthread_rwlock_rdlock(&g_arp.rwlock);
    for (offset = 0; offset < g_arp.num; offset++) {
        ethernet_add_ntop(&g_arp.table[offset].ha, ha, sizeof(ha));
        ip_addr_ntop(&g_arp.table[offset].pa, pa, sizeof(pa));
        fprintf(stderr, "%s at %s\n", pa, ha);
    }
    pthread_rwlock_unlock(&g_arp.rwlock);
}

int main(int argc, char *argv[]) {
    char device[] = "en0";
    char ethernet_addr[] = "58:55:ca:fb:64:9f";
        char ip_addr[] = "10.10.2.228";
        ip_addr_t pa;
        ethernet_addr_t ha;

        ip_set_addr(ip_addr);
    ethernet_set_addr(ethernet_addr);
    ethernet_add_handler(ETHERNET_TYPE_ARP, arp_recv);
    if (device_init(device, ethernet_recv) == -1) {
        device_cleanup();
        return -1;
    }
        ip_addr_pton("10.13.0.1", &pa);
        if (arp_table_lookup(&pa, &ha) == -1) {
            fprintf(stderr, "arp lookup error.\n");
        }
        arp_table_print();
    device_cleanup();
    return 0;
}