#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include "device.h"

static void
arp_table_print (void) {
	int offset;
	char ha[ETHERNET_ADDR_STR_LEN + 1], pa[IP_ADDR_STR_LEN + 1];

	pthread_rwlock_rdlock(&g_arp.rwlock);
	fprintf(stderr, "\n");
	fprintf(stderr, "--------------------------------\n");
	for (offset = 0; offset < g_arp.num; offset++) {
		ethernet_addr_ntop(&g_arp.table[offset].ha, ha, sizeof(ha));
		ip_addr_ntop(&g_arp.table[offset].pa, pa, sizeof(pa));
		fprintf(stderr, "%s at %s\n", pa, ha);
	}
	fprintf(stderr, "--------------------------------\n");
	pthread_rwlock_unlock(&g_arp.rwlock);
}

int
main (int argc, char *argv[]) {
	sigset_t sigset;
	int signo;

	if (argc != 5) {
		fprintf(stderr, "usage: %s device-name ethernet-addr ip-addr netmask\n", argv[0]);
		return -1;
	}
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigprocmask(SIG_BLOCK, &sigset, NULL);

	if (ip_set_addr(argv[3], argv[4]) == -1) {
		fprintf(stderr, "error: ip-addr/netmask is invalid\n");
		return -1;
	}
	arp_init();
    if (ethernet_set_addr(argv[2]) == -1) {
		fprintf(stderr, "error: ethernet-addr is invalid\n");
		return -1;
	}
    ethernet_add_handler(ETHERNET_TYPE_ARP, arp_recv);
    if (device_init(argv[1], ethernet_recv) == -1) {
        return -1;
    }
	sigwait(&sigset, &signo);
	arp_table_print();
    device_cleanup();
    return  0;
}