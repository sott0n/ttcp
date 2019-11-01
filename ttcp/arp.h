#ifndef __ARP_H_
#define __ARP_H_

#include "ethernet.h"
#include "ip.h"

extern int arp_table_lookup(const ip_addr_t, ethernet_addr_t *ha);
extern void arp_recv(uint8_t *buf, ssize len, int bcast);

#endif