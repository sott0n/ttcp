#include "arp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define ARP_HRD_ETHERNET 0x0001
#define ARP_OP_REQUEST  1
#define ARP_OP_REPLY    2

#define ARP_TABLE_SIZE 4096
#define ARP_LOOKUP_RETRY_NUM 3
#define ARP_LOOKUP_WAIT_USEC 1000*10

struct arp_hdr {
    uint16_t hrd;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
} __attribute__((packed));

struct arp {
    struct arp_hdr hdr;
    ethernet_addr_t sha;    // Source hardware address (= MAC address)
    ip_addr_t spa;          // Source internetwork address
    ethernet_addr_t tha;    // Destination hardware address (= MAC address)
    ip_addr_t tpa;          // Destination internetwork address
} __attribute__((packed));

static struct {
    struct {
        ip_addr_t pa;
        ethernet_addr_t ha;
    } table[ARP_TABLE_SIZE];
    int num;
    int position;
    gthread_rwlock_t rwlock;
} g_arp = {{0}, 0, 0, PTHREAD_RWLOCK_INITIALIZER};

static int arp_send_request(const ip_addr_t *tpa);
static int arp_send_reply(const ethernet_addr_t *tha, const ip_addr_t *tpa);

int arp_table_lookup(const ip_addr_t *pa, ethernet_addr_t *ha) {
    int offset, count, ret;

    pthread_rwlock_rdlock(&g_arp.rwlock);
    for (offset = 0; offset < g_arp.num; offset++) {
        if (g_arp.table[offset].pa == *pa) {
            memcpy(ha, &g_arp.table[offset].ha, sizeof(ethernet_addr_t));
            break;
        }
    }
    if (offset == g_arp.num) {
        for (count = 0; count < ARP_LOOKUP_RETRY_NUM; count++) {
            pthread_rwlock_unlock(&g_arp.rwlock);
            arp_send_request(pa);
            usleep(ARP_LOOKUP_WAIT_USEC);
            pthread_rwlock_rdlock(&g_arp.rwlock);
            for (offset = 0; offset < g_arp.num; offset++) {
                if (g_arp.table[offset].pa == *pa) {
                    memcpy(ha, &g_arp.table[offset].ha, sizeof(ethernet_addr_t));
                    break;
                }
            }
        }
    }
    ret = (offset < g_arp.num) ? 0 : -1;
    pthread_rwlock_unlock(&g_arp.rwlock);
    return ret;
}

static int arp_table_update(const ethernet_addr_t *ha, const ip_addr_t *pa) {
    int offset;

    pthread_rwlock_wrlock(&g_arp.rwlock);
    for (offset = 0; offset < g_arp.num; offset++) {
        if (g_arp.table[offset].pa == *pa) {
            memcpy(&g_arp.table[offset].ha, ha, sizeof(ethernet_addr_t));
            break;
        }
    }
    if (offset == g_arp.num) {
        memcpy(&g_arp.table[g_arp.position].pa, pa, sizeof(ip_addr_t));
        memcpy(&g_arp.table[g_arp.position].ha, ha, sizeof(ethernet_addr_t));
        if (++g_arp.position == ARP_TABLE_SIZE) {
            g_arp.position = 0;
        }
        if (g_arp.num != ARP_TABLE_SIZE) {
            g_arp.num += 1;
        }
        pthread_rwlock_unlock(&g_arp.rwlock);
        return 0;
    }
}

void arp_recv(uint8_t *buf, ssize_t len, int bcast) {
    struct arp *arp;

    if (len < sizeof(struct arp)) {
        return;
    }
    arp = (struct arp *)buf;
    if (ntohs(arp->hdr.hrd) != ARP_HRD_ETHERNET || ntohs(arp->hdr.pro) != ETHERNET_TYPE_IP) {
        return;
    }
    if (ip_addr_isself(&arp->tpa)) {
        if (ntohs(arp->hdr.op) == ARP_OP_REQUEST) {
            arp_send_reply(&arp->sha, &arp->spa);
        }
        arp_table_update(&arp->sha, &arp->spa);
    } else if(arp->spa == arp->tpa) {
        arp_table_update(&arp->sha, &arp->spa);
    }
}

static int arp_send_request(const ip_addr_t *tpa) {
    struct arp arp;

    if (!tpa) {
        return -1;
    }
    arp.hdr.hrd = htons(ARP_HRD_ETHERNET);
    arp.hdr.pro = htons(ETHERNET_TYPE_IP);
    arp.hdr.hln = 6;
    arp.hdr.pln = 4;
    arp.hdr.op = htons(ARP_OP_REQUEST);
    memcpy(&arp.sha, ethernet_get_addr(), ETHERNET_ADDR_LEN);
    memcpy(&arp.spa, ip_get_addr(), IP_ADDR_LEN);
    memset(&arp.tha, 0, ETHERNET_ADDR_LEN);
    memcpy(&arp.tpa, tpa, IP_ADDR_LEN);
    if (ethernet_send(ETHERNET_TYPE_ARP, (uint8_t *)&arp, sizeof(arp), &ETHERNET_ADDR_BCAST) < 0) {
        return -1;
    }
    return 0;
}

static int arp_send_reply(const ethernet_addr_t *tha, const ip_addr_t *tpa) {
    struct arp arp;

    if (!tha || !tpa) {
        return -1;
    }

    arp.hdr.hrd = htons(ARP_HRD_ETHERNET);
    arp.hdr.pro = htons(ETHERNET_TYPE_IP);
    arp.hdr.hln = 6;
    arp.hdr.pln = 4;
    arp.hdr.op = htons(ARP_OP_REPLY);
    memcpy(&arp.sha, ethernet_get_addr(), ETHERNET_ADDR_LEN);
    memcpy(&arp.spa, ip_get_addr(), IP_ADDR_LEN);
    memcpy(&arp.tha, tha, ETHERNET_ADDR_LEN);
    memcpy(&arp.tpa, tpa, IP_ADDR_LEN);
    if (ethernet_send(ETHERNET_TYPE_ARP, (uint8_t *)&arp, sizeof(arp), tha) < 0) {
        return -1;
    }
    return 0;
}