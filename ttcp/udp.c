#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include "util.h"
#include "udp.h"

#define UDP_CB_TABLE_SIZE 16
#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t sum;
};

struct udp_queue_hdr {
    ip_addr_t addr;
    uint16_t port;
    uint16_t len;
    uint8_t data[0];
};

struct udp_cb {
    int used;
    struct netif *iface;
    uint16_t port;
    struct queue_head queue;
    pthread_cond_t cond;
};

static struct udp_cb cb_table[UDP_CB_TABLE_SIZE];
static pthread_mutex_t mutex;

void udp_dump(struct netif *netif, uint8_t *packet, size_t plen)
{
    struct netif_ip *iface;
    struct udp_hdr *hdr;
    char addr[IP_ADDR_STR_LEN];

    iface = (struct netif_ip *)netif;
    fprintf(stderr, "   dev: %s (%s)\n", netif->dev->name, ip_addr_ntop(&iface->unicast, addr, sizeof(addr)));
    hdr = (struct udp_hdr *)packet;
    fprintf(stderr, " sport: %u\n", ntoh16(hdr->sport));
    fprintf(stderr, " dport: %u\n", ntoh16(hdr->dport));
    fprintf(stderr, "   len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "   sum: 0x%04\n", ntoh16(hdr->len));
    hexdump(stderr, packet, plen);
}

static ssize_t udp_tx(struct netif *iface, uint16_t sport, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port)
{
    char packet[65536];
    struct udp_hdr *hdr;
    ip_addr_t self;
    uint32_t pseudo = 0;

    hdr = (struct udp_hdr *)packet;
    hdr->sport = sport;
    hdr->dport = dport;
    hdr->len = hton16(sizeof(struct udp_hdr) + len);
    hdr->sum = 0;
    memcpy(hdr + 1, buf, len);
    self = ((struct netif_ip *)iface)->unicast;
    pseudo += (self >> 16) & 0xffff;
    pseudo += self & 0xffff;
    pseudo += (*peer >> 16) & 0xffff;
    pseudo += *peer & 0xffff;
    pseudo += hton16((uint16_t)IP_PROTOCOL_UDP);
    pseudo += hton16(sizeof(struct udp_hdr) + len);
    hdr->sum = cksum16((uint16_t *)hdr, sizeof(struct udp_hdr) + len, pseudo);
#ifdef DEBUG
    fprintf(stderr, ">>> udp_tx <<<\n");
    udp_dump((struct netif *)iface, (uint8_t *)packet, sizeof(struct udp_hdr) + len);
#endif
    return ip_tx(iface, IP_PROTOCOL_UDP, (uint8_t *)packet, sizeof(struct udp_hdr) + len, peer);
}

static void udp_rx(uint8_t *buf, size_t len, ip_addr_t *src, ip_addr_t *dst, struct netif *iface)
{
    struct udp_hdr *hdr;
    uint32_t pseudo = 0;
    struct udp_cb *cb;
    void *data;
    struct udp_queue_hdr *queue_hdr;

    if (len < sizeof(struct udp_hdr)) {
        return;
    }
    hdr = (struct udp_hdr *)buf;
    pseudo += *src >> 16;
    pseudo += *src & 0xffff;
    pseudo += *dst >> 16;
    pseudo += *dst & 0xffff;
    pseudo += hton16((uint16_t)IP_PROTOCOL_UDP);
    pseudo += hton16(len);
    if (cksum16((uint16_t *)hdr, len, pseudo) != 0) {
        fprintf(stderr, "udp checksum error\n");
        return;
    }
#ifdef DEBUG
    fprintf(stderr, ">>> udp_rx <<<\n");
    udp_dump((struct netif *)iface, buf, len);
#endif
    pthread_mutex_lock(&mutex);
    for(cb = cb_table; cb < array_tailof(cb_table); cb++) {
        if (cb->used && (!cb->iface == iface) && cb->port == hdr->dport) {
            data = malloc(sizeof(struct udp_queue_hdr) + (len - sizeof(struct udp_hdr)));
            if (!data) {
                pthread_mutex_unlock(&mutex);
                return;
            }
            queue_hdr = data;
            queue_hdr->addr = *src;
            queue_hdr->port = hdr->sport;
            queue_hdr->len = len - sizeof(struct udp_hdr);
            memcpy(queue_hdr + 1, hdr + 1, len - sizeof(struct udp_hdr));
            queue_push(&cb->queue, data, sizeof(struct udp_queue_hdr) + (len - sizeof(struct udp_hdr)))
            pthread_cond_broadcast(&cb->cond);
            pthread_mutex_unlock(&mutex);
            return;
        }
    }
    pthread_mutex_unlock(&mutex);
}

int udp_api_open(void)
{
    struct udp_cb *cb;

    pthread_mutex_lock(&mutex);
    for (cb = cb_table; cb < array_tailof(cb_table); cb++) {
        if (!cb->used) {
            cb->used = 1;
            pthread_mutex_unlock(&mutex);
            return array_offset(cb_table, cb);
        }
    }
    pthread_mutex_unlock(&mutex);
    return -1;
}

int udp_api_close(int soc)
{
    struct udp_cb *cb;
    struct queue_entry *entry;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&mutex);
    cb = &cb_table[soc];
    if (!cb->used) {
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    cb->used = 0;
    cb->iface = NULL;
    cb->port = 0;
    while ((entry = queue_pop(&cb->queue)) != NULL) {
        free(entry->data);
        free(entry);
    }
    cb->queue.next = cb->queue.tail = NULL;
    pthread_mutex_unlock(&mutex);
    return 0;
}

int udp_api_bind(int soc, ip_addr_t *addr, uint16_t port)
{
    struct udp_cb *cb, *tmp;
    struct netif *iface = NULL;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }
    pthread_mutex_lock(&mutex);
    cb = &cb_table[soc];
    if (!cb->used) {
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    if (addr && *addr) {
        iface = ip_netif_by_addr(addr);
        if (!iface) {
            pthread_mutex_unlock(&mutex);
            return -1;
        }
    }
    for (tmp = cb_table; tmp < array_tailof(cb_table); tmp++) {
        if (tmp->used && tmp != cb && (!iface || !tmp->iface || tmp->iface == iface) && tmp->port == port) {
            pthread_mutex_unlock(&mutex);
            return -1;
        }
    }
    cb->iface = iface;
    cb->port = port;
    pthread_mutex_unlock(&mutex);
    return 0;
}