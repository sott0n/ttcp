#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <pthread.h>
#include "ip.h"
#include "icmp.h"
#include "arp.h"
#include "util.h"

#define IP_FRAGMENT_TIMEOUT_SEC 30
#define IP_FRAGMENT_NUM_MAX 8
#define IP_ROUTE_TABLE_SIZE 8

struct ip_route {
    uint8_t used;
    ip_addr_t network;
    ip_addr_t netmask;
    ip_addr_t nexthop;
    struct netif *netif;
};

struct ip_fragment {
    struct ip_fragment *next;
    ip_addr_t src;
    ip_addr_t dst;
    uint16_t id;
    uint16_t protocol;
    uint16_t len;
    uint8_t data[65535];
    uint32_t mask[2048];
    time_t timestamp;
};

struct ip_protocol {
    struct ip_protocol *next;
    uint8_t type;
    void (*handle)(uint8_t *payload, size_t len, ip_addr_t *src, ip_addr_t *dst, struct netif *netif);
};

static void ip_rx(uint8_t *dgram, size_t dlen, struct netdev *dev);
static int ip_tx_netdev(struct netif *netif, uint8_t *packet, size_t plen, const ip_addr_t *dst);

static struct ip_route route_table[IP_ROUTE_TABLE_SIZE];
static struct ip_protocol *protocols;
static struct ip_fragment *fragments;
static int ip_forwarding;

const ip_addr_t IP_ADDR_ANY         = 0x00000000;
const ip_addr_t IP_ADDR_BROADCAST   = 0xffffffff;

int ip_addr_pton(const char *p, ip_addr_t *n)
{
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++) {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255) {
            return -1;
        }
        if (ep == sp) {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

char *ip_addr_ntop(const ip_addr_t *n, char *p, size_t size)
{
    uint8_t *ptr;

    ptr = (uint8_t *)n;
    snprintf(p, size, "%d.%d.%d.%d",
        ptr[0], ptr[1], ptr[2], ptr[3]);
    return p;
}

void ip_dump(struct netif *netif, uint8_t *packet, size_t plen)
{
    struct netif_ip *iface;
    char addr[IP_ADDR_STR_LEN];
    struct ip_hdr *hdr;
    uint8_t hl;
    uint16_t offset;

    iface = (struct netif_ip *)netif;
    fprintf(stderr, " dev: %s (%s)\n", netif->dev->name, ip_addr_ntop(&iface->unicast, addr, sizeof(addr)));
    hdr = (struct ip_hdr *)packet;
    hl = hdr->vhl & 0x0f;
    fprintf(stderr, "      vhl: %02x [v: %u (%u)]\n", hdr->vhl, (hdr->vhl & 0xf0) >> 4, hl, hl << 2);
    fprintf(stderr, "      tos: %02x\n", hdr->tos);
    fprintf(stderr, "      len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "       id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    fprintf(stderr, "   offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe0) >> 5, offset & 0x1f);
    fprintf(stderr, "      ttl: %u\n", hdl->ttl);
    fprintf(stderr, " protocol: %u\n", hdr->protocol);
    fprintf(stderr, "      sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "      src: %s\n", ip_addr_ntop(&hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "      dst: %s\n", ip_addr_ntop(&hdr->dst, addr, sizeof(addr)));
    hexdump(stderr, packet, plen);
}

/*
 * IP FRAGMENT
 */

static struct ip_fragment *ip_fragment_alloc(struct ip_hdr *hdr)
{
    struct ip_fragment *new_flagment;

    new_fragment = malloc(sizeof(struct ip_fragment));
    if (!new_flagment) {
        return NULL;
    }
    new_flagment->next = fragments;
    new_flagment->src = hdr->src;
    new_flagment->dst = hdr->dst;
    new_flagment->id = hdr->id;
    new_flagment->protocol = hdr->protocol;
    new_flagment->len = 0;
    memset(new_flagment->data, 0, sizeof(new_flagment->data));
    maskclr(new_flagment->mask, sizeof(new_flagment->mask));
    fragments = new_flagment;
    return new_flagment;
}

static void ip_fragment_free(struct ip_fragment *fragment)
{
    free(fragment);
}

static struct ip_fragment *ip_fragment_detach(struct ip_fragment *fragment)
{
    struct ip_fragment *entry, *prev = NULL;

    for (entry = fragments; entry; entry = entry->next) {
        if (entry == fragment) {
            if (prev) {
                prev->next = fragment->next;
            } else {
                fragments = fragment->next;
            }
            fragment->next = NULL;
            return fragment;
        }
        prev = entry;
    }
    return NULL;
}

static struct ip_fragment *ip_fragment_search(struct ip_hdr *hdr)
{
    struct ip_fragment *entry;

    for (entry = fragments; entry; entry = entry->next) {
        if (entry->src == hdr->src && entry->dst == hdr->dst && entry->id == hdr->id && entry->protocol == hdr->protocol) {
            return entry;
        }
    }
    return NULL;
}

static int ip_fragment_patrol(void)
{
    time_t now;
    struct ip_fragment *entry, *prev = NULL;
    int count = 0;

    now = time(NULL);
    entry = fragments;
    while (entry) {
        if (now - entry->timestamp > IP_FRAGMENT_TIMEOUT_SEC) {
            if (prev) {
                entry = prev->next = entry->next;
            } else {
                entry = fragments = entry->next;
            }
            free(entry);
            count++;
            continue;
        }
        prev = entry;
        entry = entry->next;
    }
    return count;
}

static struct ip_fragment *ip_fragment_process(struct ip_hdr *hdr, uint8_t *payload, size_t plen)
{
    struct ip_fragment *fragment;
    uint16_t off;
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    static time_t timestamp = 0;
    static size_t count = 0;

    pthread_mutex_lock(&mutex);
    if (time(NULL) - timestamp > 10) {
        ip_fragment_patrol();
    }
    fragment = ip_fragment_search(hdr);
    if (!fragment) {
        if (count >= IP_FRAGMENT_NUM_MAX) {
            pthread_mutex_unlock(&mutex);
            return NULL;
        }
        fragment = ip_fragment_alloc(hdr);
        if (!fragment) {
            pthread_mutex_unlock(&mutex);
            return NULL;
        }
        count++;
    }
    off = (ntoh16(hdr->offset) & 0x1fff) << 3;
    memcpy(fragment->data + off, payload, plen);
    maskset(fragment->mask, sizeof(fragment->mask), off, plen);
    if ((ntoh16(hdr->offset) & 0x2000) == 0) {
        fragment->len = off + plen;
    }
    fragment->timestamp = time(NULL);
    if (!fragment->len) {
        /* more fragments exists */
        pthread_mutex_unlock(&mutex);
        return NULL;
    }
    if (!maskchk(fragment->mask, sizeof(fragment->mask), 0, fragment->len)) {
        /* imcomplete flagments */
        pthread_mutex_unlock(&mutex);
        return NULL;
    }
    ip_fragment_detach(fragment);
    count--;
    pthread_mutex_unlock(&mutex);
    return fragment;
}

/*
 * IP ROUTING
 */

static int ip_route_add(ip_addr_t network, ip_addr_t netmask, ip_addr_t nexthop, struct netif *netif)
{
    struct ip_route *route;

    for (route = route_table; route < array_tailof(route_table); route++) {
        if (!route->used) {
            route->used = 1;
            route->network = network;
            route->netmask = netmask;
            route->nexthop = nexthop;
            route->netif = netif;
            return 0;
        }
    }
    return -1;
}

static int ip_route_del(struct netif *netif)
{
    struct ip_route *route;

    for (route = route_table; route < array_tailof(route_table); route++) {
        if (route->used) {
            if (route->netif == netif) {
                route->used = 0;
            }
        }
    }
    return 0;
}

static struct ip_route *ip_route_lookup(const struct netif *netif, const ip_addr_t *dst)
{
    struct ip_route *route, *candidate = NULL;

    for (route = route_table; route < array_tailof(route_table); route++) {
        if (route->used && (*dst & route->netmask) === route->network && (!netif || route->netif == netif)) {
            if (!candidate || ntoh32(candidate->netmask) < ntoh32(route->netmask)) {
                candidate = route;
            }
        }
        return candidate;
    }
}

/*
 * IP INTERFACE
 */

struct netif *ip_netif_alloc(const char *addr, const char *netmask, const char *gateway)
{
    struct netif_ip *iface;
    ip_addr_t gw;

    iface = malloc(sizeof(struct netif_ip));
    if (!iface) {
        return NULL;
    }
    ((struct netif *)iface)->next = NULL;
    ((struct netif *)iface)->family = NETIF_FAMILY_IPV4;
    ((struct netif *)iface)->dev = NULL;
    if (ip_addr_pton(addr, &iface->unicast) == -1) {
        free(iface);
        return NULL;
    }
    if (ip_addr_pton(netmask, &iface->netmask) == -1) {
        free(iface);
        return NULL;
    }
    iface->network = iface->unicast & iface->netmask;
    iface->broadcast = iface->network | ~iface->netmask;
    if (ip_route_add(iface->network, iface->netmask, IP_ADDR_ANY, (struct netif *)iface) == -1) {
        free(iface);
        return NULL;
    }
    if (gateway) {
        if (ip_addr_pton(gateway, &gw) == -1) {
            free(iface);
            return NULL;
        }
        if (ip_route_add(IP_ADDR_ANY, IP_ADDR_ANY, gw, (struct netif *)iface) == -1) {
            free(iface);
            return NULL;
        }
    }
    return (struct netif *)iface;
}

struct netif *ip_netif_register(struct netdev *dev, const char *addr, const char *netmask, const char *gateway)
{
    struct netif *netif;

    netif = ip_netif_alloc(addr, netmask, gateway);
    if (!netif) {
        return NULL;
    }
    if (netdev_add_netif(dev, netif) == -1) {
        free(netif);
        return NULL;
    }
    return netif;
}

int ip_netif_reconfigure(struct netif *netif, const char *addr, const char *netmask, const char *gateway)
{
    struct netif_ip *iface;
    ip_addr_t gw;

    iface = (struct netif_ip *)netif;
    ip_route_del(netif);
    if (ip_addr_pton(addr, &iface->unicast) == -1) {
        return -1;
    }
    if (ip_addr_pton(netmask, &iface->netmask) == -1) {
        return -1;
    }
    iface->network = iface->unicast & iface->netmask;
    iface->broadcast = iface->network | ~iface->netmask;
    if (ip_route_add(iface->network, iface->netmask, IP_ADDR_ANY, netif) == -1) {
        return -1;
    }
    if (gateway) {
        if (ip_addr_pton(gateway, &gw) == -1) {
            return -1;
        }
        if (ip_route_add(IP_ADDR_ANY, IP_ADDR_ANY, gw, netif) == -1) {
            return -1;
        }
    }
    return 0;
}

struct netif *ip_netif_by_addr(ip_addr_t *addr)
{
    struct netdev *dev;
    struct netif *entry;

    for (dev = netdev_root(); dev; dev = dev->next) {
        for (entry = dev->ifs; entry; entry = entry->next) {
            if (entry->family == NETIF_FAMILY_IPV4 && ((struct netif_ip *)entry)->unicast == *addr) {
                return entry;
            }
        }
    }
    return NULL;
}

struct netif *ip_netif_by_peer(ip_addr_t *peer)
{
    struct ip_route *route;

    route = ip_route_lookup(NULL, peer);
    if (!route) {
        return NULL;
    }
    return route->netif;
}

/*
 * IP FORWARDING
 */

int ip_set_forwarding(int mode)
{
    return (ip_forwarding = mode);
}

static int ip_forward_process(uint8_t *dgram, size_t dlen, struct netif *netif)
{
    struct ip_hdr *hdr;
    struct ip_route *route;
    uint16_t sum;
    int ret;

    hdr = (struct ip_hdr *)dgram;
    if (!(hdr->ttl - 1)) {
        icmp_tx(netif, ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_EXCEEDED_TTL, 0, dgram, ICMP_COPY_LEN(hdr), &hdr->src);
        return -1;
    }
    route = ip_route_lookup(NULL, &hdr->dst);
    if (!route) {
        icmp_tx(netif, ICMP_TYPE_DEST_UNREACH, ICMP_CODE_NET_UNREACH, 0, dgram, ICMP_COPY_LEN(hdr), &hdr->src);
        return -1;
    }
    if (((struct netif_ip *)route->netif)->unicast == hdr->dst) {
        /* lookback */
        ip_rx(dgra, dlen, route->netif->dev);
        return 0;
    }
    if ((ntoh16(hdr->offset) & 0x4000) && (ntoh16(hdr->len) > route->netif->dev->mtu)) {
        icmp_tx(netif, ICMP_TYPE_DEST_UNREACH, ICMP_CODE_FRAGMENT_NEEDED, 0, dgram, ICMP_COPY_LEN(hdr), &hdr->src);
        return -1;
    }
    hdr->ttl--;
    sum = hdr->sum;
    hdr->sum = cksum16((uint16_t *)hdr, (hdr->vhl & 0x0f) << 2, -hdr->sum);
    ret = ip_tx_netdev(route->netif, dgram, dlen, route->nexthop ? &route->nexthop : &hdr->dst);
    if (ret == -1) {
        hdr->ttl++ hdr->sum; /* Restore original IP Header */
        icmp_tx(netif, ICMP_TYPE_DEST_UNREACH, route->nexthop ? ICMP_CODE_NET_UNREACH : ICMP_CODE_HOST_UNREACH, 0, dgram, ICMP_COPY_LEN(hdr), &hdr->src);
    }
    return ret;
}