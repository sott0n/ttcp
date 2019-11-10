#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include "ethernet.h"
#include "device.h"

#define ETHERNET_HDR_SIZE 14
#define ETHERNET_FRAME_SIZE_MIN 60
#define ETHERNET_FRAME_SIZE_MAX 1500
#define ETHERNET_PAYLOAD_SIZE_MIN ETHERNET_FRAME_SIZE_MIN-ETHERNET_HDR_SIZE
#define ETHERNET_PAYLOAD_SIZE_MAX ETHERNET_FRAME_SIZE_MAX-ETHERNET_HDR_SIZE
#define ETHERNET_HANDLER_TABLE_SIZE 16

struct ethernet_hdr {
    // destination Mac address
    ethernet_addr_t dst;
    // Source Mac address
    ethernet_addr_t src;
    uint16_t type;
} __attribute__((packed));

const ethernet_addr_t ETHERNET_ADDR_BCAST = {"\xff\xff\xff\xff\xff\xff"};

static struct {
    ethernet_addr_t addr;
    struct {
        uint16_t type;
        __ethernet_handler_t handler;
    } handler_table[ETHERNET_HANDLER_TABLE_SIZE];
    int handler_num;
} g_ethernet;

void ethernet_init(void) {
    int index;

    memset(&g_ethernet.addr.addr, 0x00, ETHERNET_ADDR_LEN);
    for (index = 0; index < ETHERNET_HANDLER_TABLE_SIZE; index++) {
        g_ethernet.handler_table[index].type = 0;
        g_ethernet.handler_table[index].handler = NULL;
    }
    g_ethernet.handler_num = 0;
}

ethernet_addr_t *ethernet_get_addr(void) {
    return &g_ethernet.addr;
}

int ethernet_set_addr(const char *addr) {
    return ethernet_addr_pton(addr, &g_ethernet.addr);
}

int ethernet_add_handler(uint16_t type, __ethernet_handler_t handler) {
    if (g_ethernet.handler_num >= ETHERNET_HANDLER_TABLE_SIZE) {
        return -1;
    }
    g_ethernet.handler_table[g_ethernet.handler_num].type = htons(type);
    g_ethernet.handler_table[g_ethernet.handler_num].handler = handler;
    g_ethernet.handler_num++;
    return 0;
}

void ethernet_recv(uint8_t *frame, size_t flen) {
    struct ethernet_hdr *hdr;
    int offset;
    uint8_t *payload;
    size_t plen;

    if (flen < (ssize_t)sizeof(struct ethernet_hdr)) {
        return;
    }
    hdr = (struct ethernet_hdr *)frame;
    if (ethernet_addr_cmp(&g_ethernet.addr, &hdr->dst) != 0) {
        if (ethernet_addr_cmp(&ETHERNET_ADDR_BCAST, &hdr->dst) != 0) {
            return;
        }
    }
    payload = (uint8_t *)(hdr + 1);
    plen = flen - sizeof(struct ethernet_hdr);
    for (offset = 0; offset < g_ethernet.handler_num; offset++) {
        if (g_ethernet.handler_table[offset].type == hdr->type) {
            g_ethernet.handler_table[offset].handler(payload, plen, &hdr->src, &hdr->dst);
            break;
        }
    }
}

ssize_t ethernet_send(uint16_t type, const uint8_t *payload, size_t plen, const ethernet_addr_t *dst) {
    uint8_t frame[ETHERNET_FRAME_SIZE_MAX];
    struct ethernet_hdr *hdr;
    size_t flen;

    if (!payload || plen > ETHERNET_FRAME_SIZE_MAX || !dst) {
        return -1;
    }
    memset(&frame, 0x00, sizeof(frame));
    hdr = (struct ethernet_hdr *)&frame;
    memcpy(hdr->dst.addr, dst->addr, ETHERNET_ADDR_LEN);
    memcpy(hdr->src.addr, g_ethernet.addr.addr, ETHERNET_ADDR_LEN);
    hdr->type = htons(type);
    memcpy(hdr + 1, payload, plen);
    flen = sizeof(struct ethernet_hdr) + (plen < ETHERNET_PAYLOAD_SIZE_MIN ? ETHERNET_PAYLOAD_SIZE_MIN : plen);
    return device_write(frame, flen) == (ssize_t)flen ? (ssize_t)plen : -1;
}

int ethernet_addr_pton(const char *p, ethernet_addr_t *n) {
    int index;
    char *ep;
    long val;

    if (!p || !n) {
        return -1;
    }
    for (index = 0; index < ETHERNET_ADDR_LEN; index++) {
        val = strtol(p, &ep, 16);
        if (ep == p || val < 0 || val > 0xff || (index < ETHERNET_ADDR_LEN - 1 && *ep != ':')) {
            break;
        }
        n->addr[index] = (uint8_t)val;
        p = ep + 1;
    }
    if (index != ETHERNET_ADDR_LEN || *ep != '\0') {
        return -1;
    }
    return 0;
}

char *ethernet_addr_ntop(const ethernet_addr_t *n, char *p, size_t size) {
    if (!n || !p || size < ETHERNET_ADDR_STR_LEN + 1) {
        return NULL;
    }
    snprintf(p, size, "%02x:%02x:%02x:%02x:%02x:%02x",
        n->addr[0], n->addr[1], n->addr[2], n->addr[3], n->addr[4], n->addr[5]);
    return p;
}

int ethernet_addr_cmp(const ethernet_addr_t *a, const ethernet_addr_t *b) {
    return memcmp(&a->addr, &b->addr, ETHERNET_ADDR_LEN);
}

int ethernet_addr_isself(const ethernet_addr_t *addr) {
    return (ethernet_addr_cmp(addr, &g_ethernet.addr) == 0) ? 1 : 0;
}