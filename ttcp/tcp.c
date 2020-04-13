#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include "util.h"
#include "tcp.h"

#define TCP_CB_TABLE_SIZE 128
#define TCP_SOURCE_PORT_MIN 49152
#define TCP_SOURCE_PORT_MAX 65535

#define TCP_CB_STATE_CLOSED      0
#define TCP_CB_STATE_LISTEN      1
#define TCP_CB_STATE_SYN_SENT    2
#define TCP_CB_STATE_SYN_RCVD    3
#define TCP_CB_STATE_ESTABLISHED 4
#define TCP_CB_STATE_FIN_WAIT1   5
#define TCP_CB_STATE_FIN_WAIT2   6
#define TCP_CB_STATE_CLOSING     7
#define TCP_CB_STATE_TIME_WAIT   8
#define TCP_CB_STATE_CLOSE_WAIT  9
#define TCP_CB_STATE_LAST_ATK    10

#define TCP_FLG_FIN 0x01    // no more data from sender
#define TCP_FLG_SYN 0x02    // Synchronize sequence numbers
#define TCP_FLG_RST 0x04    // Reset the connection
#define TCP_FLG_PSH 0x08    // Push Function
#define TCP_FLG_ACK 0x10    // Acknowledgement field significant
#define TCP_FLG_URG 0x20    // Urgent Pointer field significant

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y))

struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t  off;
    uint8_t  flg;
    uint16_t win;
    uint16_t sum;
    uint16_t urg;
};

struct tcp_txq_entry {
    struct tcp_hdr *segment;
    uint16_t len;
    struct timeval timestamp;
    struct tcp_txq_entry *next;
};

struct tcp_txq_head {
    struct tcp_txq_entry *head;
    struct tcp_txq_entry *tail;
};

struct tcp_cb {
    uint8_t used;
    uint8_t state;
    struct netif *iface;
    uint16_t port;
    struct {
        ip_addr_t addr;
        uint16_t port;
    } peer;
    struct {
        uint32_t nxt;
        uint32_t una;
        uint16_t up;
        uint32_t wl1;
        uint32_t wl2;
        uint16_t wnd;
    } snd;
    uint32_t iss;
    struct {
        uint32_t nxt;
        uint16_t up;
        uint16_t wnd;
    } rcv;
    uint32_t irs;
    struct tcp_txq_head txq;
    uint8_t window[65535];
    struct tcp_cb *parent;
    struct queue_head backlog;
    pthread_cond_t cond;
};

#define TCP_CB_LISTENER_SIZE 128

#define TCP_CB_STATE_RX_ISREADY(x) (x->state == TCP_CB_STATE_ESTABLISHED || x->state == TCP_CB_STATE_FIN_WAIT1 || x->state == TCP_CB_STATE_FIN_WAIT2)
#define TCP_CB_STATE_TX_ISREADY(x) (x->state == TCP_CB_STATE_ESTABLISHED || x->state == TCP_CB_STATE_CLOSE_WAIT)

#define TCP_SOCKET_ISINVALID(x) (x < 0 || x >= TCP_CB_TABLE_SIZE)

static pthread_t timer_thread;
struct tcp_cb cb_table[TCP_CB_TABLE_SIZE];
pthread_mutex_t mutex;

static int tcp_txq_add(struct tcp_cb *cb, struct tcp_hdr *hdr, size_t len)
{
    struct tcp_txq_entry *txq;

    txq = malloc(sizeof(struct tcp_txq_entry));
    if (!txq) {
        return -1;
    }
    txq->segment = malloc(len);
    if (!txq->segment) {
        free(txq);
        return -1;
    }
    memcpy(txq->segment, hdr, len);
    gettimeofday(&txq->timestamp, NULL);
    txq->next = NULL;

    // set txq to next of tail entry
    if (cb->txq.head == NULL) {
        cb->txq.head = txq;
    } else {
        cb->txq.tail->next = txq;
    }
    // update tail entry
    cb->txq.tail = txq;

    retunr 0;
}

static ssize_t tcp_tx(struct tcp_cb *cb, uint32_t seq, uint32_t ack, uint8_t flg, uint8_t *buf, size_t len)
{
    uint8_t segment[1500];
    struct tcp_hdr *hdr;
    ip_addr_t self, peer;
    uint32_t pseudo = 0;

    memset(&segment, 0, sizeof(segment));
    hdr = (struct tcp_hdr *)segment;
    hdr->src = cb->port;
    hdr->dst = cb->peer.port;
    hdr->seq = hton32(seq);
    hdr->ack = hton32(ack);
    hdr->off = (sizeof(struct tcp_hdr) >> 2) << 4;
    hdr->flg = flg;
    hdr->win = hton16(cb->rcv.wnd);
    hdr->sum = 0;
    hdr->urg = 0;
    memcpy(hdr + 1, buf, len);
    self = ((struct netif_ip *)cb->iface)->unicast;
    peer = cb->peer.addr;
    pseudo += (self >> 16) & 0xffff;
    pseudo += self & 0xffff;
    pseudo += (peer >> 16) & 0xffff;
    pseudo += peer & 0xffff;
    pseudo += hton16((uint16_t)IP_PROTOCOL_TCP);
    pseudo += hton16(sizeof(struct tcp_hdr) + len);
    hdr->sum = cksum16((uint16_t *)hdr, sizeof(struct tcp_hdr) + len, pseudo);
    ip_tx(cb->iface, IP_PROTOCOL_TCP, (uint8_t *)hdr, sizeof(struct tcp_hdr) + len, &peer);
    tcp_txq_add(cb, hdr, sizeof(struct tcp_hdr) + len);
    return len;
}

static void *tcp_timer_thread(void *arg)
{
    struct timeval timestamp;
    struct tcp_cb *cb;
    struct tcp_txq_entry *txq, *prev, *tmp;
    ip_addr_t peer;

    while (1) {
        gettimeofday(&timestamp, NULL);
        pthread_mutex_lock(&mutex);
        for (cb = cb_table; cb < array_tailof(cb_table); cb++) {
            prev = NULL;
            txq = cb->txq.head;
            while (txq) {
                if (ntoh32(txq->segment->seq) >= cb->snd.una) {
                    if (timestamp.tv_sec - txq->timestamp.tv_sec > 3) {
                        peer = cb->peer.addr;
                        ip_tx(cb->iface, IP_PROTOCOL_TCP, (uint8_t *)txq->segment, txq->len, &peer);
                        txq->timestamp = timestamp;
                    }

                    // update privious tcp_txq_entry
                    prev = txq;
                    txq = txq->next;
                } else {
                    // remove tcp_txq_entry from list
                    // do not change prev, just update txq by txq->next,
                    // and free txq and txq->segment,
                    // and udpate cb->txq.[head|tail] if needed

                    // swap tail tcp_txq_entry
                    if (!txq->next) {
                        // txq is tail entry
                        cb->txq.tail = prev;
                    }
                    // swap previous tcp_txq_entry
                    if (prev) {
                        prev->next = txq->next;
                    } else {
                        cb->txq.head = txq->next;
                    }

                    // free tcp_txq_entry
                    tmp = txq->entry;
                    free(txq->segment);
                    free(txq);
                    // check next entry
                    txq = tmp;
                }
            }
        }
        pthread_mutex_unlock(&mutex);
        usleep(100000);
    }
    return NULL;
}

static void tcp_incoming_event(struct tcp_cb *cb, struct tcp_hdr *hdr, size_t len)
{
    uint32_t seq, ack;
    size_t hlen, plen;

    hlen = ((hdr->off >> 4) << 2);
    plen = len - hlen;
    switch(cb->state) {
    case TCP_CB_STATE_CLOSED:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
            return;
        }
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
            seq = ntoh32(hdr->ack);
            ack = 0;
        } else {
            seq = 0;
            ack = ntoh32(hdr->seq);
            if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
                ack++;
            }
            if (plen) {
                ack += plen;
            }
            if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
                ack++;
            }
        }
        tcp_tx(cb, seq, ack, TCP_FLG_RST, NULL, 0);
        return;
    case TCP_CB_STATE_LISTEN:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
            return;
        }
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
            seq = ntoh32(hdr->ack);
            ack = 0;
            tcp_tx(cb, seq, ack, TCP_FLG_RST, NULL, 0);
            return;
        }
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
            cb->rcv.nxt = ntoh32(hdr->seq) + 1;
            cb->irx = ntoh32(hdr->seq);
            cb->iss = (uint32_t)random();
            seq = cb->iss;
            ack = cb->rcv.nxt;
            tcp_tx(cb, seq, ack, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
            cb->snd.nxt = cb->iss + 1;
            cb->snd.una = cb->iss;
            cb->state = TCP_CB_STATE_SYN_RCVD;
        }
        return;
    case TCP_CB_STATE_SYN_SENT:
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
            if (ntoh32(hdr->ack) <= cb->iss || ntoh32(hdr->ack) > cb->snd.nxt) {
                if (!TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
                    seq = ntoh32(hdr->ack);
                    ack = 0;
                    tcp_tx(cb, seq, ack, TCP_FLG_RST, NULL, 0);
                }
                return;
            }
        }
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST)) {
            if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
                // TCB close
            }
            return;
        }
        if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
            cb->rcv.nxt = ntoh32(hdr->seq) + 1;
            cb->irs = ntoh32(hdr->seq);
            if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
                cb->snd.una = ntoh32(hdr->ack);
                // delete TX queue
                if (cb->snd.una > cb->iss) {
                    cb->state = TCP_CB_STATE_ESTABLISHED;
                    seq = cb->snd.nxt;
                    ack = cb->rcv.nxt;
                    tcp_tx(cb, seq, ack, TCP_FLG_ACK, NULL, 0);
                    pthread_cond_signal(&cb->cond);
                }
                return;
            }
            seq = cb->iss;
            ack = cb->rcv.nxt;
            tcp_tx(cb, seq, ack, TCP_FLG_ACK, NULL, 0);
        }
        return;
    default:
        break;
    }
    if (ntoh32(hdr->seq) != cb->rcv.nxt) {
        // TODO
        return;
    }
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_RST | TCP_FLG_SYN)) {
        // TODO
        return;
    }
    if (!TCP_FLG_ISSET(hdr->flg, TCP_FLG_ACK)) {
        // TODO
        return;
    }
    switch (cb->state) {
    case TCP_CB_STATE_SYN_RCVD:
        if (cb->snd.una <= ntoh32(hdr->ack) && ntoh32(hdr->ack) <= cb->snd.nxt) {
            cb->state = TCP_CB_STATE_ESTABLISHED;
            queue_push(&cb->parent->backlog, cb, sizeof(*cb));
            pthread_cond_signal(&cb->parent->cond);
        } else {
            tcp_tx(cb, ntoh32(hdr->ack), 0, TCP_FLG_RST, NULL, 0);
            break;
        }
    case TCP_CB_STATE_ESTABLISHED:
    case TCP_CB_STATE_FIN_WAIT1:
    case TCP_CB_STATE_FIN_WAIT2:
    case TCP_CB_STATE_CLOSE_WAIT:
    case TCP_CB_STATE_CLOSING:
        if (cb->snd.una < ntoh32(hdr->ack) && ntoh32(hdr->ack) <= cb->snd.nxt) {
            cb->snd.una = ntoh32(hdr->ack);
        } else if (ntoh32(hdr->ack) > cb->snd.nxt) {
            tcp_tx(cb, cb->snd.nxt, cb->rcv.nxt, TCP_FLG_ACK, NULL, 0);
            return;
        }
        // send window update
        if (cb->state == TCP_CB_STATE_FIN_WAIT1) {
            if (ntoh32(hdr->ack) == cb->snd.nxt) {
                cb->state = TCP_CB_STATE_FIN_WAIT2;
            }
        } else if (cb->state == TCP_CB_STATE_CLOSING) {
            if (ntoh32(hdr->ack) == cb->snd.nxt) {
                cb->state = TCP_CB_STATE_TIME_WAIT;
                pthread_cond_signal(&cb->cond);
            }
            return;
        }
        break;
    case TCP_CB_STATE_LAST_ATK:
        cb->state = TCP_CB_STATE_CLOSED;
        return;
    }
    if (plen) {
        switch(cb->state) {
        case TCP_CB_STATE_ESTABLISHED:
        case TCP_CB_STATE_FIN_WAIT1:
        case TCP_CB_STATE_FIN_WAIT2:
            memcpy(cb->window + (sizeof(cb->window) - cb->rcv.wnd), (uint8_t *)hdr + hlen, plen);
            cb->rcv.nxt = ntoh32(hdr->seq) + plen;
            cb->rxv.wnd -= plen;
            seq = cb->snd.nxt;
            ack = cb->rcv.nxt;
            tcp_tx(cb, seq, ack, TCP_FLG_ACK, NULL, 0);
            pthread_cond_signal(&cb->cond);
            break;
        default:
            break;
        }
    }
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
        cb->rcv.nxt++;
        tcp_tx(cb, cb->snd.nxt, cb->rcv.nxt, TCP_FLG_ACK, NULL, 0);
        switch(cb->state) {
        case TCP_CB_STATE_SYN_RCVD:
        case TCP_CB_STATE_ESTABLISHED:
            cb->state = TCP_CB_STATE_CLOSE_WAIT;
            pthread_cond_signal(&cb->cond);
            break;
        case TCP_CB_STATE_FIN_WAIT1:
            cb->state = TCP_CB_STATE_FIN_WAIT2;
            break;
        case TCP_CB_STATE_FIN_WAIT2:
            cb->state = TCP_CB_STATE_TIME_WAIT;
            pthread_cond_signal(&cb->cond);
            break;
        default:
            break;
        }
        return;
    }
    return;
}

static void tcp_rx(uint8_t *segment, size_t len, ip_addr_t *src, ip_addr_t *dst, struct netif *iface)
{
    struct tcp_hdr *hdr;
    uint32_t pseudo = 0;
    struct tcp_cb *cb, *fcb = NULL, *lcb = NULL;

    if (*dst != ((struct netif *)iface)->unicast) {
        return;
    }
    if (len < sizeof(struct tcp_hdr)) {
        return;
    }
    hdr = (struct tcp_hdr *)segment;
    pseudo += *src >> 16;
    pseudo += *src & 0xffff;
    pseudo += *dst >> 16;
    pseudo += *dst & 0xffff;
    pseudo += hton16((uint16_t)IP_PROTOCOL_TCP);
    pseudo += hton16(len);
    if (cksum16((uint16_t *)hdr, len, pseudo) != 0) {
        fprintf(stderr, "tcp checksum error \n");
        return;
    }
    pthread_mutex_lock(&mutex);
    for (cb = cb_table; cb < array_tailof(cb_table); cb++) {
        if (!cb->used) {
            if (!fcb) {
                fcb = cb;
            }
        }
        else if ((!cb->iface || cb->iface == iface) && cb->port == hdr->dst) {
            if (cb->peer.addr == *src && cb->peer.port == hdr->src) {
                break;
            }
            if (cb->state == TCP_CB_STATE_LISTEN && !lcb) {
                lcb = cb;
            }
        }
    }
    if (cb == array_tailof(cb_table)) {
        if (!lcb || !fcb || !TCP_FLG_IS(hdr->flg, TCP_FLG_SYN)) {
            // send RST
            pthread_mutex_unlock(&mutex);
            return;
        }
        cb = fcb;
        cb->used = 1;
        cb->state = lcb->state;
        cb->iface = iface;
        cb->port = lcb->port;
        cb->peer.addr = *src;
        cb->peer.port = hdr->src;
        cb->rcv.wnd = sizeof(cb->window);
        cb->parent = lcb;
    }
    tcp_incoming_event(cb, hdr, len);
    pthread_mutex_unlock(&mutex);
    return;
}

int tcp_api_open(void)
{
    struct tcp_cb *cb;

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