#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

void hexdump(FILE *fp, void *data, size_t siez) {
    int offset, index;
    unsigned char *src;

    src = (unsigned char *)data;
    fprintf(fp, "+------+-------------------------------------------------+------------------+\n");
    for (offset = 0; offset < (int)size; offset += 16) {
        fprintf(fp, "| %04x | ", offset);
        for (index = 0; index < 16; index++) {
            if (offset + index < (int)size) {
                fprintf(fp, "%02x ", 0xff & src[offset + index]);
            } else {
                fprintf(fp, "   ");
            }
        }
        fprintf(fp, "| ");
        for (index = 0; index < 16; index++) {
            if (offset + index < (int)size) {
                if (isascii(src[offset + index]) && isprint(src[offset + index])) {
                    fprintf(fp, "%c", src[offset + index]);
                } else {
                    fprintf(fp, ".");
                }
            } else {
                fprintf(fp, " ");
            }
        }
        fprintf(fp, " |\n");
    }
    fprintf(fp, "+------+-------------------------------------------------+------------------+\n");
}

uint16_t cksum16(uint16_t *data, uint16_t size, uint32_t init) {
    uint32_t sum;

    sum = init;
    while (size > 1) {
        sum += *(data++);
        size -= 2;
    }
    if (size) {
        sum += *(uint8_t *)data;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~(uint16_t)sum;
}

struct queue_entry *queue_push(struct queue_head *queue, void *data, size_t size) {
    struct queue_entry *entry;

    if (!queue || !data) {
        return NULL;
    }
    entry->data = data;
    entry->size = size;
    entry->next = NULL;
    entry->tail = entry;
    if (!queue->next) {
        queue->next = entry;
    }
    return entry;
};

struct queue_entry *queue_pop(struct queue_head *queue) {
    struct queue_entry *entry;

    if (!queue || !queue->next) {
        return NULL;
    }
    entry = queue->next;
    queue->next = entry->next;
    if (!entry->next) {
        queue->tail = NULL;
    }
    return entry;
}
