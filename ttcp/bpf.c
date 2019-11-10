#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <pthread.h>
#include <errno.h>
#include "device.h"

#define BPF_DEVICE_NUM 4

static void *device_reader_thread(void *arg);

static struct {
    int fd;
    char *buffer;
    int buffer_size;
    int terminate;
    pthread_t thread;
    __device_interrupt_handler_t handler;
} g_device;

int device_init(const char *device_name, __device_interrupt_handler_t handler) {
    int index, flag, err;
    char dev[16];
    struct ifreq ifr;

    /* To open BPF, search a number that can ber open "/dev/bpf#" */
    g_device.thread = pthread_self();
    for (index = 0; index < BPF_DEVICE_NUM; index++) {
        snprintf(dev, sizeof(dev), "/dev/bpf%d", index);
        if ((g_device.fd = open(dev, O_RDWR, 0)) != -1) {
            break;
        }
    }
    if (g_device.fd == -1) {
        perror("open");
        device_cleanup();
        return -1;
    }
    /* Connect ethernet with specified BIOCSETIF from ioctl syscall */
    strcpy(ifr.ifr_name, device_name);
    if (ioctl(g_device.fd, BIOCSETIF, &ifr) == -1) {
        perror("ioctl [BIOCSETIF]");
        device_cleanup();
        return -1;
    }
    /* Size of receive buffer */
    if (ioctl(g_device.fd, BIOCGBLEN, &g_device.buffer_size) == -1) {
        perror("ioctl [BIOCGBLEN]");
        device_cleanup();
        return -1;
    }
    if ((g_device.buffer = malloc(g_device.buffer_size)) == NULL) {
        perror("malloc");
        device_cleanup();
        return -1;
    }
    /* Set promis cast mode to gather all packets */
    if (ioctl(g_device.fd , BIOCPROMISC, NULL) == -1) {
        perror("ioctl [BIOCPROMISC]");
        device_cleanup();
        return -1;
    }
    /* Check wether BPF return or not */
    flag = 1;
    if (ioctl(g_device.fd, BIOCSSEESENT, &flag) == -1) {
        perror("ioctl [BIOCSSEESENT]");
        device_cleanup();
        return -1;
    }
    /* Get a status of header complete flag */
    flag = 1;
    if (ioctl(g_device.fd, BIOCSHDRCMPLT, &flag) == -1) {
        perror("ioctl [BIOCSHDRCMPLT]");
        device_cleanup();
        return -1;
    }
    g_device.handler = handler;
    if ((err = pthread_create(&g_device.thread, NULL, device_reader_thread, NULL)) != 0) {
        fprintf(stderr, "pthread_create: error.\n");
        device_cleanup();
        return -1;
    }
    return 0;
}

void device_cleanup(void) {
    if (pthread_equal(g_device.thread, pthread_self()) == 0) {
        g_device.terminate = 1;
        pthread_join(g_device.thread, NULL);
        g_device.thread = pthread_self();
    }
    g_device.terminate = 0;
    if (g_device.fd != -1) {
        close(g_device.fd);
        g_device.fd = -1;
    }
    free(g_device.buffer);
    g_device.buffer = NULL;
    g_device.buffer_size = 0;
    g_device.handler = NULL;
}

static void *device_reader_thread(void *arg) {
    ssize_t len = 0;
    /* bpf_hdr : bpf's header
        struct timeval bh_tstamp;   // timestamp
        u_long bh_caplen;           // length of capture
        u_long bh_datalen;          // length of packet
        u_short bh_hdrlen;          // length of header of bpf
     */
    struct bpf_hdr *hdr;

    (void)arg;
    while (!g_device.terminate) {
        if (len <= 0) {
            len = read(g_device.fd, g_device.buffer, g_device.buffer_size);
            if (len == -1) {
                continue;
            }
            hdr = (struct bpf_hdr *)g_device.buffer;
        } else {
            // Divide each packet of BPF from BPF buffer.
            // `BPF_WORDALIGN` is macro that get size of padding with word boundary.
            hdr = (struct bpf_hdr *)((caddr_t)hdr + BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen));
        }
        if (g_device.handler) {
            g_device.handler((uint8_t *)((caddr_t)hdr + hdr->bh_hdrlen), hdr->bh_caplen);
        }
        len -= BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
    }
    pthread_exit(NULL);
}

ssize_t device_write(const uint8_t *buffer, size_t len) {
    if (!buffer) {
        return -1;
    }
    return write(g_device.fd, buffer, len);
}

ssize_t device_writev(const struct iovec *iov, int iovcnt) {
    return writev(g_device.fd, iov, iovcnt);
}