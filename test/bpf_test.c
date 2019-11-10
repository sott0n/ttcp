#include <stdio.h>
#include "bpf.h"
#include "util.h"

void interrupt_handler(uint8_t *buf, size_t len) {
    printf("input: %ld octets\n", len);
    hexdump(stderr, buf, len);
}

int main(int argc, char *argv[]) {
    sigset_t sigset;
    int signo;

    if (argc != 2) {
        fprintf(stderr, "usage: %s device-name\n", argv[0]);
        return -1;
    }
    sigemtyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigprocmask(SIG_BLOCK, &sigset, NULL);
    if (device_init(argv[1], interrupt_handler) == -1) {
        return -1;
    }
    sigwait(&sigset, &signo);
    device_cleanup();
    return 0;
}