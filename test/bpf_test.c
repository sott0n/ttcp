#include <stdio.h>
#include "bpf.h"

void dummy_function(uint8_t *buf, ssize_t len) {
    printf("input: %ld\n", len);
}

int main(int argc, char *argv[]) {
    if (device_init("en0", dummy_function) == -1) {
        device_cleanup();
        return -1;
    }
    sleep(10);
    device_cleanup();
    return 0;
}