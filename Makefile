OBJS =	ttcp/arp.o \
		ttcp/bpf.o \
		ttcp/device.o \
		ttcp/ethernet.o \
		ttcp/ip.o \
		ttcp/pkt.o

TEST =	test/arp_test \
		test/bpf_test \
		test/ethernet_test \
		test/ip_test

CFLAGS := $(CFLAGS) -g -W -Wall -Who-unused-parameter -I .

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(TEST)

$(TEST): % : %.o $(OBJS)
		$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
		$(CC) $(CFLAGS) -c $< -o $@

clean:
		rm -rf $(OBJS) $(TEST) $(TEST:=.o)