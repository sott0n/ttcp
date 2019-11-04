#ifndef _IP_H_
#define _IP_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#define IP_PROTOCOL_ICMP 2
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17
#define IP_PROTOCOL_RAW 255

#define IP_ADDR_LEN 4
#define IP_ADDR_STR_LEN 15

typedef uint32_t ip_addr_t;

typedef void (*__ip_handler_t)(uint8_t *, ssize_t);

extern ip_addr_t * ip_get_addr(void);
extern int ip_set_addr(const char *addr);
extern int ip_add_handler(uint16_t type, __ip_handler_t handler);
extern void ip_recv(uint8_t *buf, ssize_t len, int bcast);
extern ssize_t ip_send(const uint8_t *buf, size_t len, const ip_addr_t *addr);
extern int ip_addr_pton(const char *p, ip_addr_t *n);
extern char *ip_addr_ntop(const ip_addr_t *n, char *p, size_t size);
extern int ip_addr_isself(const ip_addr_t *addr);

#endif