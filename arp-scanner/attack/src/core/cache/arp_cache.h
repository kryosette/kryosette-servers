#ifndef ARP_CACHE_H
#define ARP_CACHE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>

/*
    Cache entry states
*/
typedef enum {
    ARP_CACHE_INCOMPLETE = 0;
    ARP_CACHE_REACHABLE = 1;
    ARP_CACHE_STALE = 2;
    ARP_CACHE_PERMANENT = 3;
} arp_cache_state_t;

typedef struct arp_cache_entry {
    uint8_t ip[4];
    uint8_t mac[6];
    struct timeval timestamp;
    int state;
    struct arp_cache_entry *next;
} arp_cache_entry_t;

/*
    Cache config
*/
typedef struct {
    size_t max_size;
    time_t default_timeout;
    time_t cleanup_interval;
    int enable_stats;
} arp_cache_config_t;

// === INTERFACE ARP CACHE ===

// Init/clean
int arp_cache_init(const arp_cache_config_t *config)
void arp_cache_destroy(void);

// Base functions
void arp_cache_add(uint8_t *ip, uint8_t *mac, int state);
uint8_t* arp_cache_lookup(uint8_t *ip); 
void arp_cache_remove(uint32_t *ip);
void arp_cache_cleanup(void); 

// Utils
void arp_cache_print(void);
size_t arp_cache_size(void);

#endif