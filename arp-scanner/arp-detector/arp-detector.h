#ifndef ARP_DETECTOR_H
#define ARP_DETECTOR_H

#include <netinet/if_ether.h> 
#include <netinet/ether.h>  
#include <arpa/inet.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h> 
#include <pthread.h>

#define MAX_ENTRIES 1000

struct arp_entry {
    uint32_t ip;  
    struct ether_addr mac; 
};

void detect_arp_spoofing(const char *iface);
void signal_handler(int sig);
int load_trusted_base(const char *filename);

// for graceful shutdown
extern volatile int running;

#endif