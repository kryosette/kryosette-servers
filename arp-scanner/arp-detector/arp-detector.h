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

/*
    struct ether_arp {
        struct arphdr ea_hdr;      // ARP header (hardware and protocol type, opcode, etc.)
        u_char arp_sha[ETH_ALEN];  // Sender hardware address (MAC) - 6 bytes
        u_char arp_spa[4];         // Sender protocol address (IPv4) - 4 bytes
        u_char arp_tha[ETH_ALEN];  // Target hardware address (MAC) - 6 bytes
        u_char arp_tpa[4];         // Target protocol address (IPv4) - 4 bytes
*/
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