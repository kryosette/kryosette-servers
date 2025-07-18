#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

// #ifndef ARP_H_INCLUDED
// #define ARP_H_INCLUDED

// struct arp_header
// {
//     unsigned short int hw_type;
//     unsigned short int pro_type;
//     unsigned char hw_len;
//     unsigned char pro_len;
//     unsigned short int op;
//     unsigned char sha[6];
//     unsigned char spa[4];
//     unsigned char tha[5];
//     unsigned char tpa[4];
// } __attribute__((__packed__));

// #endif
