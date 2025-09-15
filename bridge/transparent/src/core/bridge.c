#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <linux/if_packet.h>

#include "llc.h"
#include "llc_snap.h"
#include "types.h"

int main()
{
    int sock_rx;
    struct sockaddr_ll saddr;
    uint8_t buffer[1600];

    if ((sock_rx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    {
        perror("socket");
        exit(1);
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = if_nametoindex("eth0")

    /*
    struct packet_mreq {
        int            mr_ifindex;
        unsigned short mr_type;
        unsigned short mr_alen;
        unsigned char mr_address[8];
    };
    */
}