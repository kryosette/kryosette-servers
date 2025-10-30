#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>

int create_raw_socket(const char *interface)
{
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        perror("socket");
        return -1;
    }

    struct sockaddr_ll saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = if_nametoindex(interface);

    if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
    {
        perror("bind");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

void packet_handler(unsigned char *buffer, int length)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;

    printf("Ethernet Header:\n");
    printf("  Destination: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("  Source: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("  Protocol: 0x%04x\n", ntohs(eth->h_proto));

    if (ntohs(eth->h_proto) == ETH_P_IP)
    {
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        printf("IP Packet: %d.%d.%d.%d -> %d.%d.%d.%d\n",
               (ip->saddr >> 0) & 0xFF, (ip->saddr >> 8) & 0xFF,
               (ip->saddr >> 16) & 0xFF, (ip->saddr >> 24) & 0xFF,
               (ip->daddr >> 0) & 0xFF, (ip->daddr >> 8) & 0xFF,
               (ip->daddr >> 16) & 0xFF, (ip->daddr >> 24) & 0xFF);

        if (ip->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
            printf("TCP Ports: %d -> %d\n", ntohs(tcp->source), ntohs(tcp->dest));

            if (ntohs(tcp->dest) == 80 || ntohs(tcp->source) == 80)
            {
                printf("=== HTTP TRAFFIC DETECTED ===\n");

                int ip_header_len = ip->ihl * 4;
                int tcp_header_len = tcp->doff * 4;
                unsigned char *payload = buffer + sizeof(struct ethhdr) + ip_header_len + tcp_header_len;
                int payload_len = length - (sizeof(struct ethhdr) + ip_header_len + tcp_header_len);

                if (payload_len > 0)
                {
                    printf("Payload (%d bytes):\n", payload_len);
                    for (int i = 0; i < payload_len && i < 100; i++)
                    {
                        printf("%c", isprint(payload[i]) ? payload[i] : '.');
                    }
                    printf("\n");
                }
            }
        }
    }
    printf("---\n");
}

int main()
{
    int sockfd = create_raw_socket("br0");
    if (sockfd < 0)
    {
        return 1;
    }

    unsigned char buffer[65536];

    while (1)
    {
        int packet_len = recv(sockfd, buffer, sizeof(buffer), 0);
        if (packet_len < 0)
        {
            perror("recv");
            continue;
        }

        packet_handler(buffer, packet_len);
    }

    close(sockfd);
    return 0;
}