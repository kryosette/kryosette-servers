#include "white_list.h"

int is_arp_poisoning(const struct arphdr *arp_hdr, const unsigned char *src_mac)
{
    if (ntohs(arp_hdr->ar_op) != ARPOP_REPLY)
    {
        return 0;
    }

    for (size_t i = 0; i < NUM_TRUSTED; i++)
    {
        if (memcmp(&arp_hdr->ar_sip, &trusted_list[i].ip, sizeof(uint32_t)) == 0)
        {
            if (memcmp(src_mac, trusted_list[i].mac, 6) != 0)
            {
                printf("[!] ALERT: ARP Poisoning detected!\n");
                printf("    For IP: %s\n", inet_ntoa(*(struct in_addr *)&trusted_list[i].ip));
                printf("    Expected MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
                       trusted_list[i].mac[0], trusted_list[i].mac[1],
                       trusted_list[i].mac[2], trusted_list[i].mac[3],
                       trusted_list[i].mac[4], trusted_list[i].mac[5]);
                printf("    Received MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
                       src_mac[0], src_mac[1], src_mac[2],
                       src_mac[3], src_mac[4], src_mac[5]);
                return 1;
            }
        }
    }
    return 0;
}

int main()
{
    int sockfd;
    unsigned char buffer[ETH_FRAME_LEN];
    struct sockaddr_ll saddr;
    socklen_t saddr_len = sizeof(saddr);

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    printf("[+] ARP Guardian started. Monitoring for ARP spoofing...\n");

    while (1)
    {
        int recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&saddr, &saddr_len);
        if (recv_len < 0)
        {
            perror("recvfrom");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        if (recv_len < (int)(sizeof(struct ethhdr) + sizeof(struct arphdr)))
        {
            continue;
        }

        struct ethhdr *eth_hdr = (struct ethhdr *)buffer;
        struct arphdr *arp_hdr = (struct arphdr *)(buffer + sizeof(struct ethhdr));

        if (is_arp_poisoning(arp_hdr, eth_hdr->h_source))
        {
            printf("[!] Taking action...\n");
        }
    }

    close(sockfd);
    return 0;
}