#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <signal.h>

struct arphdr
{
    unsigned short int ar_hrd; /* Format of hardware address.  */
    unsigned short int ar_pro; /* Format of protocol address.  */
    unsigned char ar_hln;      /* Length of hardware address.  */
    unsigned char ar_pln;      /* Length of protocol address.  */
    unsigned short int ar_op;  /* ARP opcode (command).  */
    /* Hardware and protocol addresses. */
    unsigned char __ar_sha[6]; /* Sender hardware address.  */
    unsigned char __ar_sip[4]; /* Sender IP address.  */
    unsigned char __ar_tha[6]; /* Target hardware address.  */
    unsigned char __ar_tip[4]; /* Target IP address.  */
};

#define ARPOP_REPLY 2

typedef struct
{
    uint32_t ip;
    unsigned char mac[6];
} trusted_pair_t;

trusted_pair_t *trusted_list;
size_t num_trusted = 0;

int is_arp_poisoning(const struct arphdr *arp_hdr, const unsigned char *src_mac)
{
    if (ntohs(arp_hdr->ar_op) != ARPOP_REPLY)
    {
        return 0;
    }

    for (size_t i = 0; i < num_trusted; i++)
    {
        if (memcmp(arp_hdr->__ar_sip, &trusted_list[i].ip, sizeof(uint32_t)) == 0)
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
    num_trusted = 2;
    trusted_list = malloc(num_trusted * sizeof(trusted_pair_t));

    trusted_list[0].ip = inet_addr("192.168.1.1");
    memcpy(trusted_list[0].mac, (unsigned char[]){0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, 6);

    trusted_list[1].ip = inet_addr("192.168.1.100");
    memcpy(trusted_list[1].mac, (unsigned char[]){0x08, 0x00, 0x27, 0x96, 0x20, 0x39}, 6);

    int sockfd;
    unsigned char buffer[ETH_FRAME_LEN];
    struct sockaddr_ll saddr;
    socklen_t saddr_len = sizeof(saddr);

    // Создаём RAW-сокет для приёма всех ARP-пакетов
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0)
    {
        perror("socket");
        free(trusted_list);
        exit(EXIT_FAILURE);
    }

    printf("[+] ARP Guardian started. Monitoring for ARP spoofing...\n");

    while (1)
    {
        // Читаем приходящий пакет
        int recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&saddr, &saddr_len);
        if (recv_len < 0)
        {
            perror("recvfrom");
            close(sockfd);
            free(trusted_list);
            exit(EXIT_FAILURE);
        }

        // Проверяем, что пакет достаточно большой для Ethernet + ARP
        if (recv_len < (int)(sizeof(struct ethhdr) + sizeof(struct arphdr)))
        {
            continue;
        }

        // Парсим Ethernet-заголовок
        struct ethhdr *eth_hdr = (struct ethhdr *)buffer;
        // Парсим ARP-заголовок (после Ethernet-заголовка)
        struct arphdr *arp_hdr = (struct arphdr *)(buffer + sizeof(struct ethhdr));

        // Проверяем пакет на атаку
        if (is_arp_poisoning(arp_hdr, eth_hdr->h_source))
        {
            printf("[!] Taking action...\n");
            // Здесь можно добавить реакцию
        }
    }

    close(sockfd);
    free(trusted_list);
    return 0;
}