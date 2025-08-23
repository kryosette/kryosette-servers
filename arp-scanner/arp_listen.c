#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>

struct arp_header
{
    unsigned short hw_type;    // ARPHRD_ETHER
    unsigned short proto_type; // ETH_P_IP
    unsigned char hw_len;      // 6 (для MAC)
    unsigned char proto_len;   // 4 (для IPv4)
    unsigned short opcode;     // ARPOP_REQUEST/ARPOP_REPLY
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
} __attribute__((packed));

void listen_arp_replies(const char *interface)
{
    int sockfd;
    unsigned char buffer[ETH_FRAME_LEN];

    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0)
    {
        perror("setsockopt");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Ожидание ARP-ответов на интерфейсе %s...\n", interface);

    while (1)
    {
        ssize_t length = recvfrom(sockfd, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
        if (length < 0)
        {
            perror("recvfrom");
            continue;
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;
        struct arp_header *arp = (struct arp_header *)(buffer + sizeof(struct ethhdr));

        /*
        The ntohs() function converts the unsigned short integer netshort from
        network byte order to host byte order.
        */
        if (ntohs(eth->h_proto) != ETH_P_ARP)
            continue;
        if (ntohs(arp->opcode) != ARPOP_REPLY)
            continue;

        time_t now;
        time(&now);
        struct tm *tm_info = localtime(&now);
        char time_str[20];

        /*
        size_t strftime(char s[restrict .max], size_t max,
                       const char *restrict format,
                       const struct tm *restrict tm);

        size_t strftime_l(char s[restrict .max], size_t max,
                       const char *restrict format,
                       const struct tm *restrict tm,
                       locale_t locale);
         */
        strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

        printf("[%s] Получен ARP-ответ от:\n", time_str);
        printf("  IP: %d.%d.%d.%d\n",
               arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3]);
        printf("  MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2],
               arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
    }

    close(sockfd);
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Использование: %s <интерфейс>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    listen_arp_replies(argv[1]);
    return 0;
}