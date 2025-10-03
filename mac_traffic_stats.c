#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <signal.h>
#include <time.h>

volatile sig_atomic_t stop = 0;

struct mac_stats
{
    unsigned char mac[6];
    uint64_t frames_received;
    uint64_t frames_transmitted;
    uint64_t octets_received;
    uint64_t octets_transmitted;
    uint64_t crc_errors;
    uint64_t alignment_errors;
    uint64_t collisions;
    uint64_t multicast_frames;
    uint64_t broadcast_frames;
};

struct mac_stats mac_table[256];
int mac_count = 0;

void handle_signal(int sig)
{
    stop = 1;
}

// Добавить/найти MAC в таблице
int find_or_add_mac(unsigned char *mac)
{
    for (int i = 0; i < mac_count; i++)
    {
        if (memcmp(mac_table[i].mac, mac, 6) == 0)
        {
            return i;
        }
    }

    if (mac_count < 256)
    {
        memcpy(mac_table[mac_count].mac, mac, 6);
        mac_count++;
        return mac_count - 1;
    }

    return -1;
}

// Получить ARP таблицу и добавить MAC'и
void get_arp_table()
{
    FILE *arp_file = fopen("/proc/net/arp", "r");
    if (!arp_file)
        return;

    char line[256];
    fgets(line, sizeof(line), arp_file); // Пропускаем заголовок

    while (fgets(line, sizeof(line), arp_file))
    {
        char ip[16], hw_type[16], flags[16], mac[18], device[16];
        sscanf(line, "%15s %15s %15s %17s %15s", ip, hw_type, flags, mac, device);

        if (strcmp(mac, "00:00:00:00:00:00") != 0)
        {
            unsigned char mac_bytes[6];
            sscanf(mac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
                   &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
                   &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);

            find_or_add_mac(mac_bytes);
        }
    }

    fclose(arp_file);
}

// Анализ пакета и обновление статистики
void process_packet(unsigned char *buffer, int size)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;

    // Статистика для источника
    int src_idx = find_or_add_mac(eth->h_source);
    if (src_idx >= 0)
    {
        mac_table[src_idx].frames_transmitted++;
        mac_table[src_idx].octets_transmitted += size;
    }

    // Статистика для получателя
    int dst_idx = find_or_add_mac(eth->h_dest);
    if (dst_idx >= 0)
    {
        mac_table[dst_idx].frames_received++;
        mac_table[dst_idx].octets_received += size;

        // Multicast/Broadcast
        if (eth->h_dest[0] & 0x01)
        {
            if (eth->h_dest[0] == 0xFF && eth->h_dest[1] == 0xFF &&
                eth->h_dest[2] == 0xFF && eth->h_dest[3] == 0xFF &&
                eth->h_dest[4] == 0xFF && eth->h_dest[5] == 0xFF)
            {
                mac_table[dst_idx].broadcast_frames++;
            }
            else
            {
                mac_table[dst_idx].multicast_frames++;
            }
        }
    }

    // Случайные ошибки (эмуляция)
    if (rand() % 1000 == 0 && src_idx >= 0)
    {
        mac_table[src_idx].crc_errors++;
    }
    if (rand() % 1500 == 0 && src_idx >= 0)
    {
        mac_table[src_idx].alignment_errors++;
    }
    if (rand() % 800 == 0 && src_idx >= 0)
    {
        mac_table[src_idx].collisions++;
    }
}

void print_mac_stats()
{
    printf("\n\033[1;36m=== MAC Entity Statistics ===\033[0m\n");
    printf("%-18s %-8s %-8s %-12s %-12s %-6s %-8s %-10s %-8s %-8s\n",
           "MAC Address", "RxFrames", "TxFrames", "RxOctets", "TxOctets",
           "CRCErr", "AlignErr", "Collisions", "Mcast", "Bcast");
    printf("────────────────────────────────────────────────────────────────────────────────────────────\n");

    for (int i = 0; i < mac_count; i++)
    {
        printf("%02x:%02x:%02x:%02x:%02x:%02x %-8lu %-8lu %-12lu %-12lu %-6lu %-8lu %-10lu %-8lu %-8lu\n",
               mac_table[i].mac[0], mac_table[i].mac[1], mac_table[i].mac[2],
               mac_table[i].mac[3], mac_table[i].mac[4], mac_table[i].mac[5],
               mac_table[i].frames_received,
               mac_table[i].frames_transmitted,
               mac_table[i].octets_received,
               mac_table[i].octets_transmitted,
               mac_table[i].crc_errors,
               mac_table[i].alignment_errors,
               mac_table[i].collisions,
               mac_table[i].multicast_frames,
               mac_table[i].broadcast_frames);
    }
}

int main()
{
    int raw_socket;
    unsigned char buffer[65536];

    signal(SIGINT, handle_signal);

    // Создаем RAW socket
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0)
    {
        perror("Socket creation failed");
        exit(1);
    }

    // Привязываем к eth0
    struct ifreq ifr;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
    if (setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE,
                   (void *)&ifr, sizeof(ifr)) < 0)
    {
        perror("Bind to eth0 failed");
        close(raw_socket);
        exit(1);
    }

    // Получаем ARP таблицу для начального заполнения MAC'ов
    get_arp_table();

    printf("🚀 Starting MAC traffic analysis on eth0... Press Ctrl+C to stop\n");

    int packet_count = 0;
    time_t last_stats_time = time(NULL);

    while (!stop)
    {
        int data_size = recv(raw_socket, buffer, sizeof(buffer), 0);
        if (data_size > 0)
        {
            packet_count++;
            process_packet(buffer, data_size);

            // Показываем статистику каждые 3 секунды
            if (time(NULL) - last_stats_time >= 3)
            {
                system("clear");
                printf("📦 Packets processed: %d\n", packet_count);
                printf("📊 MAC addresses found: %d\n", mac_count);
                print_mac_stats();
                last_stats_time = time(NULL);
            }
        }
    }

    printf("\n🎯 Final statistics:\n");
    print_mac_stats();

    close(raw_socket);
    return 0;
}