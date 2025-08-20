#include "arp-detector.h"

volatile int running = 1;

struct arp_entry arp_table[MAX_ENTRIES];
int entry_count = 0;

pthread_mutex_t table_mutex = PTHREAD_MUTEX_INITIALIZER; // mutex for thread safety

void signal_handler(int sig) {
    running = 0;
    printf("\nShutting down detector...\n");
}

void check_arp_entry(uint32_t ip, struct ether_addr mac) {
    pthread_mutex_lock(&table_mutex); 

    /*
    INET_ADDRSTRLEN represents the maximum length required to store a null-terminated string 
    representation of an IPv4 address in dotted-decimal notation.
    */
    char ip_str[INET_ADDRSTRLEN];

    /*
    const char *inet_ntop(int af, const void *restrict src,
                             char dst[restrict .size], socklen_t size);
    */
    inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);

    for (int i = 0; i < entry_count; i++) {
        if (arp_table[i].ip == ip) {
            
            /*
            int memcmp(const void s1[.n], const void s2[.n], size_t n);

            The memcmp() function compares the first n bytes (each interpreted
            as unsigned char) of the memory areas s1 and s2.
            */
            if (memcmp(&arp_table[i].mac, &mac, sizeof(mac)) != 0) {
                fprintf(stderr, "\n\033[1;31m[ALERT!] ARP Spoofing detected!\033[0m\n");
                fprintf(stderr, "   IP: %s\n", ip_str);
                fprintf(stderr, "   Old MAC: %s\n", ether_ntoa(&arp_table[i].mac));
                fprintf(stderr, "   New MAC: %s\n", ether_ntoa(&mac));
                fprintf(stderr, "   This is likely an attack!\n\n");
            }

            pthread_mutex_unlock(&table_mutex);
            return;
        }
    }

    // if the IP is not found
    if (entry_count < MAX_ENTRIES) {
        arp_table[entry_count].ip = ip;
        arp_table[entry_count].mac = mac;
        entry_count++;
        printf("\033[1;32m[LEARNED]\033[0m New ARP entry: %s -> %s\n", ip_str, ether_ntoa(&mac));
    } else {
        fprintf(stderr, "ARP table is full!\n");
    }

    pthread_mutex_unlock(&table_mutex);
}

void detect_arp_spoofing(const char *iface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp; // the structure in which the compiled file will be placed
    char filter_exp[] = "arp"; // only arp packets
    bpf_u_int32 net; // for storage ipv4 in .bin

    /*
    pcap_t *pcap_open_live(const char *device, int snaplen,
           int promisc, int to_ms, char *errbuf);
    */
    handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", iface, errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    printf("Starting ARP Spoofing Detector on interface %s...\n", iface);
    printf("Press Ctrl+C to stop.\n");

    /*
    struct pcap_pkthdr {
        struct timeval ts; // Timestamp (seconds and microseconds) of packet capture
        bpf_u_int32 caplen; // How many bytes were actually captured (may be less than len)
        bpf_u_int32 len; // Actual packet length in bytes (as was on the network)
    };
    */
    struct pcap_pkthdr header;
    const u_char *packet; // raw packet
    /*
    struct ether_arp {
        struct arphdr ea_hdr;      // ARP header (hardware and protocol type, opcode, etc.)
        u_char arp_sha[ETH_ALEN];  // Sender hardware address (MAC) - 6 bytes
        u_char arp_spa[4];         // Sender protocol address (IPv4) - 4 bytes
        u_char arp_tha[ETH_ALEN];  // Target hardware address (MAC) - 6 bytes
        u_char arp_tpa[4];         // Target protocol address (IPv4) - 4 bytes
    };
    */
    struct ether_arp *arp_pkt;

    while (running) {
        /*
        int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
        const u_char **pkt_data);
        const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);
        */
        packet = pcap_next(handle, &header);
        if (packet == NULL) continue;   

        // The packet starts with an Ethernet header (14 bytes), followed by ARP data
        arp_pkt = (struct ether_arp *)(packet + 14);

        // only arp
        // The htons() function converts the unsigned short integer hostshort from host byte order to network byte order.
        if (ntohs(arp_pkt->ea_hdr.ar_op) != ARPOP_REPLY) continue;

        // extract the sender's IP and MAC from the ARP packet
        uint32_t src_ip;
        memcpy(&src_ip, arp_pkt->arp_spa, sizeof(src_ip));

        struct ether_addr src_mac;
        memcpy(&src_mac, arp_pkt->arp_sha, sizeof(src_mac));

        check_arp_entry(src_ip, src_mac);
    }

    pcap_close(handle);
    printf("Detector stopped.\n");
}
