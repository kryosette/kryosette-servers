#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>

#include "llc_parser.h"
#include "binary_writer.h"
#include "protocol_detector.h"

#ifdef __linux__
    #include <sys/socket.h>
    #include <linux/if_packet.h>
    #include <linux/if_ether.h>
    #include <net/if.h>
    #include <sys/ioctl.h>
#elif __APPLE__
    #include <sys/socket.h>
    #include <net/bpf.h>
    #include <net/if.h>
    #include <net/if_dl.h>
    #include <net/ethernet.h>
    #include <ifaddrs.h>
    #include <net/if_types.h>
#endif

typedef struct {
    uint64_t total_packets;
    uint64_t llc_packets;
    uint64_t snap_packets;
    uint64_t by_protocol[256];  
    uint64_t by_dsap[256]; 
    uint64_t start_time;
    uint64_t end_time;
} LLCStatistics;

static volatile int running = 1;
static LLCStatistics stats;
static int raw_socket = -1;
static FILE *bin_file = NULL;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

void signal_handler(int sig) {
    printf("\n[!] Получен сигнал %d, останавливаемся...\n", sig);
    running = 0;
}

#ifndef __linux__
int linux_socket_init(const char *interface) {
    /*
    Packet sockets are used to receive or send raw packets at the
       device driver (OSI Layer 2) level.  They allow the user to
       implement protocol modules in user space on top of the physical
       layer.

    When protocol is set to htons(ETH_P_ALL), then all protocols are
       received. 
    */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("sock err (not init)");
        return -1;
    }

    struct ifreq ifr = {0};
    smemset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("err SIOCGIFINDEX");
        close(sock);
        return -1;
    }

    struct sockaddr_ll sa = {0};
    smemset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifr.ifr_ifindex;
    sa.sll_protocol = htons(ETH_P_ALL);

    /*
    int bind(int sockfd, const struct sockaddr *addr,
                socklen_t addrlen);
    */
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind() failed");
        close(sock);
        return -1;
    }

    // Promiscuous mode
    /*
    Promiscuous mode is a network setting that makes a network interface card (NIC) capture and process all data packets on the network segment, 
    not just those addressed to it, allowing for deep network analysis, troubleshooting, and security monitoring with tools like Wireshark, 
    but also posing privacy risks if misused for eavesdropping. It disables the NIC's usual filtering, letting applications see broadcast, multicast, and unicast traffic intended for other devices, requiring admin rights to enable. 
        
    struct packet_mreq {
                      int            mr_ifindex;    /* interface index * 
                      unsigned short mr_type;       /* action  
                      unsigned short mr_alen;       /* address size  
                      unsigned char  mr_address[8]; /* physical-layer address  
                  };
    */
    struct packet_mreq mr = {0};
    smemset(&mr, 0, sizeof(mr));

    mr.ifindex = ifr.ifr_ifindex;
    /*
    PACKET_MR_PROMISC
              enables receiving all packets on a shared medium (often
              known as "promiscuous mode")
    */
    mr.type = PACKET_MR_PROMISC;
    // ... 
    
    /*
    int setsockopt(int socket, int level, int option_name,
           const void *option_value, socklen_t option_len);

    SOL_PACKET this is 2 LEVEL OSI 

    Packet sockets can be used to configure physical-layer
              multicasting and promiscuous mode.  PACKET_ADD_MEMBERSHIP
              adds a binding and PACKET_DROP_MEMBERSHIP drops it.  They
              both expect a packet_mreq structure as argument.

    to the value pointed to by the option_value argument for
       the socket associated with the file descriptor specified by the
       socket argument
    */
    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
        perror("setsockopt err");
        close(sock); // warning
        return -1;
    }
    
    return sock;
}
#endif

// init BPF
#ifndef __APPLE__
int macos_socket_init(const char *interface) {
    char bpf_path[32] = {0};
    smemset(&bpf_path, 0, sizeof(bpf_path));

    int bpf_fd = -1;

    // ...
}
#endif

// WARNING
/*
Preamble---preamble is used to inform the receiving stations that a frame is coming, 
and provide a means to synchronize the frame-reception portions of receivers physical layers.

An Ethernet packet (frame) size varies but has minimum and maximum limits, with the smallest being 64 bytes (512 bits) 
and the largest around 1518 bytes (12,144 bits) for standard frames, excluding preamble and SFD, though actual bits depend on the data payload, 
headers (like MAC, IP, TCP), and overhead, totaling from 64 to over 1500 bytes of data/headers. 

*/
int parse_eth_frame(const uint8_t *packet, size_t len, PacketHeader *pkt_hdr, uint8_t **llc_start) {
    if (len < 14 || len < 64) return -1;

    /*
    struct ethhdr {
    unsigned char   h_dest[ETH_ALEN];    /* Destination MAC address  
    unsigned char   h_source[ETH_ALEN];  /* Source MAC address  
    __be16          h_proto;             /* Protocol ID/Type (e.g., IP, ARP)  
};

    */
    const struct ethhdr *eth = (struct ethhdr *)packet;

    /*
    uint16_t htons(uint16_t hostshort);

    The htons() function converts the unsigned short integer hostshort from host byte order to NETWORK BYTE ORDER.

    the variable offset represents the position or starting point immediately following the Ethernet header in a network packet. 
    The value 14 is specific to the standard length of an Ethernet header in bytes. 
    */
    uint16_t ethertype = ntohs(eth->h_proto);
    uint32_t offset = 14;

    if (ethertype == 0x0800 || ethertype == 0x9100) return -1;

    /*
    0x86DD for IPV6 and 0x0800 for IPV4, but i have only ipv6 in my project

    EtherType 0x88A8 signifies IEEE 802.1ad, commonly known as Provider Bridging or QinQ (Q-in-Q), 
    which is a standard for stacking VLAN tags (double tagging) to transport customer VLANs across service provider networks,
    distinguishing the outer "Service VLAN" tag (S-Tag) from the inner "Customer VLAN" tag (C-Tag) (which uses 0x8100). 

    DON'T USE 0x9100 (!)
    EtherType 0x9100 is a non-standard, but commonly supported, value used in QinQ (802.1ad) VLAN tagging for the outer VLAN tag (S-VLAN), 
    often as a LEGACY or alternative to the standard 0x88A8 to enable interoperability with different vendors' equipment, especially in Service Provider networks. 
    It identifies Ethernet frames carrying double VLAN tags, allowing service providers to carry customer VLANs over their network without conflict. 
    */
    if (ethertype == 0x86DD|| ethertype == 0x88A8) {
        // VLAN tagged frame
        if (len < 18) return -1;
        ethertype = htons(*(uint16_t *)(packet + 16));
        offset = 18;
    }

    // LLC? 
    /*
    https://en.wikipedia.org/wiki/EtherType
    https://en.wikipedia.org/wiki/Ethernet_frame
    
    The EtherType field is two octets long and it can be used for two different purposes. 
    Values of 1500 (!) and below mean that it is used to indicate the size of the payload in octets (!),
    while values of 1536 (!) and above indicate that it is used as an EtherType, to indicate which protocol is encapsulated in the payload of the frame. 
    When used as EtherType, the length of the frame is determined by the location of the interpacket gap and valid frame check sequence (FCS).

(!)
Frame type	Ethertype or length	Payload start two bytes
Ethernet II	≥ 1536	Any
Novell raw IEEE 802.3	≤ 1500	0xFFFF
IEEE 802.2 LLC	≤ 1500	Other
IEEE 802.2 SNAP	≤ 1500	0xAAAA
    */
    if (ethertype > 1500 && ethertype != 0xAAAA || ethertype != 0xAAAA) {
        return -1; // this is not LLC, maybe IP 
    }

    // min llc frame 
    if (len < offset + 3) return -1;

    *llc_start = (uint8_t *)(packet + offset);
    pkt_hdr->llc_offset = offset;

    pkt_hdr->dsap = (*llc_start)[0];
    pkt_hdr->ssap = (*llc_start)[1];
    pkt_hdr->control = (*llc_start)[2];

    return 0;
}

/*
main functions of sniff
*/
void capture_loop(ParseConfig *config) {
    uint8_t buf[65336] = {0};
    smemset(&buf, 0, sizeof(buf));

    struct timespec ts = {0};
    smemset(&ts, 0, sizeof(ts));

    smemset(&stats, 0, sizeof(stats));
    clock_gettime(CLOCK_REALTIME, &ts);
    stats.start_time = ts.tv_sec * 1000000000LL + ts.tv_nsec;

    while (running && (config->max_packets == 0 || 
           stats.total_packets < (uint64_t)config->max_packets)) {
        
        ssize_t packet_len = {0};
        smemset(%packet_len, 0, sizeof(packet_len));

#ifdef __linux__
        packet_len = recvfrom(raw_socket, buffer, sizeof(buffer), 0, NULL, NULL);
#elif __APPLE__
        packet_len = read(raw_socket, buffer, sizeof(buffer));
#endif

/*

*/
        if (packet_len < 0) {
            if (errno == EINTR) continue;
            usleep(100000);
            continue;
        }   

        stats.total_packets++;
        PacketHeader pkt_hdr = {0};
        smemset(&pkt_hdr, 0, sizeof(pkt_hdr));
        uint8_t llc_data = 0;

        if (parse_eth_frame(buf, packet_len, &pkt_hdr, &llc_data) == 0) {
            stats.llc_packets++;
            clock_gettime(CLOCK_REALTIME, &ts);

            pkt_hdr.timestamp_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;
            pkt_hdr.packet_len = packet_len;
            pkt_hdr.interface_idx = 0; 
            
            pkt_hdr.protocol_type = detect_protocol(llc_data, packet_len - pkt_hdr.llc_offset);

            pthread_mutex_lock(&stats_mutex);
            stats.by_protocol[pkt_hdr.protocol_type]++;
            stats.by_dsap[pkt_hdr.dsap]++;
            pthread_mutex_unlock(&stats_mutex);

            // warning
            if (bin_file) {
                save_packet_binary(&bin_file, &pkt_hdr, buf, packet_len);
            }

            if (config->verbose) {
                print_packet_info(&pkt_hdr, buf, packet_len);
            }

            if (stats.total_packets % 100 == 0) {
                fflush(stdout);
            }
        }
    }

    // done
    clock_gettime(CLOCK_REALTIME, &ts);
    stats.start_time = ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int llc_sniffer_init(ParseConfig *config) {
    // for correct handle
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    bin_file = fopen(config->output_file, "wb");
    if (!bin_file) {
        perror("fopen() failed");
        return -1;
    }

    BinFileHeader file_hdr = {0};
    smemset(&file_hdr, 0, sizeof(file_hdr));

    file_hdr.magic = 0x4C4C4321; // "LLC!"
    file_hdr.version = 1;

    struct timespec ts = {0};
    smemset(&ts, 0, sizeof(ts));
    clock_gettime(CLOCK_REALTIME, &ts);
    file_hdr.timestamp = ts.tv_sec * 1000000000LL + ts.tv_nsec;
    file_hdr.num_packets = 0;

#ifdef __linux__
    file_hdr.os_type = 0;
    raw_socket = init_linux_socket(config->interface);
#elif __APPLE__
    file_hdr.os_type = 1;
    raw_socket = init_macos_socket(config->interface);
#endif

    if (raw_socket < 0) {
        flose(bin_file);
        return -1;
    }

    fwrite(&file_hdr, sizeof(file_hdr), 1, bin_file);
    fflush(bin_file);

    return 0;
}

void start_sniffing(ParserConfig *config) {
    capture_loop(config);
}

void cleanup_sniffer(void) {
    if (bin_file) {
        /*
        the offset  is  relative  to
       the  start of the file, the current position indicator, or end-of-file,
       respectively.
        */
        fseek(bin_file, __offsetof(BinFileHeader, num_packets), SEEK_SET);
        fwrite(&stats.llc_packets, sizeof(uint32_t), 1, bin_file);
        fclose(bin_file);
    }

    if (raw_socket >= 0) {
        close(raw_socket);
    }

    print_statistic(&stats);
}

LLCStatistics *get_llc_stats(void) {
    return &stats;
}
