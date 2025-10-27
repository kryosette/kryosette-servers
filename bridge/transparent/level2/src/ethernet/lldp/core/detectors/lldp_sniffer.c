#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

#define LLDP_ETH_TYPE 0x88CC
#define LLDP_MULTICAST_MAC {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E}

// LLDP TLV Types
typedef enum
{
    LLDP_TLV_END = 0,
    LLDP_TLV_CHASSIS_ID = 1,
    LLDP_TLV_PORT_ID = 2,
    LLDP_TLV_TTL = 3,
    LLDP_TLV_PORT_DESC = 4,
    LLDP_TLV_SYSTEM_NAME = 5,
    LLDP_TLV_SYSTEM_DESC = 6,
    LLDP_TLV_SYSTEM_CAP = 7,
    LLDP_TLV_MGMT_ADDR = 8,
    LLDP_TLV_ORG_SPECIFIC = 127
} lldp_tlv_type_t;

// LLDP TLV Structure
typedef struct
{
    uint16_t type : 7;
    uint16_t length : 9;
    uint8_t value[];
} __attribute__((packed)) lldp_tlv_t;

// Chassis ID Subtypes
static const char *chassis_subtypes[] = {
    "Reserved", "Chassis Component", "Interface Alias", "Port Component",
    "MAC Address", "Network Address", "Interface Name", "Local"};

// Port ID Subtypes
static const char *port_subtypes[] = {
    "Reserved", "Interface Alias", "Port Component", "MAC Address",
    "Network Address", "Interface Name", "Agent Circuit ID", "Local"};

// System Capabilities
static const char *system_caps[] = {
    "Other", "Repeater", "Bridge", "WLAN AP",
    "Router", "Telephone", "DOCSIS Cable Device", "Station Only"};

// Function to print MAC address
void print_mac(const uint8_t *mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Function to print hex data
void print_hex(const uint8_t *data, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02X ", data[i]);
    }
}

// Parse and print Chassis ID TLV
void parse_chassis_id(const uint8_t *value, uint16_t length)
{
    if (length < 1)
        return;

    uint8_t subtype = value[0];
    const char *subtype_str = "Unknown";
    if (subtype < sizeof(chassis_subtypes) / sizeof(chassis_subtypes[0]))
    {
        subtype_str = chassis_subtypes[subtype];
    }

    printf("        Subtype: %d (%s)\n", subtype, subtype_str);
    printf("        ID: ");

    if (subtype == 4)
    { // MAC Address
        print_mac(&value[1]);
        printf("\n");
    }
    else if (subtype == 5)
    { // Network Address
        if (value[1] == 1)
        { // IPv4
            struct in_addr addr;
            memcpy(&addr, &value[2], 4);
            printf("IPv4: %s\n", inet_ntoa(addr));
        }
    }
    else
    {
        // Print as string or hex
        if (length > 1)
        {
            // Try to print as string if printable
            int printable = 1;
            for (int i = 1; i < length; i++)
            {
                if (value[i] < 32 || value[i] > 126)
                {
                    printable = 0;
                    break;
                }
            }
            if (printable)
            {
                printf("%.*s\n", length - 1, &value[1]);
            }
            else
            {
                print_hex(&value[1], length - 1);
                printf("\n");
            }
        }
    }
}

// Parse and print Port ID TLV
void parse_port_id(const uint8_t *value, uint16_t length)
{
    if (length < 1)
        return;

    uint8_t subtype = value[0];
    const char *subtype_str = "Unknown";
    if (subtype < sizeof(port_subtypes) / sizeof(port_subtypes[0]))
    {
        subtype_str = port_subtypes[subtype];
    }

    printf("        Subtype: %d (%s)\n", subtype, subtype_str);
    printf("        ID: ");

    if (subtype == 3)
    { // MAC Address
        print_mac(&value[1]);
        printf("\n");
    }
    else
    {
        // Print as string or hex
        if (length > 1)
        {
            int printable = 1;
            for (int i = 1; i < length; i++)
            {
                if (value[i] < 32 || value[i] > 126)
                {
                    printable = 0;
                    break;
                }
            }
            if (printable)
            {
                printf("%.*s\n", length - 1, &value[1]);
            }
            else
            {
                print_hex(&value[1], length - 1);
                printf("\n");
            }
        }
    }
}

// Parse and print System Capabilities TLV
void parse_system_capabilities(const uint8_t *value, uint16_t length)
{
    if (length != 4)
        return;

    uint16_t capabilities = ntohs(*(uint16_t *)&value[0]);
    uint16_t enabled = ntohs(*(uint16_t *)&value[2]);

    printf("        Capabilities: 0x%04X\n", capabilities);
    printf("        Enabled: 0x%04X\n", enabled);

    printf("        Capabilities List: ");
    for (int i = 0; i < 16; i++)
    {
        if (capabilities & (1 << i))
        {
            if (i < sizeof(system_caps) / sizeof(system_caps[0]))
            {
                printf("%s", system_caps[i]);
                if (enabled & (1 << i))
                {
                    printf("(enabled)");
                }
                printf(" ");
            }
        }
    }
    printf("\n");
}

// Parse and print Management Address TLV
void parse_mgmt_address(const uint8_t *value, uint16_t length)
{
    if (length < 5)
        return;

    uint8_t addr_len = value[0];
    uint8_t addr_subtype = value[1];

    printf("        Address Length: %d\n", addr_len);
    printf("        Subtype: %d ", addr_subtype);

    if (addr_subtype == 1)
    {
        printf("(IPv4)\n");
        printf("        Address: %d.%d.%d.%d\n",
               value[2], value[3], value[4], value[5]);
    }
    else
    {
        printf("(Unknown)\n");
        printf("        Address: ");
        print_hex(&value[2], addr_len);
        printf("\n");
    }

    // Parse interface numbering
    if (length > 5 + addr_len)
    {
        uint8_t if_subtype = value[6 + addr_len];
        uint32_t if_number;

        printf("        Interface: Subtype=%d ", if_subtype);

        if (if_subtype == 1 || if_subtype == 2)
        { // ifIndex or System Port Number
            if (length >= 10 + addr_len)
            {
                memcpy(&if_number, &value[7 + addr_len], 4);
                if_number = ntohl(if_number);
                printf("Number=%u\n", if_number);
            }
        }
        else
        {
            printf("Unknown\n");
        }
    }
}

// Parse and print Organizationally Specific TLV
void parse_org_specific(const uint8_t *value, uint16_t length)
{
    if (length < 3)
        return;

    printf("        OUI: %02X:%02X:%02X\n", value[0], value[1], value[2]);
    printf("        Subtype: %d\n", value[3]);
    printf("        Data: ");
    print_hex(&value[4], length - 4);
    printf("\n");
}

// Main LLDP packet processing function
void process_lldp_packet(const uint8_t *packet, int len)
{
    printf("\n=== LLDP Packet Received ===\n");

    const uint8_t *lldp_data = packet;
    int offset = 0;

    while (offset < len)
    {
        lldp_tlv_t *tlv = (lldp_tlv_t *)&lldp_data[offset];
        uint16_t type = tlv->type;
        uint16_t tlv_length = tlv->length;

        printf("TLV Type: %d, Length: %d\n", type, tlv_length);

        switch (type)
        {
        case LLDP_TLV_END:
            printf("    End of LLDPDU\n");
            return;

        case LLDP_TLV_CHASSIS_ID:
            printf("    Chassis ID:\n");
            parse_chassis_id(tlv->value, tlv_length);
            break;

        case LLDP_TLV_PORT_ID:
            printf("    Port ID:\n");
            parse_port_id(tlv->value, tlv_length);
            break;

        case LLDP_TLV_TTL:
            printf("    Time To Live:\n");
            if (tlv_length == 2)
            {
                uint16_t ttl = ntohs(*(uint16_t *)tlv->value);
                printf("        TTL: %d seconds\n", ttl);
            }
            break;

        case LLDP_TLV_PORT_DESC:
            printf("    Port Description:\n");
            printf("        %.*s\n", tlv_length, tlv->value);
            break;

        case LLDP_TLV_SYSTEM_NAME:
            printf("    System Name:\n");
            printf("        %.*s\n", tlv_length, tlv->value);
            break;

        case LLDP_TLV_SYSTEM_DESC:
            printf("    System Description:\n");
            printf("        %.*s\n", tlv_length, tlv->value);
            break;

        case LLDP_TLV_SYSTEM_CAP:
            printf("    System Capabilities:\n");
            parse_system_capabilities(tlv->value, tlv_length);
            break;

        case LLDP_TLV_MGMT_ADDR:
            printf("    Management Address:\n");
            parse_mgmt_address(tlv->value, tlv_length);
            break;

        case LLDP_TLV_ORG_SPECIFIC:
            printf("    Organizationally Specific:\n");
            parse_org_specific(tlv->value, tlv_length);
            break;

        default:
            printf("    Unknown TLV Type\n");
            printf("    Data: ");
            print_hex(tlv->value, tlv_length);
            printf("\n");
            break;
        }

        offset += 2 + tlv_length; // Type/Length (2 bytes) + Value
        if (type == LLDP_TLV_END)
            break;
    }

    printf("=== End of LLDP Packet ===\n\n");
}

int main(int argc, char *argv[])
{
    int sockfd;
    struct sockaddr_ll addr;
    uint8_t buffer[4096];

    if (argc != 2)
    {
        printf("Usage: %s <interface>\n", argv[0]);
        printf("Example: %s eth0\n", argv[0]);
        exit(1);
    }

    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        perror("socket");
        exit(1);
    }

    // Get interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl");
        close(sockfd);
        exit(1);
    }

    // Bind to interface
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifr.ifr_ifindex;

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(sockfd);
        exit(1);
    }

    printf("LLDP Sniffer started on interface %s\n", argv[1]);
    printf("Press Ctrl+C to stop...\n\n");

    // Main capture loop
    while (1)
    {
        int packet_len = recv(sockfd, buffer, sizeof(buffer), 0);
        if (packet_len < 0)
        {
            perror("recv");
            continue;
        }

        // Check if it's an Ethernet frame
        if (packet_len < (int)sizeof(struct ethhdr))
        {
            continue;
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;

        // Check for LLDP Ethernet type and multicast MAC
        uint8_t lldp_mac[] = LLDP_MULTICAST_MAC;
        if (ntohs(eth->h_proto) == LLDP_ETH_TYPE &&
            memcmp(eth->h_dest, lldp_mac, 6) == 0)
        {

            // Process LLDP packet (skip Ethernet header)
            process_lldp_packet(buffer + sizeof(struct ethhdr),
                                packet_len - sizeof(struct ethhdr));
        }
    }

    close(sockfd);
    return 0;
}