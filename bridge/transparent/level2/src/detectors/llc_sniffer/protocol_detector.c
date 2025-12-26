#include "structures.h"

// WARNING! CHECK
ProtocolType detect_protocol(const uint8_t *llc_data, uint32_t len) {
    if (len < 3) return PROTO_UNKNOWN;

    /*
    https://en.wikipedia.org/wiki/IEEE_802.2
    */
    uint8_t dsap = llc_data[0];
    uint8_t ssap = llc_data[1];
    uint8_t control = llc_data[2];

    /*
    
    */
    if (dsap == 0xAA && ssap == 0xAA && control == 0x03) {
        if (len >= 8) { // llc + snap
            SNAPHeader *snap = (SNAPHeader *)(llc_data + 3);
            uint16_t pid = ntohs(snap->pid);

            if (snap->oui[0] == 0x00 && snap->oui[1] == 0x00 && snap->oui[2] == 0x00) {
                switch (pid) {
                    // warning! CHECK | IT MAY BE DEPRECATED
                    case 0x0800: return PROTO_IP;
                    case 0x0806: return PROTO_ARP;
                    case 0x8137: return PROTO_IPX;
                    case 0x6558: return PROTO_LACP;
                    case 0x2004: return PROTO_CDP;
                    case 0x9000: return PROTO_LOOP;
                }
            } else if (snap->oui[0] == 0x00 && snap->oui[1] == 0x80 && snap->oui[2] == 0xC2) {
                switch (pid) {
                    case 0x0004: return PROTO_LLDP;
                    case 0x0007: return PROTO_EAPOL;
                    case 0x0009: return PROTO_LACP;
                }
            }

            return PROTO_SNAP;
        }
    }

    switch (dsap) {
        // warning! CHECK | IT MAY BE DEPRECATED
        case 0x42: return PROTO_STP; // Spanning Tree
        case 0x7A: return PROTO_IPX; // IPX/SPX
        case 0xF0: return PROTO_NETBEUI; // NetBEUI
        case 0xFE: return PROTO_ISIS; // ISIS
        case 0x06: return PROTO_IP; // IP (редко)
        case 0xE0: return PROTO_IP; // IP (Novell)
    }

    if (control == 0x03) {
        // Ненумерованная информация
    } else if ((control & 0x01) == 0) {
        // Нумерованная информация (I-frame)
    } else if ((control & 0x03) == 0x01) {
        // Супервизорный кадр (S-frame)
    }

    return PROTO_UNKNOWN;
}

void print_packet_info(const PacketHeader *hdr, const uint8_t *packet, uint32_t len) {
    char time_buf[64] = {0};
    smemset(&time_buf, 0, sizeof(time_buf));
    struct tm tm_info = {0};
    smemset(&tm_info, 0, sizeof(tm_info));
    time_t sec = hdr->timestamp_ns / 1000000000;
    localtime_r(&sec, &tm_info);
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm_info);
    
    printf("[%s.%03ld] ", time_buf, (hdr->timestamp_ns % 1000000000) / 1000000);
    printf("Len: %5u | ", hdr->packet_len);
    printf("DSAP: 0x%02X | SSAP: 0x%02X | Ctrl: 0x%02X | ", 
           hdr->dsap, hdr->ssap, hdr->control);
    
    const char *proto_name = "Unknown";
    switch (hdr->protocol_type) {
        case PROTO_IP: proto_name = "IP"; break;
        case PROTO_ARP: proto_name = "ARP"; break;
        case PROTO_SNAP: proto_name = "SNAP"; break;
        case PROTO_STP: proto_name = "STP"; break;
        case PROTO_LLDP: proto_name = "LLDP"; break;
        case PROTO_EAPOL: proto_name = "EAPOL"; break;
        case PROTO_LACP: proto_name = "LACP"; break;
        case PROTO_CDP: proto_name = "CDP"; break;
        case PROTO_ISIS: proto_name = "ISIS"; break;
    }
    
    printf("Proto: %-6s\n", proto_name);
}

void print_statistics(const LLCStatistics *stats) {
    printf("\n=== LLC STATISTICS ===\n");
    printf("Время захвата: %.2f секунд\n", 
           (stats->end_time - stats->start_time) / 1e9);
    printf("Всего пакетов: %lu\n", stats->total_packets);
    printf("LLC пакетов: %lu (%.1f%%)\n", 
           stats->llc_packets,
           stats->total_packets > 0 ? 
           (stats->llc_packets * 100.0 / stats->total_packets) : 0.0);
    
    printf("\nРаспределение по протоколам:\n");
    const char *proto_names[] = {
        "Unknown", "IP", "ARP", "IPX", "NetBEUI", "SNAP", 
        "STP", "LLDP", "EAPOL", "LACP", "CDP", "Loop", "ISIS"
    };
    
    for (int i = 0; i <= PROTO_ISIS; i++) {
        if (stats->by_protocol[i] > 0) {
            printf(" %-10s: %lu\n", proto_names[i], stats->by_protocol[i]);
        }
    }
    
    printf("\nТоп DSAP значений:\n");
    for (int i = 0; i < 256; i++) {
        if (stats->by_dsap[i] > 0) {
            printf(" DSAP 0x%02X: %lu пакетов\n", i, stats->by_dsap[i]);
        }
    }
}