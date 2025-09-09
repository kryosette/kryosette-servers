#include "stp.h"

struct stp_instance *stp;
struct mac_table_t *mac;

int bridge_id_compare(const struct bridge_id *a, const struct bridge_id *b) {
    if (a->priority != b->priority) {
        return a->priority - b->priority;
    }
    return memcmp(a->mac, b->mac, 6);
}

void init_bridge_id(struct bridge_id *bid, uint16_t priority, const uint8_t *mac) {
    bid->priority = priority;
    memcpy(bid->mac, mac, 6);
}

void stp_init(const uint8_t *our_mac, uint32_t max_ports) {
    printf("Initializing STP with MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           our_mac[0], our_mac[1], our_mac[2], our_mac[3], our_mac[4], our_mac[5]);
    
    init_bridge_id(&stp_global.bridge_id, 32768, our_mac); // Default priority 32768
    
    memcpy(&stp_global.root_bridge, &stp_global.bridge_id, sizeof(struct bridge_id));
    stp_global.root_path_cost = 0;
    stp_global.is_root_bridge = true;
    
    stp_global.ports = malloc(max_ports * sizeof(struct stp_port));
    if (!stp_global.ports) {
        printf("STP init failed: cannot allocate memory for ports\n");
        return;
    }
    
    stp_global.max_ports = max_ports;
    stp_global.port_count = 0;
    
    for (uint32_t i = 0; i < max_ports; i++) {
        stp_global.ports[i].port_id = i;
        stp_global.ports[i].state = PORT_STATE_DISABLED;
        stp_global.ports[i].enabled = false;
        stp_global.ports[i].path_cost = 0;
        stp_global.ports[i].designated_port = 0;
        stp_global.ports[i].hello_timer = 0;
        stp_global.ports[i].forward_delay_timer = 0;
        stp_global.ports[i].max_age_timer = 0;
        memset(&stp_global.ports[i].designated_bridge, 0, sizeof(struct bridge_id));
    }
    
    printf("STP initialized successfully. We are root bridge: %s\n",
           stp_global.is_root_bridge ? "YES" : "NO");
}
