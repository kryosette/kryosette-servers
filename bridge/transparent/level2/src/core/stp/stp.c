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

bool stp_port_add(uint32_t port_id, uint32_t cost) {
    if (port_id >= stp_global.max_ports) {
        printf("STP error: port_id %u exceeds max ports %u\n", port_id, stp_global.max_ports);
        return false;
    }
    
    if (stp_global.port_count >= stp_global.max_ports) {
        printf("STP error: cannot add more ports (max: %u)\n", stp_global.max_ports);
        return false;
    }
    
    struct stp_port *port = &stp_global.ports[port_id];
    
    port->enabled = true;
    port->path_cost = cost;
    port->state = PORT_STATE_BLOCKING; // Начинаем с blocking
    
    // Если мы root bridge, то мы designated bridge для всех портов
    if (stp_global.is_root_bridge) {
        memcpy(&port->designated_bridge, &stp_global.bridge_id, sizeof(struct bridge_id));
        port->designated_port = port_id;
    }
    
    port->hello_timer = STP_HELLO_TIME * 1000; // в миллисекундах
    port->max_age_timer = STP_MAX_AGE * 1000;
    port->forward_delay_timer = 0;
    
    stp_global.port_count++;
    
    printf("STP port %u added with cost %u, state: BLOCKING\n", port_id, cost);
    return true;
}

void stp_port_set_enabled(uint32_t port_id, bool enabled) {
    if (port_id >= stp_global.max_ports) {
        return;
    }
    
    struct stp_port *port = &stp_global.ports[port_id];
    port->enabled = enabled;
    
    if (enabled) {
        port->state = PORT_STATE_BLOCKING;
        printf("STP port %u enabled, state: BLOCKING\n", port_id);
    } else {
        port->state = PORT_STATE_DISABLED;
        printf("STP port %u disabled\n", port_id);
    }
}

uint8_t stp_get_port_state(uint32_t port_id) {
    if (port_id >= stp_global.max_ports) {
        return PORT_STATE_DISABLED;
    }
    
    if (!stp_global.ports[port_id].enabled) {
        return PORT_STATE_DISABLED;
    }
    
    return stp_global.ports[port_id].state;
}

bool stp_is_root_bridge(void) {
    return stp_global.is_root_bridge;
}

uint32_t stp_get_root_path_cost(void) {
    return stp_global.root_path_cost;
}

void stp_set_bridge_priority(uint16_t priority) {
    priority = priority & 0xF000;
    stp_global.bridge_id.priority = priority;
    
    printf("STP bridge priority set to %u\n", priority);
    
    stp_recalculate_topology();
}

// Функция пересчета топологии (заглушка, будет реализована позже)
void stp_recalculate_topology(void) {
    printf("STP topology recalculation triggered\n");
    // Здесь будет сложная логика выбора root bridge и портов
}

