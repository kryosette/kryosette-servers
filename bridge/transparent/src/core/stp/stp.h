#pragma once
#ifndef STP_H
#define STP_H

#include <stdint.h>
#include <stdbool.h>

#define BPDU_TYPE_CONFIG      0x00
#define BPDU_TYPE_TCN         0x80
#define BPDU_TYPE_RSTP        0x02

#define BPDU_FLAG_TC          0x01  // Topology Change
#define BPDU_FLAG_TCA         0x80  // TC Acknowledgment

#define STP_HELLO_TIME        2
#define STP_FORWARD_DELAY     15
#define STP_MAX_AGE           20

#define STP_HELLO_TIME        2
#define STP_FORWARD_DELAY     15  
#define STP_MAX_AGE           20

#define PORT_STATE_DISABLED   0
#define PORT_STATE_BLOCKING   1
#define PORT_STATE_LISTENING  2
#define PORT_STATE_LEARNING   3
#define PORT_STATE_FORWARDING 4

struct bridge_id {
    uint16_t priority;
    uint8_t mac[6];
};

struct stp_port {
    uint32_t port_id;
    uint32_t path_cost;
    struct bridge_id designated_bridge;
    uint16_t designated_port;
    uint8_t state; 
    bool enabled;
};

struct stp_instance {
    struct bridge_id bridge_id;
    struct bridge_id root_bridge;
    uint32_t root_path_cost;
    struct stp_port *ports;
    uint32_t port_count;
};

void stp_init(struct stp_instance *stp, uint8_t *mac_addr);
void stp_port_add(struct stp_instance *stp, uint32_t port_id, uint32_t cost);

void stp_handle_bpdu(struct stp_instance *stp, uint32_t port_id, 
                    const uint8_t *bpdu, size_t len);
void stp_send_bpdu(struct stp_instance *stp, uint32_t port_id, uint8_t type);

void stp_timer_tick(struct stp_instance *stp);
void stp_hello_timer(struct stp_instance *stp);

uint8_t stp_get_port_state(struct stp_instance *stp, uint32_t port_id);
bool stp_is_root_bridge(struct stp_instance *stp);

#endif 
