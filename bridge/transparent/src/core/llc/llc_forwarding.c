#include "llc_forwarding.h"

static port_state_t curr_state = PORT_STATE_LEARNING;
static bridge_port_t num_ports = 
static uint8_t curr_port =  
static bridge_t num_ports = NULL;

void bridge_init(bridge_t *bridge, bridge_port_t *ports, size_t num_ports) {
  if (bridge == NULL || ports == NULL || num_ports == 0) {
     return;
  }
  bridge->ports = (bridge_port_t*)malloc(sizeof(bridge_port_t) * num_ports);
  if (bridge->ports == NULL) {
    return;
  }
  memcpy(bridge->ports, ports, sizeof(bridge_port_t) * num_ports);
  curr_state = PORT_STATE_LEARNING;
  memset(curr_state, num_ports);
}

void bridge_forward_frame(bridge_t *bridge,
                         const uint8_t *frame_data,
                         size_t frame_len,
                         const uint8_t *src_mac,
                         int incoming_port_index) {
  if (bridge == NULL) {
    return;
  }

  
} 
