#include "llc_forwarding.h"

static port_state_t curr_state = PORT_STATE_LEARNING;
static bridge_port_t 
static uint8_t curr_port =  

void bridge_init(bridge_t *bridge, bridge_port_t *ports, size_t num_ports) {
  if (bridge == NULL || ports == NULL || num_ports == NULL) {
     return;
  }
  const bridge_port_t *mac_addr = (uint8_t*) *port_data;
  memcpy(bridge, mac_addr, num_ports);
  curr_state = PORT_STATE_LEARNING;
  memset(curr_state, );
}

void bridge_forward_frame(bridge_t *bridge,
                         const uint8_t *frame_data,
                         size_t frame_len,
                         const uint8_t *src_mac,
                         int incoming_port_index) {} 
