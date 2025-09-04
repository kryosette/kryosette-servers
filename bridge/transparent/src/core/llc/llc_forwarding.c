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
  bridge->num_ports = num_ports;
  for (int i = 0; i < num_ports; i++) {
     bridge->ports[i].state = PORT_STATE_LEARNING;
  }

}

void bridge_destroy(bridge_t *bridge) {
    if (bridge == NULL) {
        return;
    }
    free(bridge->ports);
    bridge->ports = NULL;
    bridge->num_ports = 0;
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
