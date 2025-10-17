#ifndef LLC_FORWARDING_H
#define LLC_FORWARDING_H

#include <stdint.h>
#include <stddef.h>
#include "mac.h" 
#include "llc.h" 

typedef enum {
    PORT_STATE_DISABLED,   
    PORT_STATE_BLOCKING,  
    PORT_STATE_LEARNING,
    PORT_STATE_FORWARDING  
} port_state_t;

typedef struct {
    int fd; 
    uint8_t mac_addr[MAC_ADDR_LEN];
    port_state_t state; 
} bridge_port_t;

typedef struct {
    bridge_port_t *ports;   
    size_t num_ports;       
} bridge_t;

void bridge_init(bridge_t *bridge, bridge_port_t *ports, size_t num_ports);
void bridge_forward_frame(bridge_t *bridge,
                         const uint8_t *frame_data,
                         size_t frame_len,
                         const uint8_t *src_mac,
                         int incoming_port_index);
void bridge_send_frame_on_port(const bridge_port_t *port,
                              const uint8_t *frame_data,
                              size_t frame_len);

#endif // LLC_FORWARDING_H
