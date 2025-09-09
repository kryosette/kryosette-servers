#include "bpdu.h"

void bpdu_send_configuration(uint32_t port_id) {
    struct bpdu_header bpdu;
    
    bpdu.protocol_id = htons(0x0000);
    bpdu.version = 0x00;
    bpdu.bpdu_type = BPDU_TYPE_CONFIG;
    
    bpdu.root_bridge_id = stp_global.root_bridge;
    bpdu.root_path_cost = htonl(stp_global.root_path_cost);
    
    bpdu.bridge_id = stp_global.bridge_id;
    bpdu.port_id = htons(port_id);
    
    bpdu.message_age = htons(0);
    bpdu.max_age = htons(STP_MAX_AGE);
    bpdu.hello_time = htons(STP_HELLO_TIME);
    bpdu.forward_delay = htons(STP_FORWARD_DELAY);
    
    network_send_bpdu(port_id, &bpdu, sizeof(bpdu));
}
