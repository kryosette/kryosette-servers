#ifndef FORWARDING_H
#define FORWARDING_H

#include <stdint.h>
#include <stddef.h>
#include "mac.h"

typedef enum {
    FWD_DROP,   
    FWD_LOCAL,   
    FWD_FLOOD,
    FWD_TO_PORT 
} forwarding_decision_t;

forwarding_decision_t decide_forwarding(const uint8_t *dst_mac,
                                       int incoming_port_index,
                                       int *output_port_index);

void process_frame(const uint8_t *frame_data,
                  size_t frame_len,
                  const uint8_t *src_mac,
                  int incoming_port_index);

#endif // FORWARDING_H
