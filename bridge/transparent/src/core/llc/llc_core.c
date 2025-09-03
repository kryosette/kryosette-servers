#include "llc.h"
#include "forwarding.h" 
#include "filtering.h" 
#include "stp.h"      
#include "llc_core.h"

void llc_receive_ip(uint8_t *ip_packet, size_t len) {
  if (ip_packet == NULL || len == 0) return 0;
}
