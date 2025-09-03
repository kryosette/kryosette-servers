#include "llc.h"
#include "forwarding.h" 
#include "filtering.h" 
#include "stp.h"      

void llc_receive_ip(uint8_t *ip_packet, size_t len) {
  if (ip_packet == NULL || len == 0) return 0;

  uint8_t *llc_pdu = llc_encapsulate_ip(ip_packet, len);

  if (llc_pdu != NULL) {
    mac_send(llc_pdu, LLC_FRAME_SIZE(len);

    free(llc_pdu);
  }
}
