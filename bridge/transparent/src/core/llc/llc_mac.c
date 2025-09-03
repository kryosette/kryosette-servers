#include "llc_mac.h"

void mac_send(uint8_t *llc_pdu, size_t ip_len) {
  if (llc_pdu == NULL || ip_len == NULL) return;

  
}

void mac_set_rx_callback(mac_rx_callback_t callback) {
  
}

void mac_set_tx_callback(mac_rx_callback_t callback);
