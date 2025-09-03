#include "mac.h"
#include "llc.h" 
#include <string.h>
#include <arpa/inet.h> 

static uint8_t mac_my_address[MAC_ADDR_LEN];
static mac_rx_callback_t rx_callback = NULL;
static mac_tx_complete_callback_t tx_callback = NULL;
static mac_stats_t statistics = {0};
static mac_state_t current_state = MAC_STATE_IDLE;

const uint8_t MAC_BROADCAST_ADDR[MAC_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t MAC_NULL_ADDR[MAC_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

void mac_init(const uint8_t* my_mac_addr) {
  memcpy(mac_my_address, my_mac_addr, MAC_ADDR_LEN);
  current_state = MAC_STATE_IDLE;
  memset(&statistics, 0, sizeof(statistics));
}

bool mac_send_llc_pdu(const uint8_t* dst_addr, const uint8_t* llc_pdu, size_t pdu_len) {
    if (!dst_addr || !llc_pdu || pdu_len == 0) return false;
    
    return mac_send_frame(dst_addr, llc_pdu, pdu_len, ETH_P_LLC_SNAP);
}

bool mac_send_frame(const uint8_t* dst_addr, 
                   const uint8_t* data, 
                   size_t data_len,
                   uint16_t ethertype) {
  if (data_len > ETH_MTU) return false;

  eth_frame_t frame;

  mac_addr_copy(frame->header.dst_addr, dst_addr);
  mac_addr_copy(frame->header.src_addr, src_addr);
  frame->header.ethertype = htons(ethertype);
}

void mac_set_rx_callback(mac_rx_callback_t callback) {
  
}

void mac_set_tx_callback(mac_rx_callback_t callback);
