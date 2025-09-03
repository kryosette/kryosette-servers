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

  memcpy(frame.payload, data, data_len);
  mac_update_fcs(&frame);
  
  statistics.tx_frames++;
  statistics.tx_bytes += data_len;

  current_state = MAC_STATE_SENDING;
  if (tx_callback) { tx_callback(true); }
  current_state = MAC_STATE_IDLE;

  
}

void mac_receive_frame(const uint8_t* frame_data, size_t frame_len) {
    if (frame_len < sizeof(eth_header_t) + 4) return;
  
    current_state = MAC_STATE_RECEIVING;
    const eth_frame_t* frame = (const eth_frame_t*)frame_data;

    uint8_t received_fcs = frame->fcs;
  
    if (!mac_addr_equal(frame->header.dst_addr, mac_my_address) &&
       !mac_addr_is_broadcast(frame->header.dst_addr)) {
       current_state = MAC_STATE_IDLE;
       return;
    }

    statistics.rx_frames++;
    size_t payload_len = frame_len - sizeof(eth_header_t) - 4;
    statistics.rx_bytes += payload_len;
}

void mac_update_fcs(eth_frame_t* frame) {
    frame->fcs = 0x12345678; // plug
}

void mac_set_rx_callback(mac_rx_callback_t callback) {
    
}

void mac_set_tx_callback(mac_rx_callback_t callback);
