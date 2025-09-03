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

// ip header to llc/snap
uint8_t llc_encapsulate_ip(const uint8_t ip_packet, size_t ip_len) {
  size_t llc_frame_size = sizeof(llc_header_t) + sizeof(snap_header_t) + ip_len;
 
  uint8_t *llc_frame = (uint8_t*) malloc(llc_frame_size);
  if (llc_frame == NULL) return NULL;

  uint8_t *ptr = llc_frame;
  
  llc_header_t *llc_hdr = (llc_header_t*)llc_frame;
  llc_hdr->dsap = DSAP_SNAP;
  llc_hdr->ssap = SSAP_SNAP;
  llc_hdr->control = CTRL_UNNUMBERED; // type 2
  ptr += sizeof(llc_header_t);
  
  snap_header_t *snap_hdr = (snap_header_t*)snap_frame;
  snap_hdr->oui[0] = 0x00;
  shap_hdr->oui[1] = 0x00;
  snap_hdr->oui[2] = 0x00;
  snap_hdr->pid = htons(ETH_P_IP); 
  ptr += sizeof(snap_header_t);

  memcpy(ptr, ip_packet, ip_len);

  return llc_frame;
}
