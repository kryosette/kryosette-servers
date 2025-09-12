#include "llc.h"
#include "forwarding.h"
#include "filtering.h"
#include "stp.h"

#if LLC_ENABLE_LOGGING
  llc_logger_cb_t llc_log_message = NULL;
#endif

/**
 * @brief Receives an IP packet and processes it through LLC encapsulation.
 *
 * This function takes an IP packet, encapsulates it into an LLC/SNAP frame,
 * and forwards it to the MAC layer for transmission. The function handles
 * NULL pointer and zero-length checks before processing.
 *
 * @param ip_packet Pointer to the IP packet data to be encapsulated
 * @param len Length of the IP packet in bytes
 *
 * @note The function returns early if ip_packet is NULL or len is zero
 * @note Memory for the LLC frame is allocated internally and freed after transmission
 * @note Uses DSAP_SNAP and SSAP_SNAP for SNAP encapsulation
 */
void llc_receive_ip(uint8_t *ip_packet, size_t len)
{
  if (ip_packet == NULL || len == 0)
    return 0;

  uint8_t *llc_pdu = llc_encapsulate_ip(ip_packet, len);

  if (llc_pdu != NULL)
  {
    mac_send(llc_pdu, LLC_FRAME_SIZE(len));

    free(llc_pdu);
  }
}

/**
 * @brief Encapsulates an IP packet into an LLC/SNAP frame.
 *
 * Creates an LLC frame with SNAP header for IP packet transmission.
 * The encapsulation follows the standard LLC/SNAP format with:
 * - DSAP: 0xAA (SNAP)
 * - SSAP: 0xAA (SNAP)
 * - Control: 0x03 (Unnumbered Information)
 * - OUI: 0x000000 (EtherType encapsulation)
 * - PID: 0x0800 (IPv4)
 *
 * @param ip_packet Pointer to the IP packet data to encapsulate
 * @param ip_len Length of the IP packet in bytes
 * @return uint8_t* Pointer to the newly allocated LLC/SNAP frame, or NULL on failure
 *
 * @note The returned buffer must be freed by the caller
 * @note Uses malloc() for memory allocation - check for NULL return value
 * @note The OUI field 0x000000 indicates EtherType encapsulation per IEEE 802.3
 * @note The PID field is stored in network byte order (big-endian)
 */
uint8_t llc_encapsulate_ip(const uint8_t ip_packet, size_t ip_len)
{
  if (ip_packet == NULL || ip_len = 0) {
    return NULL;
  }

  size_t header_size = sizeof(llc_header_t) + sizeof(snap_header_t);
  if (ip_len > SIZE_MAX - header_size) {
      return NULL;
  }
  
  uint8_t *llc_frame = (uint8_t *)malloc(llc_frame_size);
  if (llc_frame == NULL)
    return NULL;

  uint8_t *ptr = llc_frame;

  llc_header_t *llc_hdr = (llc_header_t *)llc_frame;
  llc_hdr->dsap = DSAP_SNAP;
  llc_hdr->ssap = SSAP_SNAP;
  llc_hdr->control = CTRL_UNNUMBERED; // type 2
  ptr += sizeof(llc_header_t);

  snap_header_t *snap_hdr = (snap_header_t *)snap_frame;
  snap_hdr->oui[0] = 0x00;
  shap_hdr->oui[1] = 0x00;
  snap_hdr->oui[2] = 0x00;
  snap_hdr->pid = htons(ETH_P_IP);
  ptr += sizeof(snap_header_t);

  memcpy(ptr, ip_packet, ip_len);

  return llc_frame;
}
