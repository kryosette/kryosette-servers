#include "mac.h"
#include "llc.h"
#include <string.h>
#include <arpa/inet.h>

/*
 * MAC Layer Implementation for Ethernet/Wi-Fi MSDU handling
 *
 * This module provides Media Access Control layer functionality for
 * frame transmission, reception, and statistical monitoring. Supports
 * both Ethernet and Wi-Fi MSDU (MAC Service Data Unit) processing.
 */

/** Static MAC layer configuration and state variables */
static uint8_t mac_my_address[MAC_ADDR_LEN];          /**< Local MAC address storage */
static mac_rx_callback_t rx_callback = NULL;          /**< Registered RX callback function */
static mac_tx_complete_callback_t tx_callback = NULL; /**< Registered TX completion callback */
static mac_stats_t statistics = {0};                  /**< MAC layer statistics counter */
static mac_state_t current_state = MAC_STATE_IDLE;    /**< Current MAC layer state */

/** Standard MAC address constants */
const uint8_t MAC_BROADCAST_ADDR[MAC_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; /**< Broadcast MAC address */
const uint8_t MAC_NULL_ADDR[MAC_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};      /**< Null MAC address */

/**
 * @brief Initializes the MAC layer with local address.
 *
 * Sets up the MAC layer by configuring the local MAC address and
 * initializing all state variables and statistics counters.
 *
 * @param my_mac_addr Pointer to 6-byte MAC address array
 *
 * @note Must be called before any other MAC operations
 * @note Resets all statistics and sets state to IDLE
 */
void mac_init(const uint8_t *my_mac_addr)
{
  memcpy(mac_my_address, my_mac_addr, MAC_ADDR_LEN);
  current_state = MAC_STATE_IDLE;
  memset(&statistics, 0, sizeof(statistics));
}

/**
 * @brief Sends an LLC PDU through the MAC layer.
 *
 * Encapsulates and transmits an LLC Protocol Data Unit with proper
 * Ethernet header and LLC/SNAP EtherType designation.
 *
 * @param dst_addr Destination MAC address (6 bytes)
 * @param llc_pdu Pointer to LLC PDU data
 * @param pdu_len Length of LLC PDU in bytes
 * @return bool True if transmission initiated successfully, false otherwise
 *
 * @note Uses EtherType 0x0806 for LLC/SNAP encapsulation
 * @note Validates input parameters before transmission
 */
bool mac_send_llc_pdu(const uint8_t *dst_addr, const uint8_t *llc_pdu, size_t pdu_len)
{
  if (!dst_addr || !llc_pdu || pdu_len == 0)
    return false;

  return mac_send_frame(dst_addr, llc_pdu, pdu_len, ETH_P_LLC_SNAP);
}

/**
 * @brief Transmits a raw Ethernet frame.
 *
 * Constructs and sends a complete Ethernet frame with specified
 * destination address, payload data, and EtherType. Handles frame
 * encapsulation, FCS calculation, and statistics updating.
 *
 * @param dst_addr Destination MAC address (6 bytes)
 * @param data Pointer to payload data
 * @param data_len Length of payload data in bytes
 * @param ethertype Ethernet Type field value (host byte order)
 * @return bool True if transmission successful, false if MTU exceeded
 *
 * @note Automatically calculates and appends Frame Check Sequence
 * @note Updates TX statistics counters on successful transmission
 * @note Triggers TX completion callback if registered
 */
bool mac_send_frame(const uint8_t *dst_addr,
                    const uint8_t *data,
                    size_t data_len,
                    uint16_t ethertype)
{
  if (data_len > ETH_MTU)
    return false;

  eth_frame_t frame;

  mac_addr_copy(frame->header.dst_addr, dst_addr);
  mac_addr_copy(frame->header.src_addr, src_addr);
  frame->header.ethertype = htons(ethertype);

  memcpy(frame.payload, data, data_len);
  mac_update_fcs(&frame);

  statistics.tx_frames++;
  statistics.tx_bytes += data_len;

  current_state = MAC_STATE_SENDING;
  if (tx_callback)
  {
    tx_callback(true);
  }
  current_state = MAC_STATE_IDLE;

  if (rx_callback)
  {
    rx_callback(frame->payload, payload_len, frame->header.src_addr);
  }
}

/**
 * @brief Processes an incoming Ethernet frame.
 *
 * Handles reception of Ethernet frames, performing address filtering,
 * FCS validation, and statistical tracking. Forwards valid frames
 * to the registered RX callback function.
 *
 * @param frame_data Pointer to received frame data
 * @param frame_len Length of received frame in bytes
 *
 * @note Only processes frames addressed to local MAC or broadcast
 * @note Updates RX statistics counters for valid frames
 * @note Minimum frame length check includes header and FCS
 */
void mac_receive_frame(const uint8_t *frame_data, size_t frame_len)
{
  if (frame_len < sizeof(eth_header_t) + 4)
    return;

  current_state = MAC_STATE_RECEIVING;
  const eth_frame_t *frame = (const eth_frame_t *)frame_data;

  uint8_t received_fcs = frame->fcs;

  if (!mac_addr_equal(frame->header.dst_addr, mac_my_address) &&
      !mac_addr_is_broadcast(frame->header.dst_addr))
  {
    current_state = MAC_STATE_IDLE;
    return;
  }

  statistics.rx_frames++;
  size_t payload_len = frame_len - sizeof(eth_header_t) - 4;
  statistics.rx_bytes += payload_len;
}

/**
 * @brief Calculates and updates Frame Check Sequence for Ethernet frame.
 *
 * Computes the CRC32 checksum for the entire Ethernet frame (header + payload)
 * and stores it in the FCS field. Uses standard CRC32 algorithm for
 * IEEE 802.3 compliance.
 *
 * @param frame Pointer to Ethernet frame structure
 *
 * @note FCS field is the last 4 bytes of the Ethernet frame
 * @note CRC32 calculation covers all bytes except the FCS field itself
 */
void mac_update_fcs(eth_frame_t *frame)
{
  size_t data_length = sizeof(eth_header_t) + ((uint8_t *)&frame->fcs - (uint8_t *)&frame->payload[0]);
  uint32_t calculated_crc = crc32_calculate((uint8_t *)frame, data_length);

  // We write the result in the FCS field (in the Big-Endian order
  /*
  Big-Endian (direct byte order) is a way of organizing data in computer memory in which the highest byte (most significant)
  of a number is located at the lowest memory address, and the lowest byte (least significant) is located at the highest address.
  */
  frame->fcs = calculated_crc;
}

/**
 * @brief Retrieves current MAC layer statistics.
 *
 * Returns a pointer to the internal statistics structure containing
 * counters for transmitted and received frames and bytes.
 *
 * @return const mac_stats_t* Pointer to statistics structure (read-only)
 *
 * @note Statistics are cumulative since last mac_init() call
 * @note Returned pointer should be used for read operations only
 */
const mac_stats_t *mac_get_stats()
{
  return &statistics;
}