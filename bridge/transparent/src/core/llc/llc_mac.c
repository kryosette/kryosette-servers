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
  if (data_len > ETH_MTU) {
      return false;
  }

  if (!tx_callback) {
      return false;
  }

  eth_frame_t frame; 

  mac_addr_copy(frame.header.dst_addr, dst_addr);
  mac_addr_copy(frame.header.src_addr, mac_my_address); 
  frame.header.ethertype = htons(ethertype);

  memcpy(frame.payload, data, data_len);

  size_t total_frame_len = sizeof(eth_header_t) + data_len + ETH_FCS_LEN;
  if (total_frame_len < ETH_MIN_FRAME_LEN) {
      size_t padding_len = ETH_MIN_FRAME_LEN - total_frame_len;
      memset(frame.payload + data_len, 0, padding_len);
      data_len += padding_len; 
  }

  mac_update_fcs(&frame);

  statistics.tx_frames++;
  statistics.tx_bytes += data_len; 

  current_state = MAC_STATE_SENDING;
  bool success = tx_callback((uint8_t*)&frame, sizeof(eth_header_t) + data_len + ETH_FCS_LEN);
  current_state = MAC_STATE_IDLE;

  return success;
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
  if (frame_len < ETH_MIN_RX_FRAME_LEN) {
     statistics->rx_errors++;
     return;
  }

  current_state = MAC_STATE_RECEIVING;
  const eth_frame_t *frame = (const eth_frame_t)*frame_data;

  if (!mac_addr_equal(frame->header.dst_addr, mac_my_address) &&
        !mac_addr_is_broadcast(frame->header.dst_addr) &&
        !mac_addr_is_multicast(frame->header.dst_addr)) { // Let's add multicast just in case
        current_state = MAC_STATE_IDLE;
        return;
  }

  uint8_t *calc_frame = malloc(frame_len);
  if (calc_frame == NULL) {
        current_state = MAC_STATE_IDLE;
        return;
    }
  memcpy(calc_frame, frame_data, frame_len);
  
  uint32_t received_fcs = *((uint32_t *)(calc_frame + frame_len - ETH_FCS_LEN));
  *((uint32_t *) (calc_frame + frame_len - ETH_FCS_LEN)) = 0;

  uint32_t calculated_fcs = crc32_calculate(calc_frame, frame_len);
  free(calc_frame);
  
  if (received_fcs != calculated_fcs) {
      statistics.rx_errors++;
      current_state = MAC_STATE_IDLE;
      return;
  }

  statistics.rx_frames++;
  size_t payload_len = frame_len - sizeof(eth_header_t) - ETH_FCS_LEN;
  statistics.rx_bytes += payload_len;

  current_state = MAC_STATE_IDLE;
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

static uint64_t mac_to_uint64(const uint8_t *mac) {
    uint64_t result = 0;
    for (int i = 0; i < 6; i++) {
        result = (result << 8) | mac[i];
    }
    return result;
}

mac_table_t* mac_table_create(size_t size) {
    mac_table_t *table = malloc(sizeof(mac_table_t));
    table->size = size;
    table->count = 0;
    table->buckets = calloc(size, sizeof(mac_table_entry_t*)); // Инициализируем нулями
    return table;
}

void mac_table_destroy(mac_table_t *table) {
    for (size_t i = 0; i < table->size; i++) {
        mac_table_entry_t *entry = table->buckets[i];
        while (entry != NULL) {
            mac_table_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
    }
    free(table->buckets);
    free(table);
}

void mac_table_learn(mac_table_t *table, const uint8_t *mac, int port_index) {
    uint64_t mac_key = mac_to_uint64(mac);
    size_t index = mac_key % table->size; // Простая хэш-функция

    mac_table_entry_t *entry = table->buckets[index];
    mac_table_entry_t *prev = NULL;
    
    while (entry != NULL) {
        if (entry->mac == mac_key) {
            entry->port_index = port_index;
            entry->last_seen = time(NULL);
            return;
        }
        prev = entry;
        entry = entry->next;
    }

    mac_table_entry_t *new_entry = malloc(sizeof(mac_table_entry_t));
    new_entry->mac = mac_key;
    new_entry->port_index = port_index;
    new_entry->last_seen = time(NULL);
    new_entry->next = NULL;

    if (prev == NULL) {
        table->buckets[index] = new_entry;
    } else {
        prev->next = new_entry;
    }
    table->count++;
}

int mac_table_lookup(mac_table_t *table, const uint8_t *mac) {
    uint64_t mac_key = mac_to_uint64(mac);
    size_t index = mac_key % table->size;
    
    mac_table_entry_t *entry = table->buckets[index];
    while (entry != NULL) {
        if (entry->mac == mac_key) {
            return entry->port_index; // Нашли!
        }
        entry = entry->next;
    }
    return -1; 
}

void mac_table_ageing(mac_table_t *table) {
    time_t now = time(NULL);
    
    for (size_t i = 0; i < table->size; i++) {
        mac_table_entry_t **ptr = &table->buckets[i];
        while (*ptr != NULL) {
            if (now - (*ptr)->last_seen > MAC_AGEING_TIME) {
                // Удаляем запись
                mac_table_entry_t *to_free = *ptr;
                *ptr = to_free->next;
                free(to_free);
                table->count--;
            } else {
                ptr = &(*ptr)->next;
            }
        }
    }
}
