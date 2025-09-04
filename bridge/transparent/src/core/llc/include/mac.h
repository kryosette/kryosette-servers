#pragma once
#ifndef MAC_H
#define MAC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define MAC_ADDR_LEN 6          // Длина MAC-адреса
#define ETH_MTU 1500            // Maximum Transmission Unit
#define ETH_MIN_FRAME_LEN 64    // Минимальный размер кадра (с преамбулой)
#define ETH_MAX_FRAME_LEN 1518  // Максимальный размер кадра (с преамбулой)

#define ETH_P_LLC_SNAP 0x8870   // LLC/SNAP инкапсуляция
#define ETH_P_IP       0x0800   // IPv4
#define ETH_P_ARP      0x0806   // ARP
#define ETH_P_IPV6     0x86DD   // IPv6

#define ETH_MIN_FRAME_LEN      64    // Минимальная длина кадра от Преамбулы до FCS включительно (по стандарту)
#define ETH_MIN_PAYLOAD_LEN    46   
#define ETH_FCS_LEN            4    

#define ETH_MIN_RX_FRAME_LEN   (sizeof(eth_header_t) + ETH_MIN_PAYLOAD_LEN + ETH_FCS_LEN)

extern const uint8_t MAC_BROADCAST_ADDR[MAC_ADDR_LEN]; // FF:FF:FF:FF:FF:FF
extern const uint8_t MAC_NULL_ADDR[MAC_ADDR_LEN];      // 00:00:00:00:00:00

#pragma pack(push, 1)

typedef struct {
    uint8_t dst_addr[MAC_ADDR_LEN];  
    uint8_t src_addr[MAC_ADDR_LEN];  
    uint16_t ethertype;              
} eth_header_t;

typedef struct {
    eth_header_t header;    
    uint8_t payload[ETH_MTU];
    uint32_t fcs;            
} eth_frame_t;

#pragma pack(pop)

typedef enum {
    MAC_STATE_IDLE,          
    MAC_STATE_SENDING,      
    MAC_STATE_RECEIVING,     
    MAC_STATE_ERROR          
} mac_state_t;

typedef struct {
    uint32_t tx_frames;      
    uint32_t rx_frames;      
    uint32_t tx_bytes;       
    uint32_t rx_bytes;       
    uint32_t crc_errors;     
    uint32_t collisions;     
    uint64_t rx_errors;
    uint64_t tx_errors;
} mac_stats_t;

typedef void (*mac_rx_callback_t)(const uint8_t* data, size_t len, const uint8_t* src_addr);
typedef void (*mac_tx_complete_callback_t)(bool success);


void mac_init(const uint8_t* my_mac_addr);

void mac_set_rx_callback(mac_rx_callback_t callback);
void mac_set_tx_complete_callback(mac_tx_complete_callback_t callback);

bool mac_send_frame(const uint8_t* dst_addr, 
                   const uint8_t* data, 
                   size_t data_len,
                   uint16_t ethertype);

bool mac_send_llc_pdu(const uint8_t* dst_addr, const uint8_t* llc_pdu, size_t pdu_len);

void mac_receive_frame(const uint8_t* frame_data, size_t frame_len);

void mac_get_address(uint8_t* buffer); // Получить свой MAC
const mac_stats_t* mac_get_stats();    // Получить статистику
void mac_update_fcs(eth_frame_t* frame); // Обновить FCS

bool mac_addr_equal(const uint8_t* addr1, const uint8_t* addr2);
bool mac_addr_is_broadcast(const uint8_t* addr);
bool mac_addr_is_multicast(const uint8_t* addr);
void mac_addr_copy(uint8_t* dst, const uint8_t* src);

#endif // MAC_H
