#ifndef LLC_H
#define LLC_H

#include <stdint.h>
#include <stddef.h>

// Константы
#define DSAP_SNAP 0xAA
#define SSAP_SNAP 0xAA
#define CTRL_UNNUMBERED 0x03
#define ETH_P_IP 0x0800 // Ethernet type для IPv4

// Стр��ктура LLC-заголовка
typedef struct {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t control;
} __attribute__((packed)) llc_header_t;

// Структура SNAP-заголовка
typedef struct {
    uint8_t oui[3];
    uint16_t pid;
} __attribute__((packed)) snap_header_t;

// Макрос для расчета размера LLC-фрейма
#define LLC_FRAME_SIZE(ip_len) (sizeof(llc_header_t) + sizeof(snap_header_t) + (ip_len))

// Объявления функций
void llc_receive_ip(uint8_t *ip_packet, size_t len);
uint8_t* llc_encapsulate_ip(const uint8_t *ip_packet, size_t ip_len);

#endif
