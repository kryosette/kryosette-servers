#pragma once 
#ifndef LLC_H
#define LLC_H

#include <stdint.h>
#include <stddef.h>

#define DSAP_SNAP 0xAA
#define SSAP_SNAP 0xAA
#define CTRL_UNNUMBERED 0x03
#define ETH_P_IP 0x0800 // Ethernet type для IPv4

#define LLC_FRAME_SIZE(ip_len) (sizeof(llc_header_t) + sizeof(snap_header_t) + (ip_len))

#ifndef LLC_ENABLE_LOGGING
#define LLC_ENABLE_LOGGING 0
#endif

#if LLC_ENABLE_LOGGING
    typedef void (*llc_logger_cb_t)(const char *msg);
    extern llc_logger_cb_t llc_log_message;
    #define LLC_LOG(msg) do { if (llc_log_message != NULL) llc_log_message(msg); } while (0)
#else
    #define LLC_LOG(msg)
#endif

typedef struct {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t control;
} __attribute__((packed)) llc_header_t;

typedef struct {
    uint8_t oui[3];
    uint16_t pid;
} __attribute__((packed)) snap_header_t;

uint8_t* llc_encapsulate_ip(const uint8_t *ip_packet, size_t ip_len);

void llc_receive_ip(uint8_t *ip_packet, size_t len);

#endif 
