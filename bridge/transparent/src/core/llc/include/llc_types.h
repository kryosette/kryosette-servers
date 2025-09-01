#pragma once
#ifndef LLC_TYPES_H
#define LLC_TYPES_H

#define LLC_I_FRAME 0x00   // Information frame
#define LLC_RR_FRAME 0x01  // Receive Ready
#define LLC_RNR_FRAME 0x05 // Receive Not Ready
#define LLC_REJ_FRAME 0x09 // Reject
#define LLC_SABME 0x6F     // Set Async Balanced Mode Extended (команда установки соединения)
#define LLC_DISC 0x43      // Disconnect (команда разрыва)
#define LLC_UA 0x63        // Unnumbered Acknowledgment (подтверждение)
#define LLC_DM 0x0F        // Disconnected Mode (ответ "я не в соединении")
#define LLC_FRMR 0x87

typedef enum
{
    LLC_STATE_DISCONNECTED, // Соединение разорвано
    LLC_STATE_SETUP,        // В процессе установки (отправили SABME, ждем UA)
    LLC_STATE_READY,        // Соединение установлено, готовы к обмену данными
    LLC_STATE_BUSY,         // Соединение есть, но мы перегружены (получили RNR)
    LLC_STATE_REJECT        // Была ошибка, требуется восстановление
} llc_state_t;

typedef struct llc_connection
{
    uint8_t remote_mac[ETH_ALEN];
    llc_state_t state;

    uint8_t v_s;
    uint8_t v_r;
    uint8_t v_a;

    int t1_timeout;
    int poll_flag;

    struct llc_connection *next;
} llc_connection_t;

#endif