#pragma once
#ifndef LLC_FSM_H
#define LLC_FSM_H

#include <stdint.h>
#include "llc_connection.h"

typedef enum {
    LLC_EVENT_SABME_CMD,
    LLC_EVENT_DISC_CMD,
    LLC_EVENT_UA_RSP,
    LLC_EVENT_DM_RSP,
    LLC_EVENT_I_CMD,
    LLC_EVENT_RR_CMD,
    LLC_EVENT_RR_RSP,
    LLC_EVENT_RNR_CMD,
    LLC_EVENT_RNR_RSP,
    LLC_EVENT_REJ_CMD,
    LLC_EVENT_REJ_RSP,
    LLC_EVENT_FRMR_RSP,
    LLC_EVENT_TIMEOUT_T1,
    LLC_EVENT_TIMEOUT_T2
} llc_event_type_t;

typedef struct {
    llc_event_type_t type;
    uint8_t dsap;
    uint8_t ssap;
    uint8_t pf_bit; 
    uint8_t nr;     
    uint8_t ns;     
    const uint8_t *info;
    uint16_t info_len;
} llc_event_t;

typedef llc_state_t (*llc_state_handler_fn)(llc_connection_t *conn, const llc_event_t *event);

void llc_fsm_register_handlers(void);

llc_state_t llc_fsm_dispatch_event(llc_connection_t *conn, const llc_event_t *event);

#endif
