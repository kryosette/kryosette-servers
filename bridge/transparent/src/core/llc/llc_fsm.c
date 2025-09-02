#include "llc_fsm.h"
#include "llc_states.h"

// improve
static void _send_dm_response(const uint8_t *dest_mac, uint8_t dsap, uint8_t ssap) {
    llc_send_unnumbered_frame(dest_mac, dsap, ssap, LLC_DM, NULL, 0);
}

static void _send_ua_response(const uint8_t *dest_mac, uint8_t dsap, uint8_t ssap) {
    llc_send_unnumbered_frame(dest_mac, dsap, ssap, LLC_UA, NULL, 0);
}

static llc_state_handler_fn state_handlers[LLC_NUM_STATES] = {NULL};

void llc_fsm_register_handlers(void) {
    state_handlers[LLC_STATE_DISCONNECTED] = llc_state_disconnected;
    state_handlers[LLC_STATE_READY] = llc_state_ready;
    state_handlers[LLC_STATE_BUSY] = llc_state_busy;
}

llc_state_t llc_fsm_dispatch_event(llc_connection_t *conn, const llc_event_t *event) {
    if (conn == NULL || event == NULL) return LLC_STATE_INVALID;

    llc_state_handler_fn handler = state_handlers[conn->fsm_state];
    if (handler == NULL) {
        return LLC_STATE_INVALID;  
    }

    return handler(conn, event);
}
