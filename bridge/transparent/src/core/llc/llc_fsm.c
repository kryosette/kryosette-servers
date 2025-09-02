#include 

static void _send_dm_response(const uint8_t *dest_mac, uint8_t dsap, uint8_t ssap) {
    llc_send_unnumbered_frame(dest_mac, dsap, ssap, LLC_DM, NULL, 0);
}

static void _send_ua_response(const uint8_t *dest_mac, uint8_t dsap, uint8_t ssap) {
    llc_send_unnumbered_frame(dest_mac, dsap, ssap, LLC_UA, NULL, 0);
}

void llc_fsm_process_pdu(llc_connection_t *conn, uint8_t dsap, uint8_t ssap, uint8_t control, const uint8_t *info, uint16_t info_len) {
  if (conn == NULL) return 0;

  llc_state_t old_state = conn->fsm_state;

  
}
