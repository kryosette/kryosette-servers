#include "llc_types.h"

llc_state_t llc_type2_state_machine(llc_connection_t *conn, uint8_t *received_pdu)
{
    // improve
    if (conn == NULL || received_pdu == NULL)
    {
        return LLC_STATE_DISCONNECTED;
    }
}