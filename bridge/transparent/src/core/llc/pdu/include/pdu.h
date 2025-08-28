#include "llc.h"
#include "forwarding.h"

extern int llc_sap_get_handler(lsap_t sap, llc_sap_handler_fn *handler);

void llc_receive_frame(port_id_t port, const uint8_t *frame_data, size_t frame_len)
{
    llc_parsed_pdu_t pdu;
    int parse_result = llc_pdu_parse(frame_data, frame_len, &pdu);

    if (parse_result != 0)
    {
        return;
    }

    llc_sap_handler_fn handler = NULL;
}