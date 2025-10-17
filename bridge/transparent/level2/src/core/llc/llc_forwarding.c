#include "llc_forwarding.h"

static port_state_t curr_state = PORT_STATE_LEARNING;
static bridge_port_t num_ports =
    static uint8_t curr_port =
        static bridge_t num_ports = NULL;

void bridge_init(bridge_t *bridge, bridge_port_t *ports, size_t num_ports)
{
    if (bridge == NULL || ports == NULL || num_ports == 0)
    {
        return;
    }

    bridge_port_t *new_ports = (bridge_port_t *)malloc(sizeof(bridge_port_t) * num_ports);
    if (new_ports == NULL)
    {
        return;
    }

    memcpy(new_ports, ports, sizeof(bridge_port_t) * num_ports);

    bridge->ports = new_ports;
    bridge->num_ports = num_ports;

    for (size_t i = 0; i < num_ports; i++)
    {
        bridge->ports[i].state = PORT_STATE_LEARNING;
    }
}

void bridge_destroy(bridge_t *bridge)
{
    if (bridge == NULL)
    {
        return;
    }
    free(bridge->ports);
    bridge->ports = NULL;
    bridge->num_ports = 0;
}

// improve
void bridge_forward_frame(bridge_t *bridge,
                          const uint8_t *frame_data,
                          size_t frame_len,
                          const uint8_t *src_mac,
                          int incoming_port_index)
{
    if (bridge == NULL)
    {
        return;
    }
    const uint8_t *dest_mac = frame_data;
    const uint8_t *src_mac = frame_data + 6;

    mac_table_learn(bridge->mac_table, src_mac, incoming_port_index);
    forwarding_decision_t decision;
    int out_port_index;

    if (mac_is_broadcast(dest_mac))
    {
        decision = FLOOD;
    }
    else if (mac_is_our(dest_mac, bridge->ports, bridge->num_ports))
    {
        decision = FWD_LOCAL;
    }
    else
    {
        out_port_index = mac_table_lookup(bridge->mac_table, dest_mac);
        if (out_port_index != -1)
        {
            if (out_port_index == incoming_port_index)
            {
                decision = DROP;
            }
            else
            {
                decision = FWD_TO_PORT;
            }
        }
        else
        {
            decision = FLOOD;
        }
    }

    switch (decision)
    {
    case FLOOD:
        break;
    case FWD_TO_PORT:
        bridge_send_frame_on_port(&bridge->ports[out_port_index], frame_data, frame_len);
        break;
    case FWD_LOCAL:
        // Передать кадр наверх (сложно, можно заглушить)
        break;
    case DROP:
    default:
        break;
    }
}

void process_frame(const uint8_t *frame_data,
                   size_t frame_len,
                   const uint8_t *src_mac,
                   int incoming_port_index)
{
    if (frame_len < ETH_MIN_RX_FRAME_LEN)
    {
        statistics.rx_errors++;
        return;
    }

    if (!crc_check_is_ok(frame_data, frame_len))
    {
        statistics.crc_errors++;
        return;
    }

    const uint8_t *dest_mac = &frame_data[0];
    const uint8_t *src_mac = &frame_data[6];

    statistics.rx_frames++;
    statistics.rx_bytes += frame_len;

    bridge_forward_frame(bridge, frame_data, frame_len, src_mac, incoming_port_index);
}
