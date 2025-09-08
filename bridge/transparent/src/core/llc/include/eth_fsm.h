
typedef enum {
    ETH_STATE_DISABLED,
    ETH_STATE_LISTENING,
    ETH_STATE_LEARNING,
    ETH_STATE_FORWARDING,
    ETH_STATE_BLOCKING
} eth_state_t;

struct eth_fsm {
    eth_state_t current_state;
    uint32_t timer;
    uint8_t mac_addr[6];
    // STP parameters
};

void eth_fsm_init(struct eth_fsm *fsm);
void eth_fsm_process_event(struct eth_fsm *fsm, eth_event_t event);
