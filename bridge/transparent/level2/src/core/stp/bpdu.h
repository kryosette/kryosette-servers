
struct bpdu_header {
    uint16_t protocol_id;     // Всегда 0x0000
    uint8_t  version;         // 0x00 для STP, 0x02 для RSTP
    uint8_t  bpdu_type;       // 0x00 Config, 0x80 TCN
    uint8_t  flags;           // Флаги TC, TCA
    uint64_t root_bridge_id;  // Root Bridge ID
    uint32_t root_path_cost;  // Стоимость пути до корня
    uint64_t bridge_id;       // Bridge ID отправителя
    uint16_t port_id;         // Port ID отправителя
    uint16_t message_age;     // Возраст сообщения
    uint16_t max_age;         // Max Age (20 сек)
    uint16_t hello_time;      // Hello Time (2 сек)
    uint16_t forward_delay;   // Forward Delay (15 сек)
} __attribute__((packed));
