#pragma once
#ifndef LLDP_H
#define LLDP_H

#include <stdint.h>
#include <stddef.h>

/*
 * LLDP (Link Layer Discovery Protocol) - IEEE 802.1AB
 * Протокол для обнаружения соседних устройств в сети
 */
/*
+--------------------------------------------------------------------------------+
|                          LLDP Agent                                           |
|                                                                                |
| +-----------------------------------+    +-----------------------------------+ |
| | Organizationally Defined          |    | Organizationally Defined          | |
| | Local Device LLDP MIB             |    | Remote Device LLDP MIB            | |
| | Extensions (Optional)             |    | Extensions (Optional)             | |
| +-----------------------------------+    +-----------------------------------+ |
|                                                                                |
| +-----------------------------------+    +-----------------------------------+ |
| |        LLDP Local System MIB      |    |       LLDP Remote Systems MIB     | |
| +-----------------------------------+    +-----------------------------------+ |
|                                                                                |
| +---------------------------------------------------------------------------+ |
| |               LLDPDU Transmission and Reception                           | |
| +---------------------------------------------------------------------------+ |
|                                                                                |
| +---------------------------------------------------------------------------+ |
| |                            LLDP Frames                                    | |
| +---------------------------------------------------------------------------+ |
|                                                                                |
+--------------------------------------------------------------------------------+
          ʌ                                 ʌ
          |                                 |
          |                                 |
+-------------------+             +-------------------+
| Local Device      |             | Remote Device     |
| Information       |             | Information       |
+-------------------+             +-------------------+

          ʌ                                 ʌ
          |                                 |
+--------------------------------------------------------------------------------+
|                          LLC Entity                                           |
+--------------------------------------------------------------------------------+
*/
/* LLDP Destination MAC Address */
#define LLDP_MULTICAST_ADDR {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E}

/* Ethernet Type for LLDP */
#define ETHERTYPE_LLDP 0x88CC

/* LLDP TLV Types */
typedef enum
{
    LLDP_TLV_END = 0,
    LLDP_TLV_CHASSIS_ID = 1,
    LLDP_TLV_PORT_ID = 2,
    LLDP_TLV_TTL = 3,
    LLDP_TLV_PORT_DESCRIPTION = 4,
    LLDP_TLV_SYSTEM_NAME = 5,
    LLDP_TLV_SYSTEM_DESCRIPTION = 6,
    LLDP_TLV_SYSTEM_CAPABILITIES = 7,
    LLDP_TLV_MANAGEMENT_ADDRESS = 8,
    LLDP_TLV_ORG_SPECIFIC = 127
} lldp_tlv_type_t;

/* LLDP Chassis ID Subtypes */
typedef enum
{
    LLDP_CHASSIS_RESERVED = 0,
    LLDP_CHASSIS_CHASSIS_COMPONENT = 1,
    LLDP_CHASSIS_INTERFACE_ALIAS = 2,
    LLDP_CHASSIS_PORT_COMPONENT = 3,
    LLDP_CHASSIS_MAC_ADDRESS = 4,
    LLDP_CHASSIS_NETWORK_ADDRESS = 5,
    LLDP_CHASSIS_INTERFACE_NAME = 6,
    LLDP_CHASSIS_LOCALLY_ASSIGNED = 7
} lldp_chassis_subtype_t;

/* LLDP Port ID Subtypes */
typedef enum
{
    LLDP_PORT_RESERVED = 0,
    LLDP_PORT_INTERFACE_ALIAS = 1,
    LLDP_PORT_PORT_COMPONENT = 2,
    LLDP_PORT_MAC_ADDRESS = 3,
    LLDP_PORT_NETWORK_ADDRESS = 4,
    LLDP_PORT_INTERFACE_NAME = 5,
    LLDP_PORT_AGENT_CIRCUIT_ID = 6,
    LLDP_PORT_LOCALLY_ASSIGNED = 7
} lldp_port_subtype_t;

/* System Capabilities Bitmask */
typedef enum
{
    LLDP_CAP_OTHER = (1 << 0),
    LLDP_CAP_REPEATER = (1 << 1),
    LLDP_CAP_BRIDGE = (1 << 2),
    LLDP_CAP_AP = (1 << 3), /* Access Point */
    LLDP_CAP_ROUTER = (1 << 4),
    LLDP_CAP_TELEPHONE = (1 << 5),
    LLDP_CAP_DOCSIS = (1 << 6),
    LLDP_CAP_STATION = (1 << 7),
    LLDP_CAP_CVLAN = (1 << 8),
    LLDP_CAP_SVLAN = (1 << 9),
    LLDP_CAP_TPMR = (1 << 10) /* Two-port MAC Relay */
} lldp_system_capabilities_t;

/* LLDP TLV Header Structure */
typedef struct __attribute__((packed))
{
    uint16_t type_length; /* Bits 15-13: Type, Bits 12-0: Length */
} lldp_tlv_header_t;

#define LLDP_TLV_TYPE_MASK 0xFE00
#define LLDP_TLV_LENGTH_MASK 0x01FF
#define LLDP_TLV_TYPE_SHIFT 9

/* LLDP Basic TLV Structure */
typedef struct __attribute__((packed))
{
    lldp_tlv_header_t header;
    uint8_t value[]; /* Variable length value */
} lldp_tlv_t;

/* Chassis ID TLV */
typedef struct __attribute__((packed))
{
    lldp_tlv_header_t header;
    uint8_t subtype;
    uint8_t id[]; /* Chassis ID value */
} lldp_chassis_id_tlv_t;

/* Port ID TLV */
typedef struct __attribute__((packed))
{
    lldp_tlv_header_t header;
    uint8_t subtype;
    uint8_t id[]; /* Port ID value */
} lldp_port_id_tlv_t;

/* Time To Live TLV */
typedef struct __attribute__((packed))
{
    lldp_tlv_header_t header;
    uint16_t ttl; /* Time to live in seconds */
} lldp_ttl_tlv_t;

/* System Capabilities TLV */
typedef struct __attribute__((packed))
{
    lldp_tlv_header_t header;
    uint16_t capabilities;
    uint16_t enabled_capabilities;
} lldp_system_capabilities_tlv_t;

/* Management Address TLV Structure */
typedef struct __attribute__((packed))
{
    uint8_t address_length;
    uint8_t address_subtype; /* 1 = IPv4, 2 = IPv6 */
    uint8_t address[16];     /* Max IPv6 address size */
    uint8_t interface_subtype;
    uint32_t interface_number;
    uint8_t oid_length;
    uint8_t oid[]; /* Object Identifier */
} lldp_management_address_t;

/* Organizationally Specific TLV */
typedef struct __attribute__((packed))
{
    lldp_tlv_header_t header;
    uint8_t oui[3]; /* Organizationally Unique Identifier */
    uint8_t subtype;
    uint8_t info[]; /* Organization specific information */
} lldp_org_specific_tlv_t;

/* Complete LLDP Packet Structure */
typedef struct __attribute__((packed))
{
    /* Mandatory TLVs in order: */
    lldp_chassis_id_tlv_t chassis_id;
    lldp_port_id_tlv_t port_id;
    lldp_ttl_tlv_t ttl;
    /* Optional TLVs follow... */
    uint8_t optional_tlvs[];
} lldp_packet_t;

/* LLDP Neighbor Information Structure */
typedef struct
{
    uint8_t chassis_id[64];
    uint8_t chassis_id_subtype;
    uint8_t port_id[32];
    uint8_t port_id_subtype;
    uint16_t ttl;
    char system_name[256];
    char system_description[512];
    char port_description[256];
    uint16_t capabilities;
    uint16_t enabled_capabilities;
    uint8_t management_address[16];
    uint8_t management_address_type;
    uint32_t management_interface;
    uint64_t last_update;
    uint8_t source_mac[6];
} lldp_neighbor_t;

/* LLDP Configuration */
typedef struct
{
    uint16_t tx_interval; /* Transmission interval in seconds (default: 30) */
    uint16_t tx_hold;     /* Hold multiplier (default: 4) */
    uint16_t tx_delay;    /* Initial delay in seconds (default: 2) */
    uint8_t enabled;      /* LLDP enabled/disabled */
    uint8_t management_address[16];
    uint8_t management_address_type;
    char system_name[256];
    char system_description[512];
} lldp_config_t;

/* LLDP Statistics */
typedef struct
{
    uint32_t frames_out;
    uint32_t frames_in;
    uint32_t frames_discarded;
    uint32_t tlv_discarded;
    uint32_t tlv_unknown;
    uint32_t ageouts;
    uint32_t errors;
} lldp_stats_t;

/* LLDP Module State */
typedef struct
{
    lldp_config_t config;
    lldp_stats_t stats;
    lldp_neighbor_t neighbors[64]; /* Max neighbors */
    uint8_t neighbor_count;
    uint8_t chassis_mac[6];
    uint32_t last_tx_time;
    uint8_t tx_sequence;
} lldp_state_t;

/* Function Prototypes */

/**
 * @brief Initialize LLDP module
 * @param chassis_mac MAC address of local device
 * @param config LLDP configuration
 * @return 0 on success, -1 on error
 */
int lldp_init(const uint8_t *chassis_mac, const lldp_config_t *config);

/**
 * @brief Create LLDP packet for transmission
 * @param port_id Port identifier string
 * @param port_id_subtype Port ID subtype
 * @param buffer Output buffer for LLDP packet
 * @param buffer_size Size of output buffer
 * @return Length of created packet, -1 on error
 */
int lldp_create_packet(const char *port_id, uint8_t port_id_subtype,
                       uint8_t *buffer, size_t buffer_size);

/**
 * @brief Process received LLDP packet
 * @param packet Received LLDP packet data
 * @param packet_len Length of received packet
 * @param source_mac Source MAC address of packet
 * @return 0 on success, -1 on error
 */
int lldp_process_packet(const uint8_t *packet, size_t packet_len,
                        const uint8_t *source_mac);

/**
 * @brief Get LLDP neighbor information
 * @param neighbors Output array for neighbors
 * @param max_neighbors Maximum number of neighbors to return
 * @return Number of neighbors found
 */
int lldp_get_neighbors(lldp_neighbor_t *neighbors, size_t max_neighbors);

/**
 * @brief Age out old neighbor entries
 * @param current_time Current system time
 */
void lldp_age_neighbors(uint64_t current_time);

/**
 * @brief Get LLDP statistics
 * @return Pointer to statistics structure
 */
const lldp_stats_t *lldp_get_statistics(void);

/**
 * @brief Reset LLDP statistics
 */
void lldp_reset_statistics(void);

/**
 * @brief Deinitialize LLDP module
 */
void lldp_cleanup(void);

/* Utility Functions */

/**
 * @brief Create TLV header
 * @param type TLV type
 * @param length TLV value length
 * @return TLV header value
 */
static inline uint16_t lldp_create_tlv_header(uint8_t type, uint16_t length)
{
    return ((type & 0x7F) << 9) | (length & 0x01FF);
}

/**
 * @brief Extract type from TLV header
 * @param header TLV header
 * @return TLV type
 */
static inline uint8_t lldp_get_tlv_type(uint16_t header)
{
    return (header >> 9) & 0x7F;
}

/**
 * @brief Extract length from TLV header
 * @param header TLV header
 * @return TLV length
 */
static inline uint16_t lldp_get_tlv_length(uint16_t header)
{
    return header & 0x01FF;
}

/**
 * @brief Check if TLV is mandatory
 * @param type TLV type
 * @return 1 if mandatory, 0 if optional
 */
static inline int lldp_is_mandatory_tlv(uint8_t type)
{
    return (type >= LLDP_TLV_CHASSIS_ID && type <= LLDP_TLV_TTL);
}

#endif /* LLDP_H */