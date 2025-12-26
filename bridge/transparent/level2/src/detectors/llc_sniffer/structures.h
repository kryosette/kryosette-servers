#pragma once

#include <stdint.h>
#include <time.h>

#pragma pack(push, 1) 

// WARNING! REMOVE ALL TYPEDEF

typedef struct {
    uint32_t magic; // Магическое число: 0x4C4C4321 ("LLC!")
    uint16_t version; // Версия формата: 1
    uint64_t timestamp; // Время создания файла (unixtime наносекунды)
    uint32_t num_packets; // Количество пакетов (заполняется позже)
    uint8_t os_type; // 0=Linux, 1=macOS
    uint8_t reserved[15]; // Зарезервировано
} BinFileHeader;

// for LLC
/*
Link Service Access Point (LSAP) includes both Destination Service Access Point (DSAP) and Source Service Access Point (SSAP). 
It enables a MAC station to communicate with upper layers via different protocols. Standard Network layer protocols have been assigned reserved LLC addresses, as recorded in ISO/IEC TR 11802-1.
*/
typedef struct {
    uint64_t timestamp_ns; // Время захвата (наносекунды)
    uint32_t packet_len; // Длина всего пакета
    uint32_t llc_offset; // Смещение LLC данных от начала пакета
    uint16_t interface_idx; // Индекс интерфейса
    uint8_t dsap; // LLC DSAP
    uint8_t ssap; // LLC SSAP
    uint8_t control; // LLC Control
    uint8_t protocol_type; // Определенный протокол (см. ниже)
    uint8_t flags; // Флаги
    uint8_t reserved[2]; // Выравнивание
} PacketHeader;

typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_IP = 1,
    PROTO_ARP = 2,
    PROTO_IPX = 3,
    PROTO_NETBEUI = 4,
    PROTO_SNAP = 5,
    PROTO_STP = 6,
    PROTO_LLDP = 7,
    PROTO_EAPOL = 8, // 802.1X
    PROTO_LACP = 9,
    PROTO_CDP = 10, // Cisco Discovery
    PROTO_LOOP = 11, // Loopback
    PROTO_ISIS = 12, // ISIS over LLC
    PROTO_CUSTOM = 255
} ProtocolType;

typedef struct {
    uint8_t oui[3]; // Organizationally Unique Identifier
    uint16_t pid; // Protocol ID
} SNAPHeader;

typedef struct {
    uint64_t total_packets;
    uint64_t llc_packets;
    uint64_t snap_packets;
    uint64_t by_protocol[256]; // Статистика по протоколам
    uint64_t by_dsap[256]; // Статистика по DSAP
    uint64_t start_time;
    uint64_t end_time;
} LLCStatistics;

#pragma pack(pop) // Возвращаем обычное выравнивание