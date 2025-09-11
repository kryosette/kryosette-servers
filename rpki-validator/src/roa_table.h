#pragma once
#ifndef ROA_TABLE_H
#define ROA_TABLE_H

#include <stdint.h>
#include <netinet/in.h>
#include <time.h>

typedef enum {
    ROA_IPv4 = 4,
    ROA_IPv6 = 6
} roa_address_family_t;

typedef struct ip_addr_block {
    roa_address_family_t address_family; // addressFamily (OCTET STRING в RFC)
    union {
        struct in_addr v4_prefix;        // IPv4 префикс
        struct in6_addr v6_prefix;       // IPv6 префикс
    } prefix;
    uint8_t prefix_length;               // Длина маски префикса
    uint8_t max_prefix_length;           // maxLength (INTEGER в RFC)
    
    struct ip_addr_block *next;          // Для linked list блоков
} ip_addr_block_t;

typedef struct {
    uint32_t asn;                   // ASN
    uint8_t prefix_len;             // Длина префикса
    uint8_t max_prefix_len;         // Максимальная длина
    time_t created_at;              // Время создания записи
    time_t valid_until;             // Время истечения валидности
    uint32_t flags;                 // Флаги (например, VALID/INVALID)
} roa_common_info_t;

typedef struct roa {
    uint32_t asn;                       // asID (OCTET STRING в RFC)
    ip_addr_block_t *ip_addr_blocks;    // ipAddrBlocks (SEQUENCE OF) ← ВМЕСТО ПРЕФИКСА
    
    time_t created_at;
    time_t valid_until;
    char *source_uri;
    
    struct roa *next;
} roa_t;

typedef union {
    struct in_addr v4;              // IPv4 адрес
    struct in6_addr v6;             // IPv6 адрес
} ip_prefix_t;

typedef struct roa_entry {
    roa_address_family_t family;    // Семейство адресов
    ip_prefix_t prefix;             // Префикс (union)
    roa_common_info_t info;         // Общая информация
    
    char *source;                   // Источник данных (например, URL)
    struct roa_entry *next;         // Для linked list
} roa_entry_t;

typedef struct {
    roa_entry_t *entries;           // Массив записей
    size_t count;                   // Количество записей
    size_t capacity;                // Емкость массива
    
    uint32_t ipv4_count;
    uint32_t ipv6_count;
    uint32_t total_asns;
    
    int (*add_entry)(struct roa_table*, const roa_entry_t*);
    const roa_entry_t* (*find_entry)(const struct roa_table*, const char*, uint8_t, uint32_t);
} roa_table_t;

#define ROA_FLAG_VALID      0x01
#define ROA_FLAG_INVALID    0x02
#define ROA_FLAG_EXPIRED    0x04

int roa_table_init(roa_table_t *table);
int roa_table_add(roa_table_t *table, const char *ip_prefix, uint8_t prefix_len, 
                 uint8_t max_prefix_len, uint32_t asn, const char *source);
const roa_entry_t *roa_table_find(const roa_table_t *table, const char *prefix_str, 
                                 uint8_t prefix_len, uint32_t asn);
void roa_table_cleanup(roa_table_t *table);
void roa_table_print_stats(const roa_table_t *table);

const char *roa_family_to_str(roa_address_family_t family);
int roa_validate_prefix_length(uint8_t prefix_len, roa_address_family_t family);

#endif
