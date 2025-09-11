#pragma once
#ifndef ROA_TABLE_H
#define ROA_TABLE_H

#include <stdint.h>
#include <netinet/in.h>
#include <time.h>

typedef enum
{
    ROA_IPv4 = 4,
    ROA_IPv6 = 6
} roa_address_family_t;

typedef struct ip_addr_block
{
    roa_address_family_t address_family;
    1 union
    {
        struct in_addr v4_prefix;
        struct in6_addr v6_prefix;
    } prefix;
    uint8_t prefix_length;
    uint8_t max_prefix_length;

    struct ip_addr_block *next;
} ip_addr_block_t;

typedef struct
{
    uint32_t asn;
    uint8_t prefix_len;
    uint8_t max_prefix_len;
    time_t created_at;
    time_t valid_until;
    uint32_t flags;
} roa_common_info_t;

typedef struct roa
{
    uint32_t asn;
    ip_addr_block_t *ip_addr_blocks;

    time_t created_at;
    time_t valid_until;
    char *source_uri;

    struct roa *next;
} roa_t;

typedef union
{
    struct in_addr v4;
    struct in6_addr v6;
} ip_prefix_t;

typedef struct roa_entry
{
    roa_address_family_t family;
    ip_prefix_t prefix;
    roa_common_info_t info;

    char *source;
    struct roa_entry *next;
} roa_entry_t;

typedef struct
{
    roa_entry_t *entries;
    size_t count;
    size_t capacity;

    uint32_t ipv4_count;
    uint32_t ipv6_count;
    uint32_t total_asns;

    int (*add_entry)(struct roa_table *, const roa_entry_t *);
    const roa_entry_t *(*find_entry)(const struct roa_table *, const char *, uint8_t, uint32_t);
} roa_table_t;

#define ROA_FLAG_VALID 0x01
#define ROA_FLAG_INVALID 0x02
#define ROA_FLAG_EXPIRED 0x04

roa_table_t *roa_table_new(void);
int roa_table_add(roa_table_t *table, const char *ip_prefix, uint8_t prefix_len,
                  uint8_t max_prefix_len, uint32_t asn, const char *source);
const roa_entry_t *roa_table_find(const roa_table_t *table, const char *prefix_str,
                                  uint8_t prefix_len, uint32_t asn);
void roa_table_cleanup(roa_table_t *table);
void roa_table_print_stats(const roa_table_t *table);

const char *roa_family_to_str(roa_address_family_t family);
int roa_validate_prefix_length(uint8_t prefix_len, roa_address_family_t family);

#endif
