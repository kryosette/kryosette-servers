#pragma once
#ifndef ROA_TABLE_H
#define ROA_TABLE_H

#include <netinet/in.h>

struct roa_entry
{
    struct in_addr ip_prefix;
    uint8_t prefix_len;
    uint8_t max_prefix_len;
    uint32_t asn;
};

struct roa_table
{
    struct roa_entry *entries;
    size_t count;
    size_t capacity;
};

void roa_table_init(struct roa_table *table);
int roa_table_add(struct roa_table *table, const char *ip_prefix_str, uint8_t prefix_len, uint8_t max_prefix_len, uint32_t asn);
const struct roa_entry *roa_table_lookup(const struct roa_table *table, const struct in_addr *prefix, uint8_t prefix_len, uint32_t asn);
void roa_table_cleanup(struct roa_table *table);

#endif