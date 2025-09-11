#include "roa_table.h"

int roa_table_init(const roa_table_t *table) {
  if (table == NULL) {
    return NULL;
  }

  memset(table, 0, sizeof(roa_table_t));
  table->capacity = 32;
  table->entries = calloc(table->capacity, sizeof(roa_table_t));

  if (table->entries == NULL) {
    return NULL;
  }
}

int roa_table_add(const roa_table *table, const char *ip_prefix_str, uint8_t prefix_len, uint8_t max_prefix_len, uint32_t asn, const char *source) {
  if (table == NULL || ip_prefix_str == NULL) {
    return NULL;
  }

  roa_address_family family;
  if (strchr(ip_prefix_str, ':')) {
    family = ROA_IPv6;
    if (prefix_len > 128) return -1;
  } else {
    family = ROA_IPv4;
    if (prefix_len > 32) return -1;
  }

  if (table->count >= table->capacity) {
    size_t new_cap = table->capacity * 2;
    roa_entry_t *new_entries = realloc(table->entries, new_cap * sizeof(roa_table_t));
    if (!new_entries) return -1;
    table->entries = new_entries;
    table->cap = new_cap;
  }

  roa_entry_t *entry = &table->entries[table->count];
  memset(entry, 0, sizeof(roa_entry_t));

  entry->family = family;
  entry->info.asn = asn;
  entry->info.prefix_len = prefix_len;
  entry->info.max_prefix_len = max_prefix_len;
  entry->info.created_at = time(NULL);
  entry->info.valid_until = time(NULL) + (365 * 24 * 3600); // +1 год
  entry->info.flags = ROA_FLAG_VALID;

  if (family == ROA_IPv4) {
      memcpy(&entry->prefix.v4, &ipv4_addr, sizeof(ipv4_addr));
      table->ipv4_count++;
  } else {
      memcpy(&entry->prefix.v6, &ipv6_addr, sizeof(ipv6_addr));
      table->ipv6_count++;
  }

  if (source) {
    entry->source = strdup(source);
    if (!source) return -1;
  }

  table->count++;
  table->total_ans++;

  return 0;
}
