#include "arp_cache.h"

static arp_cache_entry_t *cache = NULL;
static arp_cache_config_t *config;
static size_t curr_size = 0;

int arp_cache_init(const arp_cache_config_t *config) {
    memcpy(&config, config, sizeof(arp_cache_config_t));
    return 0;
}

void arp_cache_cleanup(void) {
    arp_cache_entry_t **curr = &cache;

    while (gettimeofday(NULL) - entry->timestamp > config->default_timeout) {

    }
}

void arp_cache_add(uint8_t *ip, uint8_t *mac, int state) {

}