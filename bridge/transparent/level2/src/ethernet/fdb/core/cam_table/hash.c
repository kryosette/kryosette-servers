#include "hash.h"

uint32_t eth_mac_vlan_hash(const mac_address_t *mac, uint16_t vlan_id)
{
    if (!mac)
        return -1;

    uint32_t hash = vlan_id;

    for (int i = 0; i < MAC_ADDRESS_LENGTH; i++)
    {
        hash += mac->bytes[i];
        hash ^= hash << 13;
        hash ^= hash >> 7;
        hash ^= hash << 5;
        hash ^= hash >> 11;
        hash ^= hash << 19;
        hash ^= hash >> 3;
        hash ^= hash << 23;
        hash ^= hash >> 17;
    }

    hash = hash ^ (hash >> 16);
    hash = hash * 0x85EBCA6B;
    hash = hash ^ (hash >> 13);
    hash = hash * 0xC2B2AE35;
    hash = hash ^ (hash >> 16);

    return hash;
}

void benchmark_hash()
{
    uint64_t start = get_time_ns();

    for (int i = 0; i < 1000000; i++)
    {
        test_mac.bytes[5] = i & 0xFF; // Меняем последний байт MAC
        eth_mac_vlan_hash(&test_mac, 100);
    }

    uint64_t end = get_time_ns();
    printf("Time per hash: %ld ns\n", (end - start) / 1000000);
}
