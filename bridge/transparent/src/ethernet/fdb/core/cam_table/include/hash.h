#pragma once
#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <stddef.h>
#include "cam_table.h" // Для mac_address_t и других структур

#ifdef __cplusplus
extern "C"
{
#endif

    /* ===== Hash Functions for Ethernet ===== */

    /**
     * Хэш функция для MAC адреса + VLAN ID
     * @param mac MAC адрес
     * @param vlan_id VLAN ID
     * @return 32-битный хэш
     */
    uint32_t eth_mac_vlan_hash(const mac_address_t *mac, uint16_t vlan_id);

    /**
     * Хэш функция только для MAC адреса
     * @param mac MAC адрес
     * @return 32-битный хэш
     */
    uint32_t eth_mac_hash(const mac_address_t *mac);

    /**
     * Хэш функция для IPv4 адреса
     * @param ip IPv4 адрес
     * @return 32-битный хэш
     */
    uint32_t eth_ipv4_hash(ipv4_addr_t ip);

    /**
     * Хэш функция для IPv6 адреса
     * @param ip IPv6 адрес
     * @return 32-битный хэш
     */
    uint32_t eth_ipv6_hash(const ipv6_addr_t *ip);

    /**
     * Универсальная хэш функция для произвольных данных
     * @param data указатель на данные
     * @param len длина данных в байтах
     * @return 32-битный хэш
     */
    uint32_t eth_generic_hash(const void *data, size_t len);

    /**
     * Jenkins hash function (используется в Linux kernel)
     * @param data указатель на данные
     * @param len длина данных в байтах
     * @return 32-битный хэш
     */
    uint32_t jenkins_hash(const void *data, size_t len);

    /**
     * MurmurHash3 (быстрая и качественная)
     * @param data указатель на данные
     * @param len длина данных в байтах
     * @param seed seed значение
     * @return 32-битный хэш
     */
    uint32_t murmur_hash3(const void *data, size_t len, uint32_t seed);

    /* ===== Hash Table Constants ===== */

#define HASH_TABLE_DEFAULT_SIZE 1024
#define HASH_TABLE_MAX_LOAD_FACTOR 0.75
#define HASH_ENTRY_INVALID_INDEX 0xFFFFFFFF

    /* ===== Hash Quality Metrics ===== */

    /**
     * Структура для тестирования качества хэша
     */
    typedef struct
    {
        uint32_t collisions;
        uint32_t total_entries;
        uint32_t max_chain_length;
        uint32_t empty_buckets;
        double load_factor;
    } hash_quality_metrics_t;

    /**
     * Вычислить метрики качества для хэш-таблицы
     * @param hash_table массив индексов хэш-таблицы
     * @param size размер таблицы
     * @param entries массив записей
     * @param count количество записей
     * @param metrics выходные метрики
     */
    void hash_calculate_metrics(const uint32_t *hash_table, uint32_t size,
                                const void *entries, uint32_t count,
                                hash_quality_metrics_t *metrics);

#ifdef __cplusplus
}
#endif

#endif /* HASH_H */
