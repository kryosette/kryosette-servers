#pragma once
#ifndef CAM_TABLE_H
#define CAM_TABLE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "atomic_shim.h";

#ifdef __cplusplus
extern "C"
{
#endif

    /* ===== Constants and Configuration ===== */

#define CAM_TABLE_VERSION_MAJOR 1
#define CAM_TABLE_VERSION_MINOR 0
#define CAM_TABLE_VERSION_PATCH 0

#define MAC_ADDRESS_LENGTH 6
#define IPV6_ADDRESS_LENGTH 16
#define MAX_VLAN_ID 4095
#define MAX_PORT_NUMBER 255
#define MAX_PRIORITY 7
#define INVALID_INDEX 0xFFFFFFFF

    /* ===== LOGGING ===== */
#define LOG_DIR "C:/Users/dmako/kryosette/kryosette-servers/bridge/logs/cam_table"
#define LOG_FILE LOG_DIR "cam_table.log"
#define MAX_LOG_SIZE (10 * 1024 * 1024)

    /* ===== Cross-platform implementation of the memory barrier ===== */

#if defined(__x86_64__) || defined(__i386__)
#define MFENCE() __asm__ __volatile__("mfence" ::: "memory")
#define SFENCE() __asm__ __volatile__("sfence" ::: "memory")
#define LFENCE() __asm__ __volatile__("lfence" ::: "memory")
#elif defined(__aarch64__)
#define MFENCE() __asm__ __volatile__("dmb ish" ::: "memory")
#define SFENCE() __asm__ __volatile__("dmb ishst" ::: "memory")
#define LFENCE() __asm__ __volatile__("dmb ishld" ::: "memory")
#elif defined(__arm__)
#define MFENCE() __asm__ __volatile__("dmb" ::: "memory")
#define SFENCE() __asm__ __volatile__("dmb st" ::: "memory")
#define LFENCE() __asm__ __volatile__("dmb ld" ::: "memory")
#elif defined(__powerpc__) || defined(__ppc__) || defined(__PPC__)
#define MFENCE() __asm__ __volatile__("sync" ::: "memory")
#define SFENCE() __asm__ __volatile__("sync" ::: "memory")
#define LFENCE() __asm__ __volatile__("lwsync" ::: "memory")
#elif defined(__mips__)
#define MFENCE() __asm__ __volatile__("sync" ::: "memory")
#define SFENCE() __asm__ __volatile__("sync" ::: "memory")
#define LFENCE() __asm__ __volatile__("sync" ::: "memory")
#elif defined(__riscv)
#define MFENCE() __asm__ __volatile__("fence iorw, iorw" ::: "memory")
#define SFENCE() __asm__ __volatile__("fence ow, ow" ::: "memory")
#define LFENCE() __asm__ __volatile__("fence ir, ir" ::: "memory")
#else
#define MFENCE() __asm__ __volatile__("" ::: "memory")
#define SFENCE() __asm__ __volatile__("" ::: "memory")
#define LFENCE() __asm__ __volatile__("" ::: "memory")
#warning "Using compiler memory barrier only - architecture not specifically optimized"
#endif

    /* ===== Cross-platform system calls ===== */

#if defined(__linux__)
#include <sys/syscall.h>
#include <unistd.h>
#define SYS_GETPID_NR SYS_getpid
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/syscall.h>
#include <unistd.h>
#define SYS_GETPID_NR SYS_getpid
#elif defined(__APPLE__) && defined(__MACH__)
#include <sys/syscall.h>
#include <unistd.h>
#define SYS_GETPID_NR 0x2000014
#elif defined(_WIN32)
#include <windows.h>
#define SYS_GETPID_NR 0
#else
#define SYS_GETPID_NR 0
#endif

    /* ===== Data Type Definitions ===== */

    typedef enum
    {
        UFT_MODE_0 = 0, /**< Maximize IPv4 LPM routes */
        UFT_MODE_1 = 1, /**< Balanced profile */
        UFT_MODE_2 = 2, /**< Default mode - maximize MAC addresses */
        UFT_MODE_3 = 3, /**< Hybrid profile */
        UFT_MODE_4 = 4, /**< Specialized applications */
        UFT_MODE_MAX
    } uft_mode_t;

    typedef enum
    {
        ENTRY_TYPE_INVALID = 0,
        ENTRY_TYPE_L2_MAC,        /**< L2 MAC address entry */
        ENTRY_TYPE_L3_IPV4_HOST,  /**< IPv4 host route (ARP entry) */
        ENTRY_TYPE_L3_IPV4_MCAST, /**< IPv4 multicast (S,G) entry */
        ENTRY_TYPE_L3_IPV6_HOST,  /**< IPv6 host route */
        ENTRY_TYPE_L3_IPV4_LPM,   /**< IPv4 Longest Prefix Match */
        ENTRY_TYPE_L3_IPV6_LPM,   /**< IPv6 Longest Prefix Match */
        ENTRY_TYPE_ACL,           /**< Access Control List entry */
        ENTRY_TYPE_QOS,           /**< Quality of Service policy */
        ENTRY_TYPE_POLICY,        /**< General policy entry */
        ENTRY_TYPE_MAX
    } cam_entry_type_t;

    typedef enum
    {
        ENTRY_STATUS_INVALID = 0,
        ENTRY_STATUS_ACTIVE,         /**< Entry is active and valid */
        ENTRY_STATUS_AGING,          /**< Entry is aging out */
        ENTRY_STATUS_PENDING_ADD,    /**< Entry pending hardware programming */
        ENTRY_STATUS_PENDING_DELETE, /**< Entry pending hardware removal */
        ENTRY_STATUS_STATIC,         /**< Static entry (does not age out) */
        ENTRY_STATUS_DYNAMIC         /**< Dynamically learned entry */
    } cam_entry_status_t;

    typedef enum
    {
        AGING_TIMER_DEFAULT = 300, /**< Default aging time (5 minutes) */
        AGING_TIMER_SHORT = 60,    /**< Short aging time (1 minute) */
        AGING_TIMER_LONG = 1800,   /**< Long aging time (30 minutes) */
        AGING_TIMER_DISABLED = 0   /**< Aging disabled */
    } aging_timer_t;

    typedef enum
    {
        ACL_ACTION_PERMIT = 0,
        ACL_ACTION_DENY,
        ACL_ACTION_REDIRECT,
        ACL_ACTION_MIRROR,
        ACL_ACTION_POLICE,
        ACL_ACTION_REMARK
    } acl_action_t;

    typedef enum
    {
        QOS_QUEUE_STRICT_PRIORITY = 0,
        QOS_QUEUE_WRR,
        QOS_QUEUE_WFQ
    } qos_queue_type_t;

    /* ===== Basic Data Structures ===== */

    typedef struct
    {
        uint8_t bytes[MAC_ADDRESS_LENGTH];
    } mac_address_t;

    typedef uint32_t ipv4_addr_t;

    typedef struct
    {
        uint8_t bytes[IPV6_ADDRESS_LENGTH];
    } ipv6_addr_t;

    typedef struct
    {
        ipv4_addr_t address;
        uint8_t prefix_length;
    } ipv4_prefix_t;

    typedef struct
    {
        ipv6_addr_t address;
        uint8_t prefix_length;
    } ipv6_prefix_t;

    /* ===== CAM Entry Structures ===== */

    typedef struct cam_entry_header
    {
        uint32_t index;            /**< Hardware table index */
        cam_entry_type_t type;     /**< Entry type */
        cam_entry_status_t status; /**< Entry status */
        time_t created_timestamp;  /**< Entry creation time */
        time_t last_updated;       /**< Last update time */
        time_t last_accessed;      /**< Last access time */
        uint16_t vlan_id;          /**< VLAN ID */
        uint8_t logical_port;      /**< Logical port/interface */
        uint8_t priority;          /**< TCAM priority (0-7) */
        uint32_t reference_count;  /**< Reference count */
        bool hit_flag;             /**< Access flag for aging */
        uint8_t pad[3];            /**< Padding for alignment */
    } cam_entry_header_t;

    typedef struct
    {
        cam_entry_header_t header;
        mac_address_t mac_address;
        uint8_t flags;
        uint8_t pad[1];
    } cam_l2_entry_t;

    /* ===== CAM Table Storage Structure ===== */

    typedef struct cam_table_entry
    {
        cam_entry_header_t header;
        union
        {
            cam_l2_entry_t l2_entry;
            cam_l3_ipv4_host_entry_t l3_ipv4_host;
            cam_l3_ipv4_lpm_entry_t l3_ipv4_lpm;
            cam_l3_ipv6_lpm_entry_t l3_ipv6_lpm;
            cam_l3_ipv4_mcast_entry_t l3_ipv4_mcast;
            cam_acl_ipv4_entry_t acl_entry;
            cam_qos_entry_t qos_entry;
            uint8_t raw_data[128]; /* Ensure union is large enough for all types */
        } data;
    } cam_table_entry_t;

    typedef struct cam_table
    {
        /* Dynamic array of entries */
        cam_table_entry_t *entries;
        uint32_t capacity; /* Total allocated capacity */
        uint32_t count;    /* Current number of entries */

        /* Indexing structures */
        uint32_t *l2_index;      /* Index for L2 entries */
        uint32_t *l3_ipv4_index; /* Index for IPv4 entries */
        uint32_t *acl_index;     /* Index for ACL entries */

        uint32_t l2_count;
        uint32_t l3_ipv4_count;
        uint32_t acl_count;

        /* Configuration */
        uint32_t max_entries;
        bool enable_aging;
        aging_timer_t aging_time;

        /* Synchronization */
        pthread_mutex_t lock; /* For thread safety */

    } cam_table_t;

#define L2_ENTRY_FLAG_LOCAL (1 << 0)
#define L2_ENTRY_FLAG_ROUTER_MAC (1 << 1)
#define L2_ENTRY_FLAG_SECURE (1 << 2)
#define L2_ENTRY_FLAG_MOVED (1 << 3)

    typedef struct
    {
        cam_entry_header_t header;
        ipv4_addr_t ip_address;
        mac_address_t next_hop_mac;
        uint8_t protocol; /**< IP protocol */
        uint8_t pad[3];
    } cam_l3_ipv4_host_entry_t;

    typedef struct
    {
        cam_entry_header_t header;
        ipv4_prefix_t prefix;
        ipv4_addr_t next_hop;
        uint8_t metric;
        uint8_t admin_distance;
        uint16_t flags;
    } cam_l3_ipv4_lpm_entry_t;

#define LPM_ENTRY_FLAG_DISCARD (1 << 0)
#define LPM_ENTRY_FLAG_RECURSIVE (1 << 1)
#define LPM_ENTRY_FLAG_ECMP (1 << 2)

    typedef struct
    {
        cam_entry_header_t header;
        ipv6_prefix_t prefix;
        ipv6_addr_t next_hop;
        uint8_t metric;
        uint8_t admin_distance;
        uint16_t flags;
    } cam_l3_ipv6_lpm_entry_t;

    typedef struct
    {
        cam_entry_header_t header;
        ipv4_addr_t source_ip;
        ipv4_addr_t group_ip;
        uint8_t source_mask;
        uint8_t group_mask;
        uint16_t pad;
    } cam_l3_ipv4_mcast_entry_t;

    typedef struct
    {
        cam_entry_header_t header;
        uint32_t acl_id;
        acl_action_t action;
        uint16_t source_port_min;
        uint16_t source_port_max;
        uint16_t dest_port_min;
        uint16_t dest_port_max;
        ipv4_addr_t source_ip;
        ipv4_addr_t source_mask;
        ipv4_addr_t dest_ip;
        ipv4_addr_t dest_mask;
        uint8_t ip_protocol;
        uint8_t dscp_value;
        uint8_t tcp_flags;
        uint8_t pad[1];
    } cam_acl_ipv4_entry_t;

    typedef struct
    {
        cam_entry_header_t header;
        uint32_t qos_policy_id;
        qos_queue_type_t queue_type;
        uint8_t queue_id;
        uint8_t dscp_remark;
        uint16_t bandwidth_percent;
        uint32_t rate_limit_bps;
        uint32_t burst_size;
    } cam_qos_entry_t;

    /* ===== Table Capacity Configuration ===== */

    typedef struct {
       uft_mode_t mode;
       const char *description;
    
    /* Базовые емкости L2 */
       uint32_t max_l2_unicast_entries;    // L2 unicast MAC
       uint32_t max_l2_multicast_entries;  // L2 multicast
       uint32_t max_vlan_entries;          // VLAN entries
       uint32_t max_lag_entries;           // LAG groups
    
    /* IPv4 хосты и мультикаст */
       uint32_t max_ipv4_host_entries;     // IPv4 host routes
       uint32_t max_ipv4_mcast_entries;    // IPv4 multicast
       uint32_t max_ipv4_arp_entries;      // ARP/ND entries
    
    /* IPv6 хосты и мультикаст */
       uint32_t max_ipv6_host_entries;     // IPv6 host routes
       uint32_t max_ipv6_mcast_entries;    // IPv6 multicast
       
    /* LPM (Longest Prefix Match) таблицы */
       uint32_t max_ipv4_lpm_entries;      // IPv4 prefixes
       uint32_t max_ipv6_lpm_entries;      // IPv6 prefixes
       uint32_t max_ipv6_64_lpm_entries;   // IPv6 /64 prefixes
       uint32_t max_ipv6_128_lpm_entries;  // IPv6 /128 host routes
    
    /* ACL и политики */
       uint32_t max_acl_entries;           // Access Control List
       uint32_t max_qos_entries;           // Quality of Service
       uint32_t max_policy_entries;        // Policy rules
       uint32_t max_meter_entries;         // Traffic meters/policers
    
    /* Tunnel таблицы */
       uint32_t max_tunnel_entries;        // VXLAN, GRE, MPLS
       uint32_t max_vxlan_vni_entries;     // VXLAN Network Identifiers
       uint32_t max_mpls_entries;          // MPLS labels
    
    /* ECMP и next-hop */
       uint32_t max_ecmp_groups;           // ECMP groups
       uint32_t max_nexthop_entries;       // Next-hop entries
       uint32_t max_ecmp_members_per_group; // Members per ECMP group
    
    /* Статистика и мониторинг */
       uint32_t max_statistics_entries;    // Statistics counters
       uint32_t max_mirror_entries;        // Mirror sessions
       uint32_t max_sflow_entries;         sFlow sampling
    
    /* Безопасность */
       uint32_t max_dos_entries;           // DoS protection
       uint32_t max_blackhole_entries;     // Blackhole routes
    
    /* Суммарные лимиты */
       uint32_t total_shared_entries;      // Total shared UFT entries
       uint32_t reserved_system_entries;   // System reserved
       uint32_t available_user_entries;    // Available for user config
    
    /* Характеристики памяти */
       uint32_t hash_table_size;           // Hash table size
       uint32_t bank_configuration;        // Memory bank config
       uint32_t entry_width_bits;          // Bits per entry
    
    } uft_capacity_profile_t;

    typedef struct
    {
        uint32_t total_capacity;    /**< Total TCAM entries available */
        uint32_t used_entries;      /**< Currently used entries */
        uint32_t allocated_l2;      /**< Allocated for L2 entries */
        uint32_t allocated_l3_ipv4; /**< Allocated for IPv4 L3 entries */
        uint32_t allocated_l3_ipv6; /**< Allocated for IPv6 L3 entries */
        uint32_t allocated_acl;     /**< Allocated for ACL entries */
        uint32_t allocated_qos;     /**< Allocated for QoS entries */
        uint32_t free_entries;      /**< Available entries */
        uint32_t hardware_errors;   /**< Hardware programming errors */
    } cam_table_utilization_t;

    /* ===== Statistics Structures ===== */

    typedef struct
    {
        ATOMIC_U64 entries_learned;
        ATOMIC_U64 entries_aged_out;
        ATOMIC_U64 entries_deleted;
        ATOMIC_U64 entries_moved;
        ATOMIC_U64 lookup_requests;
        ATOMIC_U64 lookup_hits;
        ATOMIC_U64 lookup_misses;
        ATOMIC_U64 hardware_errors;
        ATOMIC_U64 allocation_failures;
    } cam_table_stats_t;

    typedef struct __attribute__((packed, aligned(8)) {
        ATOMIC_U64 searches;
        ATOMIC_U64 hits;
        ATOMIC_U64 misses;
        ATOMIC_U64 collisions;
        uint32_t hit_ratio_percent;
    } cam_search_stats_t;

    static_assert(sizeof(cam_search_stats_t) % 8 == 0, "Bad alignment for atomics");

    /* ===== Function Pointer Types ===== */

    typedef bool (*cam_entry_callback_t)(const cam_entry_header_t *entry, void *user_data);
    typedef int (*cam_compare_func_t)(const void *entry1, const void *entry2, void *user_data);
    typedef void (*cam_log_func_t)(const char *message, int level);

    /* ===== Main CAM Table Management Structure ===== */

    typedef struct cam_table_manager
    {
        /* Configuration */
        uft_mode_t current_mode;
        uft_capacity_profile_t capacity_profile;
        aging_timer_t aging_time;
        cam_entry_callback_t cam_entry;
        cam_table_t *cam_table;

        /* Statistics */
        cam_table_stats_t stats;
        cam_table_utilization_t utilization;
        time_t last_stat_reset;

        /* Callbacks */
        cam_entry_callback_t learn_callback;
        cam_entry_callback_t age_callback;
        cam_entry_callback_t delete_callback;
        cam_log_func_t log_callback;

        /* Internal state */
        bool initialized;
        bool hardware_sync_enabled;
        uint32_t magic_number; /**< Magic number for validation */
    } cam_table_manager_t;

    /* ===== API Function Declarations ===== */

    /* CAM Table Storage Management */
    cam_table_t *cam_table_create(uint32_t max_entries);
    int cam_table_destroy(cam_table_t *table);
    int cam_table_resize(cam_table_t *table, uint32_t new_capacity);
    int cam_table_clear(cam_table_t *table);
    int cam_table_compact(cam_table_t *table);

    /* Initialization and Configuration */
    int cam_table_init(cam_table_manager_t *manager, uft_mode_t default_mode);
    int cam_table_cleanup(cam_table_manager_t *manager);
    int cam_table_set_mode(cam_table_manager_t *manager, uft_mode_t new_mode);
    int cam_table_set_aging_time(cam_table_manager_t *manager, aging_timer_t aging_time);

    /* Entry Management */
    int cam_table_add_l2_entry(cam_table_manager_t *manager, const cam_l2_entry_t *entry);
    int cam_table_add_l3_ipv4_host_entry(cam_table_manager_t *manager, const cam_l3_ipv4_host_entry_t *entry);
    int cam_table_add_l3_ipv4_lpm_entry(cam_table_manager_t *manager, const cam_l3_ipv4_lpm_entry_t *entry);
    int cam_table_add_acl_entry(cam_table_manager_t *manager, const cam_acl_ipv4_entry_t *entry);

    int cam_table_delete_entry(cam_table_manager_t *manager, uint32_t index);
    int cam_table_delete_entry_by_content(cam_table_manager_t *manager, const cam_entry_header_t *entry);
    int cam_table_clear_entries(cam_table_manager_t *manager, cam_entry_type_t type);

    /* Search and Lookup Operations */
    int cam_table_find_l2_entry(const cam_table_manager_t *manager, const mac_address_t *mac, uint16_t vlan_id, cam_l2_entry_t *result);
    int cam_table_find_l3_ipv4_host_entry(const cam_table_manager_t *manager, ipv4_addr_t ip_address, cam_l3_ipv4_host_entry_t *result);
    int cam_table_find_lpm_ipv4(const cam_table_manager_t *manager, ipv4_addr_t ip_address, cam_l3_ipv4_lpm_entry_t *result);

    /* Table Maintenance */
    int cam_table_aging_process(cam_table_manager_t *manager);
    int cam_table_compress(cam_table_manager_t *manager);
    int cam_table_validate(const cam_table_manager_t *manager);

    /* Statistics and Monitoring */
    int cam_table_get_utilization(const cam_table_manager_t *manager, cam_table_utilization_t *utilization);
    int cam_table_get_stats(const cam_table_manager_t *manager, cam_table_stats_t *stats);
    int cam_table_reset_stats(cam_table_manager_t *manager);

    /* Utility Functions */
    const char *cam_entry_type_to_string(cam_entry_type_t type);
    const char *cam_entry_status_to_string(cam_entry_status_t status);
    const char *uft_mode_to_string(uft_mode_t mode);
    void cam_table_dump_entry(const cam_entry_header_t *entry, char *buffer, size_t buffer_size);

    /* Callback Registration */
    void cam_table_set_learn_callback(cam_table_manager_t *manager, cam_entry_callback_t callback);
    void cam_table_set_age_callback(cam_table_manager_t *manager, cam_entry_callback_t callback);
    void cam_table_set_delete_callback(cam_table_manager_t *manager, cam_entry_callback_t callback);
    void cam_table_set_log_callback(cam_table_manager_t *manager, cam_log_func_t callback);

    /* Hardware Synchronization */
    int cam_table_sync_to_hardware(cam_table_manager_t *manager);
    int cam_table_sync_from_hardware(cam_table_manager_t *manager);

    uft_capacity_profile_t *cam_table_uft_learn(uint32_t uft_modes);
    /* ===== Inline Utility Functions ===== */

    static inline bool mac_address_equals(const mac_address_t *mac1, const mac_address_t *mac2)
    {
        return memcmp(mac1->bytes, mac2->bytes, MAC_ADDRESS_LENGTH) == 0;
    }

    static inline bool mac_address_is_zero(const mac_address_t *mac)
    {
        static const uint8_t zero_mac[MAC_ADDRESS_LENGTH] = {0};
        return memcmp(mac->bytes, zero_mac, MAC_ADDRESS_LENGTH) == 0;
    }

    static inline bool mac_address_is_multicast(const mac_address_t *mac)
    {
        return (mac->bytes[0] & 0x01) != 0;
    }

    static inline bool mac_address_is_broadcast(const mac_address_t *mac)
    {
        static const uint8_t broadcast_mac[MAC_ADDRESS_LENGTH] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        return memcmp(mac->bytes, broadcast_mac, MAC_ADDRESS_LENGTH) == 0;
    }

    static inline bool ipv4_address_is_zero(ipv4_addr_t ip)
    {
        return ip == 0;
    }

    static inline bool ipv4_address_is_multicast(ipv4_addr_t ip)
    {
        return (ip & 0xF0000000) == 0xE0000000;
    }

    static inline void secure_zero_memory(void *ptr, size_t size)
    {
        if (unlikely(ptr == NULL || size == 0))
            return;

        volatile uint8_t *p = (volatile uint8_t *)ptr;

        MFENCE();

        size_t i = 0;
        if (size >= 8)
        {
            volatile uint64_t *p64 = (volatile uint64_t *)ptr;
            for (; i < size / 8; i++)
            {
                p64[i] = 0;
            }
            i *= 8;
        }

        for (; i < size; i++)
        {
            p[i] = 0;
        }

        MFENCE();
    }

#ifdef __cplusplus
}
#endif

#endif /* CAM_TABLE_H */
