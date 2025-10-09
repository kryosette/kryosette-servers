/*
 * CAM Table Management Header
 *
 * Unified Forwarding Table (UFT) and Content Addressable Memory (CAM)
 * management system for network switching and routing applications.
 *
 * Key Features:
 * - L2/L3 forwarding table management
 * - Hardware synchronization
 * - Cross-platform memory barriers
 * - Comprehensive statistics and monitoring
 * - Thread-safe operations
 */

// Protection against multiple includes - DO NOT MODIFY
#pragma once
#ifndef CAM_TABLE_H
#define CAM_TABLE_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "atomic_shim.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct cam_table_entry cam_table_entry_t;
    typedef struct uft_hw_entry_t uft_hw_entry_t;

/**
 * CAM Table Version Information
 * Follows semantic versioning (major.minor.patch)
 */
#define CAM_TABLE_VERSION_MAJOR 1 /**< Major version - breaking changes */
#define CAM_TABLE_VERSION_MINOR 0 /**< Minor version - new features */
#define CAM_TABLE_VERSION_PATCH 0 /**< Patch version - bug fixes */

/**
 * Network Protocol Constants
 */
#define MAC_ADDRESS_LENGTH 6     /**< Ethernet MAC address length in bytes */
#define IPV6_ADDRESS_LENGTH 16   /**< IPv6 address length in bytes */
#define MAX_VLAN_ID 4095         /**< Maximum valid VLAN ID (12-bit space) */
#define MAX_PORT_NUMBER 255      /**< Maximum logical port number */
#define MAX_PRIORITY 7           /**< Maximum TCAM priority value */
#define INVALID_INDEX 0xFFFFFFFF /**< Invalid table index indicator */

#define CAM_MAGIC 0xCA7AB1E
#define CAM_VERSION 1
#define DEFAULT_CAPACITY 256000
    /**
     * MAC Address Structure
     * 48-bit Ethernet MAC address
     */
    typedef struct
    {
        uint8_t bytes[MAC_ADDRESS_LENGTH]; /**< Raw MAC address bytes */
    } mac_address_t;

    /** IPv4 Address - 32-bit unsigned integer in network byte order */
    typedef uint32_t ipv4_addr_t;

    /**
     * IPv6 Address Structure
     * 128-bit IPv6 address
     */
    typedef struct
    {
        uint8_t bytes[IPV6_ADDRESS_LENGTH]; /**< Raw IPv6 address bytes */
    } ipv6_addr_t;

/* ===== Constants and Configuration ===== */

// /**
//  * Feature Flags
//  */
// #define L2_HASH_TABLE /**< Enable hash-based L2 table lookups */

/* ===== Logging Configuration ===== */

/**
 * Logging system configuration for debugging and monitoring
 */
#define LOG_DIR "C:/Users/dmako/kryosette/kryosette-servers/bridge/logs/cam_table"
#define LOG_FILE LOG_DIR "cam_table.log"
#define MAX_LOG_SIZE (10 * 1024 * 1024) /**< Maximum log file size (10MB) */

    /* ===== Cross-Platform Memory Barrier Implementation ===== */

    /**
     * Memory fence operations for different CPU architectures
     * Ensures proper memory ordering for multi-threaded operations
     */

#if defined(__x86_64__) || defined(__i386__)
/* Intel x86/x64 architecture - full memory barriers */
#define MFENCE() __asm__ __volatile__("mfence" ::: "memory") /**< Full memory fence */
#define SFENCE() __asm__ __volatile__("sfence" ::: "memory") /**< Store fence */
#define LFENCE() __asm__ __volatile__("lfence" ::: "memory") /**< Load fence */
#elif defined(__aarch64__)
/* ARM64 architecture - data memory barriers */
#define MFENCE() __asm__ __volatile__("dmb ish" ::: "memory")   /**< Full memory barrier */
#define SFENCE() __asm__ __volatile__("dmb ishst" ::: "memory") /**< Store memory barrier */
#define LFENCE() __asm__ __volatile__("dmb ishld" ::: "memory") /**< Load memory barrier */
#elif defined(__arm__)
/* ARM32 architecture */
#define MFENCE() __asm__ __volatile__("dmb" ::: "memory")    /**< Full memory barrier */
#define SFENCE() __asm__ __volatile__("dmb st" ::: "memory") /**< Store memory barrier */
#define LFENCE() __asm__ __volatile__("dmb ld" ::: "memory") /**< Load memory barrier */
#elif defined(__powerpc__) || defined(__ppc__) || defined(__PPC__)
/* PowerPC architecture */
#define MFENCE() __asm__ __volatile__("sync" ::: "memory")   /**< Full synchronization */
#define SFENCE() __asm__ __volatile__("sync" ::: "memory")   /**< Store synchronization */
#define LFENCE() __asm__ __volatile__("lwsync" ::: "memory") /**< Lightweight sync */
#elif defined(__mips__)
/* MIPS architecture */
#define MFENCE() __asm__ __volatile__("sync" ::: "memory") /**< Full synchronization */
#define SFENCE() __asm__ __volatile__("sync" ::: "memory") /**< Store synchronization */
#define LFENCE() __asm__ __volatile__("sync" ::: "memory") /**< Load synchronization */
#elif defined(__riscv)
/* RISC-V architecture */
#define MFENCE() __asm__ __volatile__("fence iorw, iorw" ::: "memory") /**< Full fence */
#define SFENCE() __asm__ __volatile__("fence ow, ow" ::: "memory")     /**< Output fence */
#define LFENCE() __asm__ __volatile__("fence ir, ir" ::: "memory")     /**< Input fence */
#else
/* Fallback - compiler memory barrier only */
#define MFENCE() __asm__ __volatile__("" ::: "memory") /**< Compiler barrier */
#define SFENCE() __asm__ __volatile__("" ::: "memory") /**< Compiler barrier */
#define LFENCE() __asm__ __volatile__("" ::: "memory") /**< Compiler barrier */
#warning "Using compiler memory barrier only - architecture not specifically optimized"
#endif

    /* ===== Cross-Platform System Calls ===== */

    /**
     * System call definitions for different operating systems
     * Used for process identification and system integration
     */

#if defined(__linux__)
#include <sys/syscall.h>
#include <unistd.h>
#define SYS_GETPID_NR SYS_getpid /**< Linux getpid system call number */
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/syscall.h>
#include <unistd.h>
#define SYS_GETPID_NR SYS_getpid /**< BSD getpid system call number */
#elif defined(__APPLE__) && defined(__MACH__)
#include <sys/syscall.h>
#include <unistd.h>
#define SYS_GETPID_NR 0x2000014 /**< macOS getpid system call number */
#elif defined(_WIN32)
#include <windows.h>
#define SYS_GETPID_NR 0 /**< Windows process ID (not used directly) */
#else
#define SYS_GETPID_NR 0 /**< Unknown platform */
#endif

#pragma pack(push, 1)
    typedef struct
    {
        uint32_t magic;
        uint16_t version;
        uint16_t entry_size;
        uint32_t total_entries;
        uint32_t trusted_count;
        uint32_t pending_count;
        uint32_t blocked_count;
        uint32_t free_count;
        uint64_t created_time;
        uint64_t last_updated;
        uint8_t reserved[40];
    } cam_file_header_t;

    typedef struct
    {
        uint8_t entry_type; // 0=trusted, 1=pending, 2=blocked
        uint8_t mac[6];
        uint16_t vlan_id;
        uint32_t port_map;
        uint32_t timestamp;
        uint32_t last_seen;
        uint16_t hit_count;
        uint8_t attack_score;
        uint8_t flags;
        uint32_t reason_offset;
        uint8_t reserved[4];
    } cam_file_entry_t;
#pragma pack(pop)

    /* ===== Data Type Definitions ===== */

    /**
     * Unified Forwarding Table Operation Modes
     * Defines the primary forwarding behavior of the system
     */
    typedef enum
    {
        UFT_MODE_L2_BRIDGING = 0, /**< Pure Layer 2 MAC address forwarding */
        UFT_MODE_L3_IPV4_ROUTING, /**< Layer 3 IPv4 routing with ARP */
        UFT_MODE_L3_IPV6_ROUTING, /**< Layer 3 IPv6 routing with ND */
        UFT_MODE_HYBRID,          /**< Mixed L2/L3 forwarding mode */
        UFT_MODE_SECURITY,        /**< Security-focused mode with heavy ACL processing */
        UFT_MODE_QOS,             /**< Quality of Service focused mode */
        UFT_MODE_MAX              /**< Maximum mode value - used for validation */
    } uft_mode_t;

    /**
     * Packet Forwarding Actions
     * Defines what action to take for a processed packet
     */
    typedef enum
    {
        PKT_ACTION_FORWARD = 0, /**< Forward packet to destination port */
        PKT_ACTION_DROP,        /**< Silently discard packet */
        PKT_ACTION_PENDING,     /**< Defer decision (wait for more information) */
        PKT_ACTION_CHECK_ACL,   /**< Perform additional ACL checks */
        PKT_ACTION_MIRROR,      /**< Copy packet to monitoring port */
        PKT_ACTION_POLICE       /**< Apply traffic policing/rate limiting */
    } packet_action_t;

    /**
     * Packet Information Structure
     * Contains metadata for packet processing decisions
     */
    typedef struct
    {
        ipv4_addr_t src_ip;   /**< Source IP address */
        uint16_t src_port;    /**< Source transport port */
        uint16_t dst_port;    /**< Destination transport port */
        uint8_t protocol;     /**< IP protocol number */
        uint8_t dscp;         /**< Differentiated Services Code Point */
        uint32_t packet_size; /**< Packet size in bytes */
        time_t timestamp;     /**< Packet arrival timestamp */
        uint32_t flow_hash;   /**< Pre-computed flow hash for fast lookups */
    } packet_info_t;

    /**
     * CAM Entry Types
     * Classification of different forwarding table entry types
     */
    typedef enum
    {
        ENTRY_TYPE_INVALID = 0,   /**< Invalid or uninitialized entry */
        ENTRY_TYPE_L2_MAC,        /**< Layer 2 MAC address forwarding entry */
        ENTRY_TYPE_L3_IPV4_HOST,  /**< IPv4 host route (directly connected) */
        ENTRY_TYPE_L3_IPV4_MCAST, /**< IPv4 multicast source-group entry */
        ENTRY_TYPE_L3_IPV6_HOST,  /**< IPv6 host route */
        ENTRY_TYPE_L3_IPV4_LPM,   /**< IPv4 Longest Prefix Match route */
        ENTRY_TYPE_L3_IPV6_LPM,   /**< IPv6 Longest Prefix Match route */
        ENTRY_TYPE_ACL,           /**< Access Control List entry */
        ENTRY_TYPE_QOS,           /**< Quality of Service policy entry */
        ENTRY_TYPE_POLICY,        /**< General forwarding policy entry */
        ENTRY_TYPE_MAX            /**< Maximum entry type - used for validation */
    } cam_entry_type_t;

    /**
     * CAM Entry Status Values
     * Tracks the lifecycle state of table entries
     */
    typedef enum
    {
        ENTRY_STATUS_INVALID = 0,    /**< Entry is invalid or being deleted */
        ENTRY_STATUS_ACTIVE,         /**< Entry is active and valid for forwarding */
        ENTRY_STATUS_AGING,          /**< Entry is in aging process (soon to expire) */
        ENTRY_STATUS_PENDING_ADD,    /**< Entry pending hardware programming */
        ENTRY_STATUS_PENDING_DELETE, /**< Entry pending hardware removal */
        ENTRY_STATUS_STATIC,         /**< Static entry (does not age out) */
        ENTRY_STATUS_DYNAMIC         /**< Dynamically learned entry (subject to aging) */
    } cam_entry_status_t;

    /**
     * Aging Timer Configuration
     * Standard aging intervals for dynamic entries
     */
    typedef enum
    {
        AGING_TIMER_DEFAULT = 300, /**< Default aging time - 5 minutes */
        AGING_TIMER_SHORT = 60,    /**< Short aging time - 1 minute */
        AGING_TIMER_LONG = 1800,   /**< Long aging time - 30 minutes */
        AGING_TIMER_DISABLED = 0   /**< Aging disabled - entry never expires */
    } aging_timer_t;

    /**
     * ACL Action Types
     * Defines actions for Access Control List entries
     */
    typedef enum
    {
        ACL_ACTION_PERMIT = 0, /**< Allow packet to proceed */
        ACL_ACTION_DENY,       /**< Block packet */
        ACL_ACTION_REDIRECT,   /**< Redirect packet to different port */
        ACL_ACTION_MIRROR,     /**< Mirror packet to monitoring port */
        ACL_ACTION_POLICE,     /**< Apply rate limiting to packet */
        ACL_ACTION_REMARK      /**< Modify DSCP/CoS values */
    } acl_action_t;

    /**
     * QoS Queue Scheduling Types
     * Defines queuing algorithms for quality of service
     */
    typedef enum
    {
        QOS_QUEUE_STRICT_PRIORITY = 0, /**< Higher priority queues always serviced first */
        QOS_QUEUE_WRR,                 /**< Weighted Round Robin scheduling */
        QOS_QUEUE_WFQ                  /**< Weighted Fair Queuing */
    } qos_queue_type_t;

    /* ===== Basic Data Structures ===== */

    /**
     * IPv4 Prefix Structure
     * IP address with prefix length for LPM operations
     */
    typedef struct
    {
        ipv4_addr_t address;   /**< IPv4 network address */
        uint8_t prefix_length; /**< Network prefix length (0-32) */
    } ipv4_prefix_t;

    /**
     * IPv6 Prefix Structure
     * IPv6 address with prefix length for LPM operations
     */
    typedef struct
    {
        ipv6_addr_t address;   /**< IPv6 network address */
        uint8_t prefix_length; /**< Network prefix length (0-128) */
    } ipv6_prefix_t;

    /* ===== CAM Entry Structures ===== */

    /**
     * Common CAM Entry Header
     * Shared metadata for all types of CAM entries
     */
    typedef struct cam_entry_header
    {
        uint32_t index;            /**< Hardware table index location */
        cam_entry_type_t type;     /**< Type of CAM entry */
        cam_entry_status_t status; /**< Current lifecycle status */
        time_t created_timestamp;  /**< Entry creation timestamp */
        time_t last_updated;       /**< Last modification time */
        time_t last_accessed;      /**< Last access time (for aging) */
        uint16_t vlan_id;          /**< VLAN ID for L2 entries */
        uint8_t logical_port;      /**< Logical port/interface number */
        uint8_t priority;          /**< TCAM priority (0-7, higher wins) */
        uint32_t reference_count;  /**< Reference count for shared entries */
        bool hit_flag;             /**< Access flag for aging algorithm */
        uint8_t pad[3];            /**< Padding for 32-bit alignment */
    } cam_entry_header_t;

    /**
     * Layer 2 MAC Address Entry
     * Used for Ethernet MAC address forwarding
     */
    typedef struct
    {
        cam_entry_header_t header; /**< Common entry header */
        mac_address_t mac_address; /**< MAC address value */
        uint8_t flags;             /**< Entry-specific flags */
        uint8_t pad[1];            /**< Padding for alignment */
    } cam_l2_entry_t;

    /**
     * Hardware L2 Entry Structure
     * Packed structure for hardware programming
     */
    typedef struct __attribute__((packed, aligned(4)))
    {
        uint32_t hw_index;         /**< Hardware table index */
        mac_address_t mac_address; /**< MAC address */
        uint16_t vlan_id;          /**< VLAN ID */
        uint32_t output_port;      /**< Output port bitmap */
        packet_action_t action;    /**< Forwarding action */
        time_t timestamp;          /**< Entry creation time */
        uint8_t flags;             /**< Status flags */
    } uft_l2_entry_t;

/* L2 Entry Flags */
#define UFT_L2_FLAG_VALID (1 << 0)  /**< Entry is valid and active */
#define UFT_L2_FLAG_STATIC (1 << 1) /**< Static entry (no aging) */
#define UFT_L2_FLAG_AGED (1 << 2)   /**< Entry has been aged out */

    /* ===== CAM Table Storage Structure ===== */

    /**
     * Main CAM Table Structure
     * Manages storage and indexing of all CAM entries
     */
    typedef struct cam_table
    {
        /* Dynamic storage */
        cam_table_entry_t *entries; /**< Dynamic array of entries */
        uint32_t capacity;          /**< Total allocated capacity */
        uint32_t count;             /**< Current number of active entries */

        /* Indexing structures for fast lookups */
        uint32_t *l2_index;      /**< Index for L2 MAC entries */
        uint32_t *l3_ipv4_index; /**< Index for IPv4 entries */
        uint32_t *acl_index;     /**< Index for ACL entries */

        /* Entry type counters */
        uint32_t l2_count;      /**< Number of L2 entries */
        uint32_t l3_ipv4_count; /**< Number of IPv4 entries */
        uint32_t acl_count;     /**< Number of ACL entries */

        /* Configuration */
        uint32_t max_entries;     /**< Maximum allowed entries */
        bool enable_aging;        /**< Aging process enabled */
        aging_timer_t aging_time; /**< Current aging timer value */

        /* Synchronization */
        pthread_mutex_t lock; /**< Mutex for thread safety */
    } cam_table_t;

/* L2 Entry Specific Flags */
#define L2_ENTRY_FLAG_LOCAL (1 << 0)      /**< Locally administered MAC */
#define L2_ENTRY_FLAG_ROUTER_MAC (1 << 1) /**< Router MAC address */
#define L2_ENTRY_FLAG_SECURE (1 << 2)     /**< Secure/authenticated entry */
#define L2_ENTRY_FLAG_MOVED (1 << 3)      /**< Entry has moved ports */

    /**
     * Layer 3 IPv4 Host Entry
     * Directly connected host routes
     */
    typedef struct
    {
        cam_entry_header_t header;  /**< Common entry header */
        ipv4_addr_t ip_address;     /**< IPv4 host address */
        mac_address_t next_hop_mac; /**< Next-hop MAC address */
        uint8_t protocol;           /**< IP protocol (ARP, etc.) */
        uint8_t pad[3];             /**< Padding for alignment */
    } cam_l3_ipv4_host_entry_t;

    /**
     * Layer 3 IPv4 LPM Entry
     * Longest Prefix Match routing entry
     */
    typedef struct
    {
        cam_entry_header_t header; /**< Common entry header */
        ipv4_prefix_t prefix;      /**< IPv4 network prefix */
        ipv4_addr_t next_hop;      /**< Next-hop IP address */
        uint8_t metric;            /**< Routing metric */
        uint8_t admin_distance;    /**< Administrative distance */
        uint16_t flags;            /**< Route flags */
    } cam_l3_ipv4_lpm_entry_t;

/* LPM Entry Flags */
#define LPM_ENTRY_FLAG_DISCARD (1 << 0)   /**< Discard route (null0) */
#define LPM_ENTRY_FLAG_RECURSIVE (1 << 1) /**< Recursive route lookup */
#define LPM_ENTRY_FLAG_ECMP (1 << 2)      /**< Equal-Cost Multi-Path */

    /**
     * Layer 3 IPv6 LPM Entry
     * IPv6 Longest Prefix Match routing entry
     */
    typedef struct
    {
        cam_entry_header_t header; /**< Common entry header */
        ipv6_prefix_t prefix;      /**< IPv6 network prefix */
        ipv6_addr_t next_hop;      /**< Next-hop IPv6 address */
        uint8_t metric;            /**< Routing metric */
        uint8_t admin_distance;    /**< Administrative distance */
        uint16_t flags;            /**< Route flags */
    } cam_l3_ipv6_lpm_entry_t;

    /**
     * Layer 3 IPv4 Multicast Entry
     * Source-specific multicast forwarding
     */
    typedef struct
    {
        cam_entry_header_t header; /**< Common entry header */
        ipv4_addr_t source_ip;     /**< Multicast source IP */
        ipv4_addr_t group_ip;      /**< Multicast group IP */
        uint8_t source_mask;       /**< Source address mask */
        uint8_t group_mask;        /**< Group address mask */
        uint16_t pad;              /**< Padding for alignment */
    } cam_l3_ipv4_mcast_entry_t;

    /**
     * IPv4 ACL Entry
     * Access Control List for IPv4 packets
     */
    typedef struct
    {
        cam_entry_header_t header; /**< Common entry header */
        uint32_t acl_id;           /**< ACL identifier */
        acl_action_t action;       /**< ACL action to apply */
        uint16_t source_port_min;  /**< Minimum source port range */
        uint16_t source_port_max;  /**< Maximum source port range */
        uint16_t dest_port_min;    /**< Minimum destination port range */
        uint16_t dest_port_max;    /**< Maximum destination port range */
        ipv4_addr_t source_ip;     /**< Source IP address */
        ipv4_addr_t source_mask;   /**< Source IP wildcard mask */
        ipv4_addr_t dest_ip;       /**< Destination IP address */
        ipv4_addr_t dest_mask;     /**< Destination IP wildcard mask */
        uint8_t ip_protocol;       /**< IP protocol number */
        uint8_t dscp_value;        /**< DSCP match value */
        uint8_t tcp_flags;         /**< TCP flags to match */
        uint8_t pad[1];            /**< Padding for alignment */
    } cam_acl_ipv4_entry_t;

    /**
     * QoS Policy Entry
     * Quality of Service configuration
     */
    typedef struct
    {
        cam_entry_header_t header;   /**< Common entry header */
        uint32_t qos_policy_id;      /**< QoS policy identifier */
        qos_queue_type_t queue_type; /**< Queue scheduling algorithm */
        uint8_t queue_id;            /**< Egress queue ID */
        uint8_t dscp_remark;         /**< DSCP remarking value */
        uint16_t bandwidth_percent;  /**< Bandwidth percentage */
        uint32_t rate_limit_bps;     /**< Rate limit in bits per second */
        uint32_t burst_size;         /**< Burst size in bytes */
    } cam_qos_entry_t;

    /* ===== Table Capacity Configuration ===== */

    /**
     * UFT Capacity Profile
     * Defines hardware resource allocation for different operation modes
     */
    typedef struct
    {
        uft_mode_t mode;         /**< Operation mode */
        const char *description; /**< Mode description */

        /* Layer 2 capacities */
        uint32_t max_l2_unicast_entries;   /**< Maximum L2 unicast MAC entries */
        uint32_t max_l2_multicast_entries; /**< Maximum L2 multicast entries */
        uint32_t max_vlan_entries;         /**< Maximum VLAN entries */
        uint32_t max_lag_entries;          /**< Maximum LAG group entries */

        /* IPv4 capacities */
        uint32_t max_ipv4_host_entries;  /**< Maximum IPv4 host routes */
        uint32_t max_ipv4_mcast_entries; /**< Maximum IPv4 multicast entries */
        uint32_t max_ipv4_arp_entries;   /**< Maximum ARP/ND entries */

        /* IPv6 capacities */
        uint32_t max_ipv6_host_entries;  /**< Maximum IPv6 host routes */
        uint32_t max_ipv6_mcast_entries; /**< Maximum IPv6 multicast entries */

        /* LPM table capacities */
        uint32_t max_ipv4_lpm_entries;     /**< Maximum IPv4 LPM entries */
        uint32_t max_ipv6_lpm_entries;     /**< Maximum IPv6 LPM entries */
        uint32_t max_ipv6_64_lpm_entries;  /**< Maximum IPv6 /64 prefixes */
        uint32_t max_ipv6_128_lpm_entries; /**< Maximum IPv6 /128 host routes */

        /* Policy capacities */
        uint32_t max_acl_entries;    /**< Maximum ACL entries */
        uint32_t max_qos_entries;    /**< Maximum QoS entries */
        uint32_t max_policy_entries; /**< Maximum policy rules */
        uint32_t max_meter_entries;  /**< Maximum traffic policers */

        /* Tunnel capacities */
        uint32_t max_tunnel_entries;    /**< Maximum tunnel entries */
        uint32_t max_vxlan_vni_entries; /**< Maximum VXLAN VNI entries */
        uint32_t max_mpls_entries;      /**< Maximum MPLS label entries */

        /* Forwarding capacities */
        uint32_t max_ecmp_groups;            /**< Maximum ECMP groups */
        uint32_t max_nexthop_entries;        /**< Maximum next-hop entries */
        uint32_t max_ecmp_members_per_group; /**< Maximum members per ECMP group */

        /* Monitoring capacities */
        uint32_t max_statistics_entries; /**< Maximum statistics counters */
        uint32_t max_mirror_entries;     /**< Maximum mirror sessions */
        uint32_t max_sflow_entries;      /**< Maximum sFlow sampling entries */

        /* Security capacities */
        uint32_t max_dos_entries;       /**< Maximum DoS protection entries */
        uint32_t max_blackhole_entries; /**< Maximum blackhole routes */

        /* Total capacity limits */
        uint32_t total_shared_entries;    /**< Total shared UFT entries */
        uint32_t reserved_system_entries; /**< System-reserved entries */
        uint32_t available_user_entries;  /**< User-available entries */

        /* Memory characteristics */
        uint32_t hash_table_size;    /**< Hash table size */
        uint32_t bank_configuration; /**< Memory bank configuration */
        uint32_t entry_width_bits;   /**< Bits per TCAM entry */
    } uft_capacity_profile_t;

    /**
     * CAM Table Utilization Tracking
     * Monitors resource usage across different entry types
     */
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

    /**
     * CAM Table Performance Statistics
     * Tracks operational metrics for monitoring and debugging
     */
    typedef struct
    {
        ATOMIC_U64 entries_learned;     /**< Total entries learned */
        ATOMIC_U64 entries_aged_out;    /**< Entries removed by aging */
        ATOMIC_U64 entries_deleted;     /**< Entries explicitly deleted */
        ATOMIC_U64 entries_moved;       /**< Entries that changed ports */
        ATOMIC_U64 lookup_requests;     /**< Total lookup operations */
        ATOMIC_U64 lookup_hits;         /**< Successful lookups */
        ATOMIC_U64 lookup_misses;       /**< Failed lookups */
        ATOMIC_U64 hardware_errors;     /**< Hardware synchronization errors */
        ATOMIC_U64 allocation_failures; /**< Memory allocation failures */
    } cam_table_stats_t;

    /**
     * CAM Search Statistics
     * Performance metrics for search operations
     */
    typedef struct __attribute__((packed, aligned(8)))
    {
        ATOMIC_U64 searches;        /**< Total search operations */
        ATOMIC_U64 hits;            /**< Successful searches */
        ATOMIC_U64 misses;          /**< Failed searches */
        ATOMIC_U64 collisions;      /**< Hash collisions */
        uint32_t hit_ratio_percent; /**< Hit ratio percentage */
    } cam_search_stats_t;

    /**
     * Unified CAM Table Entry
     * Union of all possible entry types with common header
     */
    typedef struct cam_table_entry
    {
        cam_entry_header_t header; /**< Common entry metadata */
        union
        {
            cam_l2_entry_t l2_entry;                 /**< Layer 2 MAC entry */
            cam_l3_ipv4_host_entry_t l3_ipv4_host;   /**< IPv4 host route */
            cam_l3_ipv4_lpm_entry_t l3_ipv4_lpm;     /**< IPv4 LPM route */
            cam_l3_ipv6_lpm_entry_t l3_ipv6_lpm;     /**< IPv6 LPM route */
            cam_l3_ipv4_mcast_entry_t l3_ipv4_mcast; /**< IPv4 multicast */
            cam_acl_ipv4_entry_t acl_entry;          /**< IPv4 ACL entry */
            cam_qos_entry_t qos_entry;               /**< QoS policy entry */
            uint8_t raw_data[128];                   /**< Raw data for hardware */
        } data;
    } cam_table_entry_t;

    /**
     * Unified Forwarding Table Structure
     * Hardware-focused table with performance counters
     */
    typedef struct uft_table
    {
        uft_mode_t mode;                 /**< Current forwarding mode */
        uft_capacity_profile_t capacity; /**< Capacity profile */

        /* Hardware entries */
        uft_hw_entry_t *entries; /**< Hardware entry array */
        uint32_t entry_count;    /**< Current entry count */
        uint32_t max_entries;    /**< Maximum hardware entries */

        /* Performance statistics */
        ATOMIC_U64 lookups; /**< Total lookup operations */
        ATOMIC_U64 hits;    /**< Successful lookups */

        /* Synchronization */
        pthread_mutex_t lock; /**< Table access mutex */

        // L2_HASH_TABLE *hash_table; /**< Hash table for L2 lookups */
    } uft_table_t;

    /* Ensure proper alignment for atomic operations */
    static_assert(sizeof(cam_search_stats_t) % 8 == 0, "Bad alignment for atomics");

    /* ===== Function Pointer Types ===== */

    /** Callback for entry iteration operations */
    typedef bool (*cam_entry_callback_t)(const cam_entry_header_t *entry, void *user_data);

    /** Comparison function for entry sorting and searching */
    typedef int (*cam_compare_func_t)(const void *entry1, const void *entry2, void *user_data);

    /** Logging function for system messages */
    typedef void (*cam_log_func_t)(const char *message, int level);

    /* ===== Main CAM Table Management Structure ===== */

    /**
     * CAM Table Manager
     * Main control structure for the entire CAM table system
     */
    typedef struct cam_table_manager
    {
        /* Configuration */
        uft_mode_t current_mode;                 /**< Current forwarding mode */
        uft_capacity_profile_t capacity_profile; /**< Capacity configuration */
        aging_timer_t aging_time;                /**< Current aging timer setting */
        cam_entry_callback_t cam_entry;          /**< Entry processing callback */
        uft_table_t *uft_table;                  /**< Hardware table reference */
        cam_table_t *cam_table;                  /**< Software table reference */

        /* Statistics */
        cam_table_stats_t stats;             /**< Performance statistics */
        cam_table_utilization_t utilization; /**< Resource utilization */
        time_t last_stat_reset;              /**< Last statistics reset time */

        /* Event callbacks */
        cam_entry_callback_t learn_callback;  /**< Entry learning callback */
        cam_entry_callback_t age_callback;    /**< Entry aging callback */
        cam_entry_callback_t delete_callback; /**< Entry deletion callback */
        cam_log_func_t log_callback;          /**< Logging callback */

        /* Internal state */
        bool initialized;           /**< System initialization flag */
        bool hardware_sync_enabled; /**< Hardware synchronization enabled */
        uint32_t magic_number;      /**< Magic number for validation */
    } cam_table_manager_t;

    /* ===== API Function Declarations ===== */

    /**
     * Lookup Operations
     * Perform forwarding decisions based on packet information
     */

    /* L2 MAC address lookup */
    int uft_l2_lookup(uft_table_t *table, const mac_address_t *mac, uint16_t vlan_id,
                      packet_action_t *action, uint32_t *port);

    /* L3 IPv4 route lookup */
    int uft_l3_ipv4_lookup(uft_table_t *table, ipv4_addr_t dst_ip,
                           packet_action_t *action, ipv4_addr_t *next_hop);

    /* L3 IPv6 route lookup */
    int uft_l3_ipv6_lookup(uft_table_t *table, const ipv6_addr_t *dst_ip,
                           packet_action_t *action, ipv6_addr_t *next_hop);

    /* ACL policy lookup */
    int uft_acl_lookup(uft_table_t *table, const packet_info_t *pkt_info,
                       packet_action_t *action, acl_action_t *acl_action);

    /**
     * Entry Addition Operations
     * Add new forwarding entries to the table
     */

    int uft_add_l2_entry(uft_table_t *table, const mac_address_t *mac, uint16_t vlan_id,
                         uint32_t port, packet_action_t action);

    int uft_add_l3_ipv4_entry(uft_table_t *table, ipv4_addr_t dst_ip, ipv4_addr_t next_hop,
                              packet_action_t action);

    int uft_add_acl_entry(uft_table_t *table, const cam_acl_ipv4_entry_t *acl_entry);

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
    // int cam_table_add_l2_entry(cam_table_manager_t *manager, const cam_l2_entry_t *entry);
    int cam_table_add_l3_ipv4_host_entry(cam_table_manager_t *manager, const cam_l3_ipv4_host_entry_t *entry);
    int cam_table_add_l3_ipv4_lpm_entry(cam_table_manager_t *manager, const cam_l3_ipv4_lpm_entry_t *entry);
    int cam_table_add_acl_entry(cam_table_manager_t *manager, const cam_acl_ipv4_entry_t *entry);

    int cam_table_delete_entry(cam_table_manager_t *manager, uint32_t index);
    int cam_table_delete_entry_by_content(cam_table_manager_t *manager, const cam_entry_header_t *entry);
    int cam_table_clear_entries(cam_table_manager_t *manager, cam_entry_type_t type);

    /* Search and Lookup Operations */
    // int cam_table_find_l2_entry(const cam_table_manager_t *manager, const mac_address_t *mac, uint16_t vlan_id, cam_l2_entry_t *result);
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

    /* UFT Learning Function */
    uft_capacity_profile_t *cam_table_uft_learn(uint32_t uft_modes);

    /* ===== Inline Utility Functions ===== */

    /**
     * Compare two MAC addresses for equality
     * @param mac1 First MAC address to compare
     * @param mac2 Second MAC address to compare
     * @return true if addresses are identical, false otherwise
     */
    static inline bool mac_address_equals(const mac_address_t *mac1, const mac_address_t *mac2)
    {
        return memcmp(mac1->bytes, mac2->bytes, MAC_ADDRESS_LENGTH) == 0;
    }

    /**
     * Check if MAC address is all zeros (uninitialized)
     * @param mac MAC address to check
     * @return true if address is all zeros, false otherwise
     */
    static inline bool mac_address_is_zero(const mac_address_t *mac)
    {
        static const uint8_t zero_mac[MAC_ADDRESS_LENGTH] = {0};
        return memcmp(mac->bytes, zero_mac, MAC_ADDRESS_LENGTH) == 0;
    }

    /**
     * Check if MAC address is multicast
     * @param mac MAC address to check
     * @return true if multicast bit is set, false otherwise
     */
    static inline bool mac_address_is_multicast(const mac_address_t *mac)
    {
        return (mac->bytes[0] & 0x01) != 0;
    }

    /**
     * Check if MAC address is broadcast (all ones)
     * @param mac MAC address to check
     * @return true if address is broadcast, false otherwise
     */
    static inline bool mac_address_is_broadcast(const mac_address_t *mac)
    {
        static const uint8_t broadcast_mac[MAC_ADDRESS_LENGTH] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        return memcmp(mac->bytes, broadcast_mac, MAC_ADDRESS_LENGTH) == 0;
    }

    /**
     * Check if IPv4 address is all zeros
     * @param ip IPv4 address to check
     * @return true if address is zero, false otherwise
     */
    static inline bool ipv4_address_is_zero(ipv4_addr_t ip)
    {
        return ip == 0;
    }

    /**
     * Check if IPv4 address is multicast
     * @param ip IPv4 address to check
     * @return true if address is in multicast range, false otherwise
     */
    static inline bool ipv4_address_is_multicast(ipv4_addr_t ip)
    {
        return (ip & 0xF0000000) == 0xE0000000;
    }

#ifdef __cplusplus
}
#endif

#endif /* CAM_TABLE_H */

#include "hash.h"