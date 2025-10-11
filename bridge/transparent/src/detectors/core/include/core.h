#pragma once
#ifndef CORE_H
#define CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>

#include "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/transparent/src/ethernet/fdb/core/cam_table/include/cam_table_operations.h"

// ===== GLOBAL VARIABLES =====
extern volatile sig_atomic_t stop_monitoring;

// ===== CAM TABLE CONSTANTS =====
#define CAM_MAGIC 0xCA7AB1E     /* Magic number for CAM file validation */
#define CAM_VERSION 1           /* CAM file format version */
#define DEFAULT_CAPACITY 256000 /* Default capacity for CAM table entries */

// ===== BLOCKING LEVELS =====
#define BLOCK_LEVEL_PENDING 1
#define BLOCK_LEVEL_HARD 2
#define BLOCK_LEVEL_PERMANENT 3

// ===== CAM FILE STRUCTURES =====
#pragma pack(push, 1)
/**
 * struct cam_file_header_t - CAM table file header structure
 * @magic: magic number for file validation
 * @version: file format version
 * @entry_size: size of each CAM entry in bytes
 * @total_entries: total number of entries in table
 * @trusted_count: number of trusted MAC entries
 * @pending_count: number of pending MAC entries
 * @blocked_count: number of blocked MAC entries
 * @free_count: number of free slots available
 * @created_time: timestamp of table creation
 * @last_updated: timestamp of last modification
 * @reserved: reserved space for future expansion
 *
 * Represents the header of a persistent CAM table file.
 */
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

/**
 * struct cam_file_entry_t - CAM table entry structure
 * @entry_type: type of CAM entry (trusted/pending/blocked)
 * @mac: MAC address in network byte order
 * @status: current status of the entry
 * @vlan_id: VLAN identifier
 * @port_map: bitmap of ports where MAC was seen
 * @timestamp: entry creation timestamp
 * @last_seen: last time MAC was observed
 * @hit_count: number of times MAC was seen
 * @attack_score: security threat assessment score
 * @flags: various status flags
 * @reason_offset: offset to reason string in file
 * @reserved: reserved padding
 * @reason: textual reason for block/pending status
 * @ip_address: associated IP address if known
 * @block_time: when blocking was initiated
 * @block_duration: duration of block in seconds
 *
 * Represents a single MAC address entry in the CAM table.
 */
typedef struct
{
    uint8_t entry_type;
    uint8_t mac[6];
    uint8_t status;
    uint16_t vlan_id;
    uint32_t port_map;
    uint32_t timestamp;
    time_t last_seen;
    uint16_t hit_count;
    uint8_t attack_score;
    uint8_t flags;
    uint32_t reason_offset;
    uint8_t reserved[4];
    char reason[100];
    char ip_address[16];
    time_t block_time;
    int block_duration;
} cam_file_entry_t;
#pragma pack(pop)

// ===== STRUCTURES =====
/**
 * struct ip_mac_mapping_t - IP to MAC address mapping
 * @ip: IP address in string format
 * @mac: corresponding MAC address
 * @last_seen: last time this mapping was observed
 * @block_count: number of times this IP was blocked
 *
 * Maintains dynamic mapping between IP and MAC addresses.
 */
typedef struct
{
    char ip[16];
    uint8_t mac[6];
    time_t last_seen;
    int block_count;
} ip_mac_mapping_t;

/**
 * struct blocked_ip_t - Blocked IP address entry
 * @ip: blocked IP address
 * @mac: corresponding MAC address
 * @block_time: when block was initiated
 * @block_duration: duration of block in seconds
 * @reason: reason for blocking
 *
 * Represents an actively blocked IP address with metadata.
 */
typedef struct
{
    char ip[16];
    uint8_t mac[6];
    time_t block_time;
    int block_duration;
    int block_level;
    int violation_count;
    char reason[100];
} blocked_ip_t;

/**
 * struct SecurityMetrics - Network security metrics collection
 * @aFramesTransmittedOK: successfully transmitted frames
 * @aFramesReceivedOK: successfully received frames
 * @aOctetsTransmittedOK: octets transmitted successfully
 * @aOctetsReceivedOK: octets received successfully
 * @aFrameCheckSequenceErrors: frame checksum errors
 * @aAlignmentErrors: packet alignment errors
 * @aBroadcastFramesReceivedOK: broadcast frames received
 * @aMulticastFramesReceivedOK: multicast frames received
 * @aBroadcastFramesXmittedOK: broadcast frames transmitted
 * @aMulticastFramesXmittedOK: multicast frames transmitted
 * @estimated_promiscuous: promiscuous mode detection flag
 * @potential_scan_detected: port scan detection flag
 * @syn_packets: SYN packets observed (TCP handshakes)
 * @udp_packets: UDP packets observed
 * @icmp_packets: ICMP packets observed
 * @total_packets: total packets processed
 * @packets_per_second: current packet rate
 * @last_calc_time: last rate calculation timestamp
 * @last_packet_count: packet count at last calculation
 * @attacker_ip: detected attacker IP address
 * @attacker_mac: detected attacker MAC address
 * @attack_detected: attack detection flag
 * @attack_type: description of detected attack type
 *
 * Comprehensive network security and performance metrics.
 */
typedef struct
{
    unsigned long aFramesTransmittedOK;
    unsigned long aFramesReceivedOK;
    unsigned long aOctetsTransmittedOK;
    unsigned long aOctetsReceivedOK;

    unsigned long aFrameCheckSequenceErrors;
    unsigned long aAlignmentErrors;

    unsigned long aBroadcastFramesReceivedOK;
    unsigned long aMulticastFramesReceivedOK;
    unsigned long aBroadcastFramesXmittedOK;
    unsigned long aMulticastFramesXmittedOK;

    int estimated_promiscuous;
    int potential_scan_detected;

    unsigned long syn_packets;
    unsigned long udp_packets;
    unsigned long icmp_packets;
    unsigned long total_packets;
    unsigned long packets_per_second;
    time_t last_calc_time;
    unsigned long last_packet_count;

    char attacker_ip[16];
    uint8_t attacker_mac[6];
    int attack_detected;
    char attack_type[50];
} SecurityMetrics;

/**
 * struct anomaly_detector_t - Anomaly detection system context
 * @baseline: established baseline security metrics
 * @current: current security metrics
 * @previous: previous metrics for trend analysis
 * @anomaly_score: current anomaly detection score
 * @total_anomalies: total anomalies detected
 * @blocked_ips: array of blocked IP addresses
 * @blocked_count: number of currently blocked IPs
 * @ip_mac_map: IP to MAC address mapping table
 * @ip_mac_count: number of active IP-MAC mappings
 * @block_mutex: mutex for blocked IPs operations
 * @map_mutex: mutex for IP-MAC mapping operations
 * @cam_manager: CAM table manager instance
 *
 * Main context structure for network anomaly detection system.
 * Manages security metrics, blocked IPs, and CAM table integration.
 */
typedef struct
{
    SecurityMetrics baseline;
    SecurityMetrics current;
    SecurityMetrics previous;
    int anomaly_score;
    int total_anomalies;

    blocked_ip_t blocked_ips[100];
    int blocked_count;

    ip_mac_mapping_t ip_mac_map[500];
    int ip_mac_count;

    pthread_mutex_t block_mutex;
    pthread_mutex_t map_mutex;

    cam_table_manager_t *cam_manager;
} anomaly_detector_t;

// ===== FUNCTION DECLARATIONS =====
/**
 * handle_signal - Signal handler for graceful shutdown
 * @sig: signal number received
 *
 * Handles termination signals to stop monitoring gracefully.
 * Sets global stop_monitoring flag when called.
 */
void handle_signal(int sig);

/**
 * init_detector - Initialize anomaly detector instance
 * @detector: detector instance to initialize
 * @cam_manager: CAM table manager to associate
 *
 * Initializes all detector fields, mutexes, and associates CAM manager.
 * Must be called before using detector instance.
 */
void init_detector(anomaly_detector_t *detector, cam_table_manager_t *cam_manager);

/**
 * block_ip - Block IP address with specified parameters
 * @ip: IP address to block (string format)
 * @mac: corresponding MAC address to block
 * @reason: reason for blocking
 * @duration: block duration in seconds
 *
 * Blocks specified IP/MAC combination and updates CAM table.
 * Thread-safe operation.
 */
void block_ip(const char *ip, const uint8_t *mac, const char *reason, int duration);

/**
 * unblock_ip - Remove IP address block
 * @ip: IP address to unblock
 *
 * Removes blocking for specified IP and updates CAM table.
 * Thread-safe operation.
 */
void unblock_ip(const char *ip);

/**
 * add_to_block_list - Add IP to detector's block list
 * @detector: anomaly detector instance
 * @ip: IP address to block
 * @mac: MAC address to block
 * @reason: reason for blocking
 *
 * Adds IP/MAC to detector's internal block list with current timestamp.
 * Caller must hold appropriate mutexes.
 */
void add_to_block_list(anomaly_detector_t *detector, const char *ip, const uint8_t *mac, const char *reason);

/**
 * check_block_expiry - Check and remove expired blocks
 * @detector: anomaly detector instance
 *
 * Scans blocked IPs list and removes entries whose block duration has expired.
 * Automatically updates CAM table when unblocking.
 */
void check_block_expiry(anomaly_detector_t *detector);

/**
 * extract_attacker_ip - Extract attacker IP from packet
 * @packet: network packet buffer
 * @ip_buffer: output buffer for IP address (must be 16 bytes)
 *
 * Parses network packet and extracts source IP address.
 * Supports IPv4 packets. Buffer must be pre-allocated.
 */
void extract_attacker_ip(const unsigned char *packet, char *ip_buffer);

/**
 * extract_attacker_mac - Extract attacker MAC from packet
 * @packet: network packet buffer
 * @mac_buffer: output buffer for MAC address (6 bytes)
 *
 * Extracts source MAC address from Ethernet frame.
 * Buffer must be pre-allocated with 6 bytes minimum.
 */
void extract_attacker_mac(const unsigned char *packet, uint8_t *mac_buffer);

/**
 * get_proc_net_stats - Read network statistics from procfs
 * @interface: network interface name
 * @metrics: SecurityMetrics structure to populate
 *
 * Returns: 0 on success, -1 on error
 *
 * Reads current network interface statistics from /proc/net/dev
 * and populates the provided metrics structure.
 */
int get_proc_net_stats(const char *interface, SecurityMetrics *metrics);

/**
 * create_raw_socket - Create raw socket for packet capture
 *
 * Returns: socket file descriptor on success, -1 on error
 *
 * Creates raw socket suitable for packet capture and analysis.
 * Socket is configured for promiscuous mode and packet headers.
 */
int create_raw_socket();

/**
 * analyze_packet - Analyze network packet for security threats
 * @packet: packet data buffer
 * @length: packet length in bytes
 * @metrics: SecurityMetrics to update
 *
 * Parses network packet, updates security metrics, and detects
 * potential attacks based on packet contents and patterns.
 */
void analyze_packet(const unsigned char *packet, int length, SecurityMetrics *metrics);

/**
 * calculate_baseline - Calculate baseline security metrics
 * @detector: anomaly detector instance
 *
 * Establishes baseline network behavior by analyzing current metrics.
 * Used as reference for future anomaly detection.
 */
void calculate_baseline(anomaly_detector_t *detector);

/**
 * detect_anomalies - Detect security anomalies from current metrics
 * @detector: anomaly detector instance
 *
 * Returns: anomaly score (0-100) indicating threat level
 *
 * Compares current metrics against baseline to detect anomalies.
 * Higher scores indicate greater deviation from normal behavior.
 */
int detect_anomalies(anomaly_detector_t *detector);

/**
 * print_blocked_ips - Display currently blocked IP addresses
 * @detector: anomaly detector instance
 *
 * Prints formatted list of all currently blocked IP addresses
 * with their metadata to standard output.
 */
void print_blocked_ips(anomaly_detector_t *detector);

/**
 * update_ip_mac_mapping - Update IP to MAC address mapping
 * @detector: anomaly detector instance
 * @ip: IP address to map
 * @mac: MAC address to associate
 *
 * Maintains dynamic mapping between IP and MAC addresses.
 * Updates last_seen timestamp for existing entries.
 */
void update_ip_mac_mapping(anomaly_detector_t *detector, const char *ip, const uint8_t *mac);

/**
 * find_mac_by_ip - Find MAC address by IP address
 * @detector: anomaly detector instance
 * @ip: IP address to search for
 *
 * Returns: pointer to MAC address if found, NULL otherwise
 *
 * Searches IP-MAC mapping table for specified IP address.
 * Returns corresponding MAC address if mapping exists.
 */
uint8_t *find_mac_by_ip(anomaly_detector_t *detector, const char *ip);

/**
 * security_handle_attack_detection - Handle detected security attack
 * @detector: anomaly detector instance
 * @threat_level: calculated threat level (0-100)
 *
 * Implements security response based on threat level.
 * May trigger blocking, logging, or alerting actions.
 */
void security_handle_attack_detection(anomaly_detector_t *detector, int threat_level);

/**
 * start_comprehensive_monitoring - Start comprehensive network monitoring
 * @interface: network interface to monitor
 * @cam_manager: CAM table manager instance
 *
 * Main monitoring loop. Captures packets, analyzes traffic,
 * detects anomalies, and manages security responses.
 * Runs until termination signal received.
 */
void start_comprehensive_monitoring(const char *interface, cam_table_manager_t *cam_manager);

/* CAM table functions */
/**
 * cam_table_block_mac - Block MAC address in CAM table
 * @manager: CAM table manager instance
 * @mac_bytes: MAC address to block
 * @vlan_id: VLAN identifier
 * @reason: reason for blocking
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Adds MAC address to CAM table with blocked status.
 * Persists blocking reason and updates table statistics.
 */
int cam_table_block_mac(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id, const char *reason);

/**
 * cam_table_unblock_mac - Unblock MAC address in CAM table
 * @manager: CAM table manager instance
 * @mac_bytes: MAC address to unblock
 * @vlan_id: VLAN identifier
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Removes blocked status from MAC address in CAM table.
 * Updates table statistics and maintains audit trail.
 */
int cam_table_unblock_mac(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id);

/**
 * cam_table_set_mac_pending - Set MAC address to pending status
 * @manager: CAM table manager instance
 * @mac_bytes: MAC address to modify
 * @vlan_id: VLAN identifier
 * @reason: reason for pending status
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Sets MAC address to pending status for further analysis.
 * Typically used for suspicious but not confirmed malicious addresses.
 */
int cam_table_set_mac_pending(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id, const char *reason);

void apply_blocking_by_level(const char *ip, const uint8_t *mac, int block_level, const char *reason);
void remove_blocking_by_level(const char *ip, const uint8_t *mac, int block_level);
void print_cam_table();
int is_mac_blocked(const uint8_t *mac_bytes);
void handle_usr1(int sig);

#endif /* CORE_H */