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

#include "bridge/transparent/src/ethernet/fdb/core/cam_table/include/cam_table_operations.h"

// ===== GLOBAL VARIABLES =====
extern volatile sig_atomic_t stop_monitoring = 0;

// ===== CAM TABLE CONSTANTS =====
#define CAM_MAGIC 0xCA7AB1E
#define CAM_VERSION 1
#define DEFAULT_CAPACITY 256000

// ===== CAM FILE STRUCTURES =====
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
    uint8_t entry_type;
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

// ===== STRUCTURES =====
typedef struct
{
    char ip[16];
    uint8_t mac[6];
    time_t last_seen;
    int block_count;
} ip_mac_mapping_t;

typedef struct
{
    char ip[16];
    uint8_t mac[6];
    time_t block_time;
    int block_duration;
    char reason[100];
} blocked_ip_t;

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

// ===== GLOBAL VARIABLES =====
extern volatile sig_atomic_t stop_monitoring;

// ===== FUNCTION DECLARATIONS =====
void handle_signal(int sig);
void init_detector(anomaly_detector_t *detector, cam_table_manager_t *cam_manager);
void block_ip(const char *ip, const uint8_t *mac, const char *reason, int duration);
void unblock_ip(const char *ip);
void add_to_block_list(anomaly_detector_t *detector, const char *ip, const uint8_t *mac, const char *reason);
void check_block_expiry(anomaly_detector_t *detector);
void extract_attacker_ip(const unsigned char *packet, char *ip_buffer);
void extract_attacker_mac(const unsigned char *packet, uint8_t *mac_buffer);
int get_proc_net_stats(const char *interface, SecurityMetrics *metrics);
int create_raw_socket();
void analyze_packet(const unsigned char *packet, int length, SecurityMetrics *metrics);
void calculate_baseline(anomaly_detector_t *detector);
int detect_anomalies(anomaly_detector_t *detector);
void print_blocked_ips(anomaly_detector_t *detector);
void update_ip_mac_mapping(anomaly_detector_t *detector, const char *ip, const uint8_t *mac);
uint8_t *find_mac_by_ip(anomaly_detector_t *detector, const char *ip);
void security_handle_attack_detection(anomaly_detector_t *detector, int threat_level);
void start_comprehensive_monitoring(const char *interface, cam_table_manager_t *cam_manager);

// CAM table functions
int cam_table_block_mac(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id, const char *reason);
int cam_table_unblock_mac(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id);
int cam_table_set_mac_pending(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id, const char *reason);

// ===== CAM TABLE UTILITIES =====
static int create_cam_directory()
{
    struct stat st = {0};
    if (stat("/var/lib/cam-table", &st) == -1)
    {
        if (mkdir("/var/lib/cam-table", 0755) == -1)
        {
            if (mkdir("cam-data", 0755) == -1)
            {
                return -1;
            }
        }
    }
    return 0;
}

static int init_cam_file(const char *filename, uint32_t capacity)
{
    FILE *file = fopen(filename, "wb");
    if (!file)
        return -1;

    cam_file_header_t header = {
        .magic = CAM_MAGIC,
        .version = CAM_VERSION,
        .entry_size = sizeof(cam_file_entry_t),
        .total_entries = capacity,
        .trusted_count = 0,
        .pending_count = 0,
        .blocked_count = 0,
        .free_count = capacity,
        .created_time = time(NULL),
        .last_updated = time(NULL)};

    fwrite(&header, sizeof(header), 1, file);

    cam_file_entry_t empty_entry = {0};
    for (uint32_t i = 0; i < capacity; i++)
    {
        fwrite(&empty_entry, sizeof(empty_entry), 1, file);
    }

    fclose(file);
    return 0;
}

#endif /* CORE_H */