#include "constants.h"

// Redis configuration
const char *REDIS_SOCKET_PATH = "/var/run/redis/redis-server.sock";
const char *REDIS_SOCKET_BACKUP_PATH = "/tmp/redis.sock";
const int REDIS_CONNECT_TIMEOUT_SEC = 1;
const int REDIS_CONNECT_TIMEOUT_USEC = 0;
const size_t DEVICE_HASH_SIZE = 64;

// CAM table configuration
const char *CAM_TABLE_PRIMARY_PATH = "/var/lib/cam-table/cam.bin";
const char *CAM_TABLE_FALLBACK_PATH = "/tmp/cam-table/cam.bin";
const char *CAM_LOG_PATH = "/var/log/cam-table/cam.log";
const uint32_t DEFAULT_CAM_CAPACITY = 1000;

// Network configuration
const char *SOCIAL_NETWORK_API_URL = "http://172.22.224.1:8088/api/v1/auth";
const int CURL_TIMEOUT_SEC = 5;

// Security thresholds - переименованные константы
const int SECURITY_BLOCK_LEVEL_PENDING = 1;
const int SECURITY_BLOCK_LEVEL_HARD = 2;
const int SECURITY_BLOCK_LEVEL_PERMANENT = 3;
const int MAX_VIOLATIONS_PERMANENT = 3;
const int MAX_VIOLATIONS_HARD = 2;

// Timing constants
const int MONITORING_CYCLE_SEC = 3;
const int BLOCK_EXPIRY_CHECK_SEC = 60;
const int BASELINE_COLLECTION_SEC = 8;

// Getters implementation
const char *get_redis_socket_path(void)
{
    return REDIS_SOCKET_PATH;
}

const char *get_redis_socket_backup_path(void)
{
    return REDIS_SOCKET_BACKUP_PATH;
}

int get_redis_connect_timeout_sec(void)
{
    return REDIS_CONNECT_TIMEOUT_SEC;
}

int get_redis_connect_timeout_usec(void)
{
    return REDIS_CONNECT_TIMEOUT_USEC;
}

size_t get_device_hash_size(void)
{
    return DEVICE_HASH_SIZE;
}

const char *get_cam_table_primary_path(void)
{
    return CAM_TABLE_PRIMARY_PATH;
}

const char *get_cam_table_fallback_path(void)
{
    return CAM_TABLE_FALLBACK_PATH;
}

const char *get_cam_log_path(void)
{
    return CAM_LOG_PATH;
}

uint32_t get_default_cam_capacity(void)
{
    return DEFAULT_CAM_CAPACITY;
}

const char *get_social_network_api_url(void)
{
    return SOCIAL_NETWORK_API_URL;
}

int get_curl_timeout_sec(void)
{
    return CURL_TIMEOUT_SEC;
}

int get_block_level_pending(void)
{
    return SECURITY_BLOCK_LEVEL_PENDING;
}

int get_block_level_hard(void)
{
    return SECURITY_BLOCK_LEVEL_HARD;
}

int get_block_level_permanent(void)
{
    return SECURITY_BLOCK_LEVEL_PERMANENT;
}

int get_max_violations_permanent(void)
{
    return MAX_VIOLATIONS_PERMANENT;
}

int get_max_violations_hard(void)
{
    return MAX_VIOLATIONS_HARD;
}

int get_monitoring_cycle_sec(void)
{
    return MONITORING_CYCLE_SEC;
}

int get_block_expiry_check_sec(void)
{
    return BLOCK_EXPIRY_CHECK_SEC;
}

int get_baseline_collection_sec(void)
{
    return BASELINE_COLLECTION_SEC;
}