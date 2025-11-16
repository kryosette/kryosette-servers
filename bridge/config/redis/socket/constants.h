#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // Redis configuration
    extern const char *REDIS_SOCKET_PATH;
    extern const char *REDIS_SOCKET_BACKUP_PATH;
    extern const int REDIS_CONNECT_TIMEOUT_SEC;
    extern const int REDIS_CONNECT_TIMEOUT_USEC;
    extern const size_t DEVICE_HASH_SIZE;

    // CAM table configuration
    extern const char *CAM_TABLE_PRIMARY_PATH;
    extern const char *CAM_TABLE_FALLBACK_PATH;
    extern const char *CAM_LOG_PATH;
    extern const uint32_t DEFAULT_CAM_CAPACITY;

    // Network configuration
    extern const char *SOCIAL_NETWORK_API_URL;
    extern const int CURL_TIMEOUT_SEC;

    // Security thresholds - переименуем чтобы избежать конфликта
    extern const int SECURITY_BLOCK_LEVEL_PENDING;
    extern const int SECURITY_BLOCK_LEVEL_HARD;
    extern const int SECURITY_BLOCK_LEVEL_PERMANENT;
    extern const int MAX_VIOLATIONS_PERMANENT;
    extern const int MAX_VIOLATIONS_HARD;

    // Timing constants
    extern const int MONITORING_CYCLE_SEC;
    extern const int BLOCK_EXPIRY_CHECK_SEC;
    extern const int BASELINE_COLLECTION_SEC;

    // Getters for constants
    const char *get_redis_socket_path(void);
    const char *get_redis_socket_backup_path(void);
    int get_redis_connect_timeout_sec(void);
    int get_redis_connect_timeout_usec(void);
    size_t get_device_hash_size(void);
    const char *get_cam_table_primary_path(void);
    const char *get_cam_table_fallback_path(void);
    const char *get_cam_log_path(void);
    uint32_t get_default_cam_capacity(void);
    const char *get_social_network_api_url(void);
    int get_curl_timeout_sec(void);
    int get_block_level_pending(void);
    int get_block_level_hard(void);
    int get_block_level_permanent(void);
    int get_max_violations_permanent(void);
    int get_max_violations_hard(void);
    int get_monitoring_cycle_sec(void);
    int get_block_expiry_check_sec(void);
    int get_baseline_collection_sec(void);

#ifdef __cplusplus
}
#endif