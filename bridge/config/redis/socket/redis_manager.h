#pragma once

#include <hiredis/hiredis.h>
#include "constants.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        redisContext *context;
        int connected;
    } redis_connection_t;

    int redis_manager_init(void);
    void redis_manager_cleanup(void);

    char *get_device_hash_secure(const char *ip);
    int is_redis_connected(void);
    int redis_connect_safe(void);

    int is_valid_device_hash(const char *hash);
    int is_valid_ip(const char *ip);

    void get_redis_connection_stats(int *connected, int *err, const char **err_str);
    int is_redis_socket_available(void);

#ifdef __cplusplus
}
#endif