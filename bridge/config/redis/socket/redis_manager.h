#pragma once

#ifndef REDIS_MANAGER_H
#define REDIS_MANAGER_H

#include "constants.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        void *context; // Используем void* вместо redisContext*
        int connected;
    } redis_connection_t;

    // Инициализация и очистка
    int redis_manager_init(void);
    void redis_manager_cleanup(void);

    // Основные операции
    char *get_device_hash_secure(const char *ip);
    int is_redis_connected(void);
    int redis_connect_safe(void);

    // Валидация
    int is_valid_device_hash(const char *hash);
    int is_valid_ip(const char *ip);

    // Статистика
    void get_redis_connection_stats(int *connected, int *err, const char **err_str);
    int is_redis_socket_available(void);

#ifdef __cplusplus
}
#endif

#endif // REDIS_MANAGER_H