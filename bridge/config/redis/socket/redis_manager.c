#include "redis_manager.h"
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static redis_connection_t redis_conn = {NULL, 0};

int redis_manager_init(void)
{
    redis_conn.context = NULL;
    redis_conn.connected = 0;
    printf("⚠️  Redis manager: Running in stub mode (hiredis not available)\n");
    return 1; // Всегда успешно для заглушки
}

void redis_manager_cleanup(void)
{
    if (redis_conn.context)
    {
        free(redis_conn.context);
        redis_conn.context = NULL;
    }
    redis_conn.connected = 0;
}

int is_redis_connected(void)
{
    return redis_conn.connected;
}

int is_redis_socket_available(void)
{
    struct stat st;
    return (stat(get_redis_socket_path(), &st) == 0 && S_ISSOCK(st.st_mode)) ||
           (stat(get_redis_socket_backup_path(), &st) == 0 && S_ISSOCK(st.st_mode));
}

int redis_connect_safe(void)
{
    printf("⚠️  Redis: Running in stub mode, cannot connect to Redis\n");
    redis_conn.connected = 0;
    return 0;
}

int is_valid_ip(const char *ip)
{
    if (!ip || strlen(ip) > 15 || strlen(ip) < 7)
    {
        return 0;
    }

    if (strstr(ip, "..") || strstr(ip, "--") || strstr(ip, "\\") ||
        strstr(ip, ";") || strstr(ip, "|") || strstr(ip, "`"))
    {
        return 0;
    }

    return 1;
}

int is_valid_device_hash(const char *hash)
{
    if (!hash || strlen(hash) != get_device_hash_size())
    {
        return 0;
    }

    for (size_t i = 0; i < get_device_hash_size(); i++)
    {
        if (!isxdigit((unsigned char)hash[i]))
        {
            return 0;
        }
    }
    return 1;
}

char *get_device_hash_secure(const char *ip)
{
    if (!is_valid_ip(ip))
    {
        fprintf(stderr, "Invalid IP address: %s\n", ip ? ip : "NULL");
        return NULL;
    }

    static char device_hash[128] = {0};

    // В режиме заглушки возвращаем фиктивный хэш для тестирования
    // В реальной системе здесь должен быть вызов Redis
    snprintf(device_hash, sizeof(device_hash), "stub_device_hash_%s", ip);

    printf("⚠️  Redis stub: Using fake device hash for IP: %s\n", ip);

    if (is_valid_device_hash(device_hash))
    {
        return device_hash;
    }

    return NULL;
}

void get_redis_connection_stats(int *connected, int *err, const char **err_str)
{
    *connected = redis_conn.connected;
    *err = 1; // Всегда ошибка в режиме заглушки
    *err_str = "Redis stub mode - hiredis not available";
}