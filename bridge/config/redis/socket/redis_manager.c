#include "redis_manager.h"
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

static redis_connection_t redis_conn = {NULL, 0};

int redis_manager_init(void)
{
    redis_conn.context = NULL;
    redis_conn.connected = 0;
    return redis_connect_safe();
}

void redis_manager_cleanup(void)
{
    if (redis_conn.context)
    {
        redisFree(redis_conn.context);
        redis_conn.context = NULL;
    }
    redis_conn.connected = 0;
}

int is_redis_connected(void)
{
    return redis_conn.connected && redis_conn.context && !redis_conn.context->err;
}

int is_redis_socket_available(void)
{
    struct stat st;
    return (stat(get_redis_socket_path(), &st) == 0 && S_ISSOCK(st.st_mode)) ||
           (stat(get_redis_socket_backup_path(), &st) == 0 && S_ISSOCK(st.st_mode));
}

int redis_connect_safe(void)
{
    if (is_redis_connected())
    {
        redisReply *reply = redisCommand(redis_conn.context, "PING");
        if (reply && reply->type == REDIS_REPLY_STATUS &&
            strcmp(reply->str, "PONG") == 0)
        {
            freeReplyObject(reply);
            return 1;
        }
        if (reply)
            freeReplyObject(reply);
        redisFree(redis_conn.context);
        redis_conn.context = NULL;
        redis_conn.connected = 0;
    }

    struct timeval timeout = {
        .tv_sec = get_redis_connect_timeout_sec(),
        .tv_usec = get_redis_connect_timeout_usec()};

    // Пробуем основной socket
    redis_conn.context = redisConnectUnixWithTimeout(get_redis_socket_path(), timeout);

    if (redis_conn.context == NULL || redis_conn.context->err)
    {
        if (redis_conn.context)
        {
            fprintf(stderr, "Redis socket error: %s\n", redis_conn.context->errstr);
            redisFree(redis_conn.context);
            redis_conn.context = NULL;
        }

        // Пробуем backup socket
        redis_conn.context = redisConnectUnixWithTimeout(get_redis_socket_backup_path(), timeout);
        if (redis_conn.context == NULL || redis_conn.context->err)
        {
            if (redis_conn.context)
            {
                fprintf(stderr, "Redis backup socket error: %s\n", redis_conn.context->errstr);
                redisFree(redis_conn.context);
            }
            redis_conn.context = NULL;
            redis_conn.connected = 0;
            return 0;
        }
    }

    redis_conn.connected = 1;
    return 1;
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
    redisReply *reply = NULL;

    if (!is_redis_connected() && !redis_connect_safe())
    {
        fprintf(stderr, "Failed to connect to Redis\n");
        return NULL;
    }

    reply = redisCommand(redis_conn.context, "GET ip_device:%s", ip);

    if (!reply)
    {
        redis_conn.connected = 0;
        fprintf(stderr, "Redis command failed\n");
        return NULL;
    }

    if (reply->type == REDIS_REPLY_STRING)
    {
        strncpy(device_hash, reply->str, sizeof(device_hash) - 1);
        device_hash[sizeof(device_hash) - 1] = '\0';
        freeReplyObject(reply);

        if (is_valid_device_hash(device_hash))
        {
            return device_hash;
        }
        else
        {
            fprintf(stderr, "Invalid device hash format: %s\n", device_hash);
        }
    }
    else if (reply->type == REDIS_REPLY_NIL)
    {
        fprintf(stderr, "No device hash found for IP: %s\n", ip);
    }
    else
    {
        fprintf(stderr, "Redis error: Unexpected reply type: %d\n", reply->type);
    }

    freeReplyObject(reply);
    return NULL;
}

void get_redis_connection_stats(int *connected, int *err, const char **err_str)
{
    *connected = redis_conn.connected;
    if (redis_conn.context)
    {
        *err = redis_conn.context->err;
        *err_str = redis_conn.context->errstr;
    }
    else
    {
        *err = 1;
        *err_str = "Not connected";
    }
}