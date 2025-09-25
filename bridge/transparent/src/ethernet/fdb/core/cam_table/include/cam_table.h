#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#define CAM_TABLE_SIZE 8192
#define MAX_AGING_TIME 300
#define MAC_ADDR_LEN 6

typedef struct cam_entry
{
    uint8_t mac[MAC_ADDR_LEN];
    int port;
    time_t last_seen;
    uint32_t packet_count;
    struct cam_entry *next;
} cam_entry_t;

typedef struct
{
    cam_entry_t **buckets;
    pthread_rwlock_t *locks;
    size_t size;
    time_t aging_time;
    uint32_t count;

    uint64_t lookups;
    uint64_t hits;
} cam_table_t;