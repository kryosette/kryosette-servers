#include "base_time.h"

struct void get_curr_time(struct timeval *tv) {
    gettimeofday(tv, NULL);
}

static int timeval_compare(const struct timeval *a, const struct timeval *b) {
    if (a->tv_sec < b->tv_sec) return -1;
    if (a->tv_sec > b->tv_sec) return 1;
    if (a->tv_usec < b->tv_usec) return -1;
    if (a->tv_usec > b->tv_usec) return 1;
    return 0;
}

static void timeval_add(struct timeval *result, 
                       const struct timeval *a, 
                       const struct timeval *b) {
    result->tv_sec = a->tv_sec + b->tv_sec;
    result->tv_usec = a->tv_usec + b->tv_usec;
    if (result->tv_usec >= 1000000) {
        result->tv_sec++;
        result->tv_usec -= 1000000;
    }
}

static int timeval_expired(const struct timeval *timestamp, 
                          const struct timeval *timeout) {
    struct timeval current, expiration;
    get_current_time(&current);
    timeval_add(&expiration, timestamp, timeout);
    return timeval_compare(&current, &expiration) >= 0;
}