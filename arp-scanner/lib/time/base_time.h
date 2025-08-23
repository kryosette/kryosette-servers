#include <sys/time.h>

struct void get_curr_time(struct timeval *tv);
static int timeval_compare(const struct timeval *a, const struct timeval *b);
static void timeval_add(struct timeval *result, 
                       const struct timeval *a, 
                       const struct timeval *b);
static int timeval_expired(const struct timeval *timestamp, 
                          const struct timeval *timeout);