#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <signal.h>

typedef struct
{
    uint32_t ip;
    unsigned char mac[6];
} trusted_pair_t;

trusted_pair_t trusted_list[] = {
    {.ip = inet_addr("192.168.1.1"), .mac = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
    {.ip = inet_addr("192.168.1.100"), .mac = {0x08, 0x00, 0x27, 0x96, 0x20, 0x39}},
};

#define NUM_TRUSTED (sizeof(trusted_list) / sizeof(trusted_list[0]))