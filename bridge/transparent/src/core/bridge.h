#ifndef BRIDGE_H
#define BRIDGE_H

#include <net/if.h>
#include <linux/if_packet.h>
#include <stdint.h>
#include <sys/types.h>

#define MAX_FRAME_SIZE 1600
#define DEFAULT_INTERFACE "eth0"
#define BACKUP_INTERFACE "eth1"

typedef struct
{
    int sock_fd;
    struct sockaddr_ll addr;
    char iface_name[IFNAMSIZ];
    int iface_index;
} network_interface_t;

int bridge_init(network_interface_t *iface, const char *iface_name);
void bridge_cleanup(network_interface_t *iface);
int bridge_set_promiscuous(network_interface_t *iface);
int bridge_receive_frame(network_interface_t *iface, uint8_t *buffer, size_t buffer_size);
int bridge_forward_frame(const uint8_t *frame, size_t frame_size, const char *target_interface);
int process_ethernet_frame(uint8_t *buffer, ssize_t data_size, int incoming_port_index);

#endif