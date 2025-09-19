#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <errno.h>

#include "bridge.h"
#include "llc.h"
#include "llc_snap.h"
#include "types.h"

int bridge_init(network_interface_t *iface, const char *iface_name)
{
    if (!iface || !iface_name)
    {
        fprintf(stderr, "Invalid parameters\n");
        return -1;
    }

    iface->sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (iface->sock_fd == -1)
    {
        perror("socket creation failed");
        return -1;
    }

    iface->iface_index = if_nametoindex(iface_name);
    if (iface->iface_index == 0)
    {
        perror("if_nametoindex failed");
        close(iface->sock_fd);
        return -1;
    }

    strncpy(iface->iface_name, iface_name, IFNAMSIZ - 1);
    iface->iface_name[IFNAMSIZ - 1] = '\0';

    memset(&iface->addr, 0, sizeof(iface->addr));
    iface->addr.sll_family = AF_PACKET;
    iface->addr.sll_protocol = htons(ETH_P_ALL);
    iface->addr.sll_ifindex = iface->iface_index;

    if (bind(iface->sock_fd, (struct sockaddr *)&iface->addr, sizeof(iface->addr)) == -1)
    {
        perror("bind failed");
        close(iface->sock_fd);
        return -1;
    }

    return 0;
}

void bridge_cleanup(network_interface_t *iface)
{
    if (iface && iface->sock_fd != -1)
    {
        close(iface->sock_fd);
        iface->sock_fd = -1;
    }
}

int bridge_set_promiscuous(network_interface_t *iface)
{
    struct packet_mreq mr;

    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = iface->iface_index;
    mr.mr_type = PACKET_MR_PROMISC;

    if (setsockopt(iface->sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1)
    {
        perror("setsockopt promiscuous mode failed");
        return -1;
    }

    return 0;
}

int bridge_receive_frame(network_interface_t *iface, uint8_t *buffer, size_t buffer_size)
{
    ssize_t received = recvfrom(iface->sock_fd, buffer, buffer_size, 0, NULL, NULL);

    if (received < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            perror("recvfrom failed");
        }
        return -1;
    }

    return (int)received;
}

int main()
{
    network_interface_t iface = {0};
    uint8_t frame_buffer[MAX_FRAME_SIZE];

    if (bridge_init(&iface, DEFAULT_INTERFACE) != 0)
    {
        fprintf(stderr, "Failed to initialize bridge\n");
        return EXIT_FAILURE;
    }

    if (bridge_set_promiscuous(&iface) != 0)
    {
        bridge_cleanup(&iface);
        return EXIT_FAILURE;
    }

    printf("Мост запущен, слушаю интерфейс %s (index: %d)...\n",
           iface.iface_name, iface.iface_index);

    while (1)
    {
        int frame_size = bridge_receive_frame(&iface, frame_buffer, MAX_FRAME_SIZE);

        if (frame_size > 0)
        {
            int should_drop = process_ethernet_frame(frame_buffer, frame_size, iface.iface_index);

            if (!should_drop)
            {
                if (bridge_forward_frame(frame_buffer, frame_size, BACKUP_INTERFACE) != 0)
                {
                    fprintf(stderr, "Failed to forward frame\n");
                }
            }
            else
            {
                printf("Блокирую кадр!\n");
            }
        }

        usleep(1000);
    }

    bridge_cleanup(&iface);
    return EXIT_SUCCESS;
}