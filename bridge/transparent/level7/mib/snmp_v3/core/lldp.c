#include "lldp.h"

int lldp_init(const char *interface) {
    lldp_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    ioctl(lldp_socket, SIOCGIFINDEX, &ifr);
    
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_LLDP);
    
    bind(lldp_socket, (struct sockaddr*)&sll, sizeof(sll));
}
