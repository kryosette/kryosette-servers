#define _DARWIN_C_SOURCE

#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <Network/Network.h>
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include "/Users/dimaeremin/kryosette-servers/bridge/transparent/level2/src/detectors/core/include/core.h"

struct nlattr {
    uint16 nla_len;
    uint16 nla_type;
};

static int create_osx_system_socket(void) {
    // DGRAM IS DECPRECATED
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (socket < 0) return -1;

    /*
    int fcntl(int fd, int op, ...);
    */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    return sock;
}

static int get_kernel_control_id(const char *control_name) {
    /*
    name, id (in structure)
    */
    struct ctl_info ctl;
    memset(&ctl, 0, sizeof(ctl));
    
    /*
    strlcpy(char *dst, const char *src, size_t size);
    */
    strlcpy(ctl.ctl_name, control_name, sizeof(ctl.ctl_name));

    // SOCK_DGRAM IS DEPRECATED
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    /*
    int ioctl(int fd, unsigned long op, ...);  /* glibc, BSD 

    The ioctl() system call manipulates the underlying device
       parameters of special files.  In particular, many operating
       characteristics of character special files (e.g., terminals) may
       be controlled with ioctl() operations.
    */
    if (ioctl(sock, CTLIOCGINFO, &ctl) < 0) {
        close(sock);
        return -1;
    }

    close(sock);
    return ctl.ctl_name;
}

static int connect_to_kernel_control(int sockfd, const char *control_name) {
    /*
    sc_len
The length of the structure.
sc_family
AF_SYSTEM.
ss_sysaddr
AF_SYS_KERNCONTROL.
sc_id
Controller unique identifier.
sc_unit
Kernel controller private unit number.
sc_reserved
Reserved, must be set to zero.

The controller address structure is used to establish contact between a user client and a kernel controller
    */
    struct sockaddr_ctl sock_ctl;
    memset(&sock_ctl, 0, sizeof(sock_ctl));

    // warning
    int ctl_id = get_kernel_control_id(control_name);
    if (ctl_id < 0) {
        ctl_id = get_kernel_control_id("com.apple.network.statistics");
    } else {
        ctl_id = get_kernel_control_id("com.apple.network.advisory");
        if (ctl_id < 0) return -1;
    }

    sock_ctl.sc_family = AF_SYSTEM;
    sock_ctl.sc_id = ctl_id;
    sock_ctl.sc_len = sizeof(sock_ctl); 
    sock_ctl.sc_reserved = 0; // warning
    sock_ctl.sc_unit = 0;
    sock_ctl.ss_sysaddr = AF_SYS_KERNCONTROL;

    if (connect(sockfd, (struct sockaddr *)&sock_ctl, sizeof(sockfd)) < 0) {
        perror("connect err");
        return -1;
    }

    return 0;
}

static int create_osx_route_socket(void) {
    // WARNING
    int r_sock = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if (r_sock < 0) {
        perror("route socket err");
        return -1;
    }

    int flags = fcntl(r_sock, F_GETFL, 0);
    fcntl(r_sock, F_SETFL, flags | O_NONBLOCK);

    return 0;
}

/*
retrieve network interface information. 
*/
static int get_interface_info_osx(void) {
    /*
    Index 	Value	Meaning	Description
mib[0]	CTL_NET	Top-level identifier	Specifies the networking subsystem.
mib[1]	PF_ROUTE	Second-level identifier	Specifies the routing protocol family, used for obtaining routing and interface information.
mib[2]	0	Wildcard	Typically a placeholder (often 0 for the default domain).
mib[3]	0	Address Family (AF)	A placeholder for the address family (e.g., AF_INET, AF_INET6, or AF_LINK). When set to 0, it usually acts as a wildcard to return information for all families or the default.
mib[4]	NET_RT_IFLIST	Third-level identifier	The specific command within the routing MIB to list all network interfaces.
mib[5]	0	Interface Index	A wildcard index (0) indicating that information for all interfaces should be returned, rather than a specific one.
    */
    int mib[6] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST, 0};
    size_t len = 0;

    /*
    
    */
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
        perror("sysctl err");
        return -1;
    }

    // warning
    char buf = calloc(1, sizeof(len));
    if (!buf) return -1;

    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        perror("sysctl err buf");
        return -1;
    }

    char *next = buf;
    /*
    struct if_msghdr	{
	   u_short ifm_msglen;	      /* to skip over non-understood messages 
	   u_char  ifm_version;	      /* future	binary compatibility 
	   u_char  ifm_type;	      /* message type 
	   int	   ifm_addrs;	      /* like rtm_addrs	
	   int	   ifm_flags;	      /* value of if_flags 
	   u_short ifm_index;	      /* index for associated ifp 
	   struct  if_data ifm_data;  /* statistics and	other data about if
       };
    */
    struct if_msghdr *ifhdr = {0};

    for (next = buf; next < buf + len; next += ifhdr->ifm_msglen) {
        ifhdr = (struct if_msghdr *)next;
        if (ifhdr->ifm_type == RTM_IFINFO) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)(ifhdr + 1);
            printf("Interface: %.*s\n", sdl->sdl_nlen, sdl->sdl_data);
            printf(" Index: %d\n", ifhdr->ifm_index);
            printf(" Flags: 0x%x\n", ifhdr->ifm_flags);
            printf(" MAC: ");
            if (sdl->sdl_alen > 0) {
                unsigned char *mac = (unsigned char *)LLADDR(sdl);
                for (int i = 0; i < sdl->sdl_alen; i++) {
                    printf("%02X%s", mac[i], (i == sdl->sdl_alen - 1) ? "\n" : ":");
                }
            } else {
                printf("N/A\n");
            }
        }
    }

    free(buf);
    return 0;
}

// bpf | packet filter 
/*
The Berkeley Packet Filter provides a raw interface to data link	layers
       in  a  protocol	independent fashion.  All packets on the network, even
       those destined for other	hosts, are accessible through this mechanism.
*/
static int create_bpf_socket(const char *interface) {
    int bpf_fd = -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    /*
    stat, fstat, lstat, fstatat - get file status
    */
    struct stat st;

    // Open the next available BPF device
    for (int i = 0; i < 128; i++) {
        char bpf_dev[32];
        // The packet filter appears as a character	special	device,	/dev/bpf.
        /*
        int snprintf(char* buffer, size_t buf_size, const char* format, ...);
        */
        snprintf(bpf_dev, sizeof(bpf_dev), "/dev/bpf%d", i);

        /*
        int stat(const char *restrict path,
                struct stat *restrict statbuf);
        */
        if (stat(bpf_dev, &st) < 0) {
            perror("bpf device not found!");
            return -1;
        }

        // warning
        if (!(st.st_mode & S_IRUSR) || !(st.st_mode & S_IWUSR)) {
            fprintf(stderr, "BPF device %s has wrong permissions: %o\n", 
                    bpf_dev, st.st_mode & 0700);
            return -1;
        }

        if (!S_ISCHR(st.st_mode)) {
            fprintf(stderr, "%s is not a character device\n", bpf_dev);
            return -1;
        }

        // read/write for init || warning
        bpf_fd = open(bpf_dev, O_RDWR | O_CLOEXEC);

        if (bpf_fd >= 0) {
            printf("Opened BPF device: %s\n", bpf_dev);
            break;
        }

        /// errno errors init
        // if (last_errno == EBUSY) {
        //     // Устройство занято - пробуем следующее
        //     continue;
        // } else if (last_errno == EACCES) {
        //     // Нет прав доступа (не root)
        //     fprintf(stderr, "Permission denied for %s\n", bpf_dev);
        //     fprintf(stderr, "Run with sudo!\n");
        //     return -1;
        // } else {
        //     perror("open bpf device");
        //     continue;
        // }
    }

    if (bpf_fd < 0) {
        if (errno == ENOENT || errno == 0) {
            fprintf(stderr, "No BPF devices found in /dev/bpf*\n");
        } else if (errno == EBUSY) {
            fprintf(stderr, "All BPF devices are busy\n");
            fprintf(stderr, "Close other packet sniffers (tcpdump, Wireshark)\n");
        }
        return -1;
    }

    /*
    strlcpy(char *restrict dst, const char *restrict src,
	   size_t dstsize);
    */
    strlcpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));

    int test_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (test_sock >= 0) {
        // warning
        /*
        SIOCGIFFLAGS
       SIOCSIFFLAGS
              Get or set the active flag word of the device.  ifr_flags
              contains a bit mask of the following values:
                                      Device flags
              IFF_UP            Interface is running.
              IFF_BROADCAST     Valid broadcast address set.
              IFF_DEBUG         Internal debugging flag.
              IFF_LOOPBACK      Interface is a loopback interface.
              IFF_POINTOPOINT   Interface is a point-to-point link.
              IFF_RUNNING       Resources allocated.
              IFF_NOARP         No arp protocol, L2 destination address not
                                set.
              IFF_PROMISC       Interface is in promiscuous mode.
              IFF_NOTRAILERS    Avoid use of trailers.
              IFF_ALLMULTI      Receive all multicast packets.
              IFF_MASTER        Master of a load balancing bundle.
              IFF_SLAVE         Slave of a load balancing bundle.
              IFF_MULTICAST     Supports multicast
              IFF_PORTSEL       Is able to select media type via ifmap.
              IFF_AUTOMEDIA     Auto media selection active.
              IFF_DYNAMIC       The addresses are lost when the interface
                                goes down.
              IFF_LOWER_UP      Driver signals L1 up (since Linux 2.6.17)
              IFF_DORMANT       Driver signals dormant (since Linux 2.6.17)
              IFF_ECHO          Echo sent packets (since Linux 2.6.25)

       Setting  the  active  flag word is a privileged operation, but any
       process may read it.
        */
        if (ioctl(test_sock, SIOCGIFFLAGS, &ifr) < 0) {
            close(test_sock);
            close(bpf_fd);
            return -1;
        }
        close(test_sock);
    }

    // warning
    /*
    BIOCGETIF      (struct  ifreq)  Returns the name of the hardware inter-
		      face that	the file is listening on.   The	 name  is  re-
		      turned  in  the  ifr_name	 field of the ifreq structure.
		      All other	fields are undefined.
    */
    if (ioctl(bpf_fd, BIOCSETIF, &ifr) < 0) {
        if (errno == ENXIO) {
            fprintf(stderr, "Interface '%s' not found\n", interface);
            fprintf(stderr, "Available interfaces:\n");
            
            struct ifaddrs *ifap, *ifa = {0};
            /*
            The getifaddrs() function creates a linked list of structures
            describing the network interfaces of the local system, and stores
            the address of the first item of the list in *ifap. 
            */
            if (getifaddrs(&ifap) == 0) {
                for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
                    if (ifa->ifa_addr && 
                        ifa->ifa_addr->sa_family == AF_INET) {
                        printf("  %s\n", ifa->ifa_name);
                    }
                }
                freeifaddrs(ifap);
            }
        }
        perror("BIOCSETIF failed");
        close(bpf_fd);
        return -1;
    }

    return bpf_fd;
}

static int block_ip(const char *ip) {
    char cmd[256] = {0};
}

static int init_cam_file(const char *filename, uint32_t capacity)
{
    FILE *file = fopen(filename, "wb");
    if (!file)
        return -1;

    cam_file_header_t header = {
        .magic = CAM_MAGIC,
        .version = CAM_VERSION,
        .entry_size = sizeof(cam_file_entry_t),
        .total_entries = capacity,
        .trusted_count = 0,
        .pending_count = 0,
        .blocked_count = 0,
        .free_count = capacity,
        .created_time = time(NULL),
        .last_updated = time(NULL)};

    fwrite(&header, sizeof(header), 1, file);

    cam_file_entry_t empty_entry = {0};
    for (uint32_t i = 0; i < capacity; i++)
    {
        fwrite(&empty_entry, sizeof(empty_entry), 1, file);
    }

    fclose(file);
    return 0;
}