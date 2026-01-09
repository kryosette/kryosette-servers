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
#include "/Users/dimaeremin/kryosette-servers/third-party/smemset/include/smemset.h"
#include "/Users/dimaeremin/kryosette-servers/bridge/transparent/level2/src/detectors/core/include/core_darwin.h"
#include <stdbool.h>

static const uint32_t CAM_MAGIC_NUMBER = 0xC4D3F00D; 
static const uint16_t CAM_VERSION_NUMBER = 0x0001; 
static const size_t MAX_COMMAND_LENGTH = 512; 
static const size_t MAX_PATH_LENGTH = 256;
static const size_t MAX_REASON_LENGTH = 128; 
static const size_t MAX_IP_LENGTH = 46; 

struct nlattr {
    uint16 nla_len;
    uint16 nla_type;
};

static int is_file_header_valid(const cam_file_header_t* header) {
    if (header == NULL) {
        return 0;
    }
    
    if (header->magic != CAM_MAGIC_NUMBER) {
        fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Неверное магическое число: 0x%08X\n", 
                header->magic);
        return 0;
    }
    
    if (header->version != CAM_VERSION_NUMBER) {
        fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Неподдерживаемая версия: 0x%04X\n", 
                header->version);
        return 0;
    }
    
    if (header->entry_size != sizeof(cam_file_entry_t)) {
        fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Неверный размер записи: %u (ожидалось %zu)\n",
                header->entry_size, sizeof(cam_file_entry_t));
        return 0;
    }
    
    if (header->total_entries == 0 || header->total_entries > 1000000) {
        fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Недопустимое количество записей: %u\n",
                header->total_entries);
        return 0;
    }
    
    uint32_t calculated_total = header->trusted_count + header->pending_count + 
                               header->blocked_count + header->free_count;
    
    if (calculated_total != header->total_entries) {
        fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Несогласованные счетчики записей\n");
        fprintf(stderr, " trusted=%u + pending=%u + blocked=%u + free=%u = %u, total=%u\n",
                header->trusted_count, header->pending_count,
                header->blocked_count, header->free_count,
                calculated_total, header->total_entries);
        return 0;
    }
    
    time_t current_time = time(NULL);
    
    if (header->created_time > current_time + 3600) { 
        fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Время создания в будущем: %ld\n",
                header->created_time);
        return 0;
    }
    
    if (header->last_updated > current_time + 3600) {
        fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Время обновления в будущем: %ld\n",
                header->last_updated);
        return 0;
    }
    
    if (header->last_updated < header->created_time) {
        fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: last_updated < created_time\n");
        return 0;
    }
    
    return 1;
}

static int is_file_entry_valid(const cam_file_entry_t* entry, uint32_t index) {
    if (entry == NULL) {
        return 0;
    }
    
    if (entry->status > ENTRY_STATUS_TRUSTED) {
        fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Неверный статус записи %u: %d\n",
                index, entry->status);
        return 0;
    }
    
    time_t current_time = time(NULL);
    
    if (entry->status != ENTRY_STATUS_FREE) {
        if (entry->last_seen > current_time + 3600) {
            fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Запись %u: last_seen в будущем\n", index);
            return 0;
        }
        
        if (entry->block_time > current_time + 3600) {
            fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Запись %u: block_time в будущем\n", index);
            return 0;
        }
        
        if (entry->status == ENTRY_STATUS_BLOCKED && entry->block_duration < 0) {
            fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Запись %u: отрицательная длительность блокировки\n",
                    index);
            return 0;
        }
        
        if (!is_mac_address_valid(entry->mac)) {
            fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Запись %u: невалидный MAC адрес\n", index);
            return 0;
        }
        
        if (entry->vlan_id > 4095) {
            fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Запись %u: неверный VLAN ID: %u\n",
                    index, entry->vlan_id);
            return 0;
        }
        
        if (entry->status == ENTRY_STATUS_BLOCKED && 
            strlen(entry->ip_address) > 0) {
            if (!is_ip_address_valid(entry->ip_address)) {
                fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Запись %u: невалидный IP адрес: %s\n",
                        index, entry->ip_address);
                return 0;
            }
        }
        
        if (entry->status == ENTRY_STATUS_BLOCKED &&
            strlen(entry->reason) > MAX_REASON_LENGTH) {
            fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Запись %u: слишком длинная причина\n", index);
            return 0;
        }
    } else {
        for (int i = 0; i < 6; i++) {
            if (entry->mac[i] != 0x00) {
                fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Запись %u: MAC не нулевой в свободной записи\n",
                        index);
                return 0;
            }
        }
        
        if (entry->vlan_id != 0) {
            fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Запись %u: VLAN не нулевой в свободной записи\n",
                    index);
            return 0;
        }
    }
    
    return 1;
}

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
    struct ctl_info ctl = {0};
    smemset(&ctl, 0, sizeof(ctl));
    
    /*
    strlcpy(char *dst, const char *src, size_t size);
    */
    strlcpy(ctl.ctl_name, control_name, sizeof(ctl.ctl_name));

    // SOCK_DGRAM IS DEPRECATED (UDP WARNING)
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
    struct sockaddr_ctl sock_ctl = {0};
    smemset(&sock_ctl, 0, sizeof(sock_ctl));

    // warning
    int ctl_id = -1;
    ctl_id = get_kernel_control_id(control_name);
    if (ctl_id < 0) {
        ctl_id = get_kernel_control_id("com.apple.network.statistics");
    }
    if (ctl_id < 0) {
        ctl_id = get_kernel_control_id("com.apple.network.advisory");
    }
    if (ctl_id < 0) return -1;

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
    smemset(&ifhdr, 0, sizeof(ifhdr));

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
    smemset(&ifr, 0, sizeof(ifr));
    /*
    stat, fstat, lstat, fstatat - get file status
    */
    struct stat st = {0};
    smemset(&st, 0, sizeof(st));

    // Open the next available BPF device
    for (int i = 0; i < 128; i++) {
        char bpf_dev[32] = {0};
        smemset(&bpf_dev, 0, sizeof(bpf_dev));
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

    // sock_dgram is deprecated | warning
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
    smemset(&cmd, 0, sizeof(cmd));
}

static const char* get_cam_table_path_safe(void) {
    static char path_buffer[MAX_PATH_LENGTH];
    smemset(&path_buffer, 0, sizeof(path_buffer));

    const char *name = getenv("HOME");
    
    // warning
    /*
    The snprintf() function in the C and C++ programming languages is used to format and store data into a character buffer while providing protection against buffer overflows. 
    It is considered a safer alternative to the older sprintf() function because it limits the number of characters written. 
    */
    snprintf(path_buffer, sizeof(path_buffer) - 1, 
             "%s/.cam_table.dat", getenv("HOME") ? getenv("HOME") : "/tmp");
        
    return path_buffer;
}

static const char *get_cam_log_path_safe(void) {
    static char log_path_buffer[MAX_PATH_LENGTH];
    smemset(&log_path_buffer, 0, sizeof(log_path_buffer));

    /*
    The getenv() function obtains the  current  value  of  the  environment
       variable	 designated  by	 name.	 The application should	not modify the
       string pointed to by the	getenv() function.
    */
    const char *name = getenv("HOME");
    
    // warning
    /*
    The snprintf() function in the C and C++ programming languages is used to format and store data into a character buffer while providing protection against buffer overflows. 
    It is considered a safer alternative to the older sprintf() function because it limits the number of characters written. 

    sprintf(), snprintf(), vsprintf(),
       and vsnprintf() write to	the character string str;

    The  snprintf()	and vsnprintf()	functions will write at	most size-1 of
       the characters printed into the output string  (the  size'th  character
       then gets the terminating `\0');	if the return value is greater than or
       equal  to  the  size argument, the string was too short and some	of the
       printed characters were discarded.  The output  is  always  null-termi-
       nated, unless size is 0.
    */
    // snprintf(log_path_buffer, sizeof(log_path_buffer) - 1, <- buffer overflow, because buffer == N and here N-1 but down exist already -1 for \0, and it turns out that it will be N-2
    //         "%s/.cam_block.log", getenv("HOME") ? getenv("HOME") : "/tmp");
    
    // log_path_buffer[sizeof(log_path_buffer) - 1] = '\0'; <- redundant, and might be unsecure if alreasy exist snprintf

    snprintf(log_path_buffer, sizeof(log_path_buffer),
         "%s/.cam_block.log", 
         getenv("HOME") && *getenv("HOME") ? getenv("HOME") : "/tmp");
    
    return log_path_buffer;
}

/*
checks:
1. NULL
2. size
3. ipv6?
*/
static bool is_ip_address_valid(const char *ip_address) {
    // check on NULL and check is the string empty 
    if (ip_address == NULL || ip_address[0] == '\0') {
        return false;
    }

    /*
    The strlen() function calculates the length of the string pointed
       to by s, (!) excluding the terminating null byte ('\0') (!)

    The  strlen()  function	computes  the  length  of  the	string s.  The
       strnlen() function attempts to compute the length of s, but never scans
       beyond the first	maxlen bytes of	s.
    
    Problem: If the string does not end with '\0', the function will read the memory until it finds a random zero byte (or a segfault occurs).
    */
    size_t len = strlen(ip_address);
    /*
    Its value is 46, which represents the maximum number of characters required to store an IPv6 address in its standard presentation (string) format, including the null terminator character. 
    */
    // check null and overflow
    if (len == 0 || len > INET6_ADDRSTRLEN - 1) {
        return false;
    }

    /* >>> check colons don't need, i only have ipv6 <<< */

    // warning
    struct in6_addr addr6 = {0};
    smemset(&addr6, 0, sizeof(addr6)); // init safe

    /*
    int inet_pton(int af, const char *restrict src, void *restrict dst);
    */
    if (inet_pton(AF_INET6, ip_address, &addr6) == 1) {
        return true;
    }
    
    return false;
}

static bool is_mac_address_valid(const uint8_t *mac_address) {
    if (mac_address == NULL) return false;
    
    bool is_all_zero = true, is_all_one = true;
    
    for (int i = 0; i < 6; i++) {
        if (mac_address[i] != 0x00) {
            is_all_zero = false;
        }

        // check that not broadcast
        if (mac_address[i] != 0xFF) {
            is_all_one = false;
        }
    }
    
    return !is_all_zero && !is_all_one;
}

static bool create_dir_safe(const char *dir_path) {
    if (dir_path == NULL) return false;

    char copy_dir_path[dir_path];
    smemset(&copy_dir_path, 0, sizeof(copy_dir_path));
    /*
    char *
    strncpy(char *restrict dst, const char *restrict src, size_t len);
    */
    strncpy(copy_dir_path, dir_path, sizeof(dir_path) - 1);
    // warning 
    copy_dir_path[sizeof(copy_dir_path) - 1] = '\0';

    // create components
    const char *dir_components_copy = dir_path;
    char slash_pointer = NULL;

    /*
    char *
       strchr(const char *s, int c);
    */
    while ((slash_pointer = strchr(dir_components_copy, '/')) != NULL) {
        if (slash_pointer != dir_components_copy) {
            char original_pointer = *(slash_pointer);
            *(slash_pointer) = '\0';   

            // only me
            // warning
            mkdir(copy_dir_path, 0700);

            *(slash_pointer) = original_pointer;
        }
        dir_components_copy += 1;
    }

    // warning
    if (strlen(copy_dir_path) > 0) {
        mkdir(copy_dir_path, 0700);
    }

    return false;
}

static bool block_ip_secure(
    const char *ip_address,
    const uint8_t *mac_address,
    const char *block_reason,
    int duration_time
) {
    char system_command[MAX_COMMAND_LENGTH] = {0};
    cam_file_header_t file_header = {0};
    cam_file_entry_t file_entry = {0};
    FILE* cam_file_handle = NULL;
    FILE* log_file_handle = NULL;
    time_t current_time_value = 0;
    int operation_result = 0;
    uint32_t entry_index = 0;
    int entry_found_flag = 0;
    size_t bytes_read = 0;
    size_t bytes_written = 0;

    if (ip_address == NULL || mac_address == NULL) {
        fprintf(stderr, "ОШИБКА: IP адрес не может быть NULL\n");
        return;
    }
    
    if (block_reason == NULL) {
        fprintf(stderr, "ОШИБКА: Причина блокировки не может быть NULL\n");
        return;
    }
    
    if (!is_ip_address_valid(ip_address) || !is_mac_address_valid(mac_address)) {
        fprintf(stderr, "ОШИБКА: Неверный формат IP адреса: %s\n", ip_address);
        return;
    }
    
    if (contains_dangerous_characters(block_reason)) {
        fprintf(stderr, "ОШИБКА: Причина блокировки содержит опасные символы\n");
        return;
    }
    
    if (strlen(block_reason) >= MAX_REASON_LENGTH() || duration_seconds < 0) {
        fprintf(stderr, "ОШИБКА: Причина блокировки слишком длинная\n");
        return;
    }

    // printf("→ Начало блокировки L2/L3:\n");
    // printf(" MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
    //        mac_address[0], mac_address[1], mac_address[2],
    //        mac_address[3], mac_address[4], mac_address[5]);
    // printf(" IP: %s\n", ip_address);
    // printf(" Причина: %s\n", block_reason);
    // printf(" Длительность: %d секунд\n", duration_seconds);
    
    if (is_mac_address_blocked_safe(mac_address)) {
        printf("→ MAC адрес уже заблокирован в CAM таблице, пропускаем запись\n");
    } else {
        printf("→ MAC адрес не найден в блокировках, продолжаем...\n");
    }
    
    const char *cam_file_path = get_cam_table_path_safe();
    printf("→ Работа с CAM файлом: %s\n", cam_file_path);
    
    cam_file_handle = fopen(cam_file_path, "r+b");
    
    if (cam_file_handle == NULL) {
        printf("→ CAM файл не найден, создаем новый...\n");
        
        char directory_path_copy[MAX_PATH_LENGTH] = {0};
        smemset(&directory_path_copy, 0, sizeof(directory_path_copy));
        strncpy(directory_path_copy, cam_file_path, sizeof(directory_path_copy) - 1);
        // warning
        directory_path_copy[sizeof(directory_path_copy) - 1] = '\0';
        
        /*
        The strchr() function locates the first occurrence of c (converted to a
        char) in	the string pointed to by s.  The terminating null character is
        considered  part	 of  the string; therefore if c	is `\0', the functions
        locate the terminating `\0'.

        The strrchr() function is identical to strchr() except it  locates  the
        last occurrence of c
        */
        char *last_slash_position = strrchr(directory_path_copy, '/');
        if (last_slash_position != NULL) {
            *last_slash_position = '\0';
            
            if (create_directory_safely(directory_path_copy) != 0) {
                fprintf(stderr, "ОШИБКА: Не удалось создать директорию\n");
                return;
            }
        }
        
        int file_descriptor = open(cam_file_path, O_RDWR | O_CREAT | O_EXCL, 0600);
        
        if (file_descriptor < 0) {
            if (errno == EEXIST) {
                cam_file_handle = fopen(cam_file_path, "r+b");
            } else {
                fprintf(stderr, "ОШИБКА: Не удалось создать CAM файл: %s\n", strerror(errno));
                return;
            }
        } else {
            cam_file_handle = fdopen(file_descriptor, "w+b");
            
            if (cam_file_handle == NULL) {
                close(file_descriptor);
                fprintf(stderr, "ОШИБКА: Не удалось открыть созданный файл\n");
                return;
            }
            
            file_header.magic = CAM_MAGIC_NUMBER;
            file_header.version = CAM_VERSION_NUMBER;
            file_header.entry_size = sizeof(cam_file_entry_t);
            file_header.total_entries = 1000; 
            file_header.trusted_count = 0;
            file_header.pending_count = 0;
            file_header.blocked_count = 0;
            file_header.free_count = 1000;
            file_header.created_time = time(NULL);
            file_header.last_updated = time(NULL);
            
            bytes_written = fwrite(&file_header, sizeof(file_header), 1, cam_file_handle);
            if (bytes_written != 1) {
                fprintf(stderr, "ОШИБКА: Не удалось записать заголовок файла\n");
                fclose(cam_file_handle);
                return;
            }
            
            cam_file_entry_t empty_entry = {0};
            smemset(&empty_entry, 0, empty_entry);
            
            for (uint32_t fill_index = 0; fill_index < file_header.total_entries; fill_index++) {
                bytes_written = fwrite(&empty_entry, sizeof(empty_entry), 1, cam_file_handle);
                if (bytes_written != 1) {
                    fprintf(stderr, "ОШИБКА: Не удалось инициализировать запись %u\n", fill_index);
                    fclose(cam_file_handle);
                    return;
                }
            }
            
            fseek(cam_file_handle, 0, SEEK_SET);
        }

        /*
        BLOCK FILE FOR
        
        #define	 LOCK_SH	0x01	  /* shared file lock  
        #define	 LOCK_EX	0x02	  /* exclusive file lock  
        #define	 LOCK_NB	0x04	  /* do	not block when locking  
        #define	 LOCK_UN	0x08	  /* unlock file  

        int
        flock(int fd, int operation);
        */
        if (cam_file_handle != NULL) {
            int lock_file = flock(fileno(cam_file_handle), LOCK_EX); // exclusive file lock 
            if (lock_file < 0) {
                fprintf("lock_file");
                fclose(lock_file);
                return;
            }

            /*
            int
            fseek(FILE *stream, long	offset,	int whence);
            */
            fseek(cam_file_handle, 0, SEEK_SET);
            /*
            size_t
            fread(void   *	restrict   ptr,	   size_t    size,    size_t	nmemb,
	        FILE	* restrict stream);
            */
            bytes_read = fread(&cam_file_handle, sizeof(cam_file_handle), 1, cam_file_handle);
            if (bytes_read != 1) {
                fprintf("not bytes_read");
                flock(fileno(cam_file_handle), LOCK_UN);
                fclose(cam_file_handle);
                return;
            }

            if (!is_file_header_valid(&file_header)) {
                fprintf(stderr, "ОШИБКА: Заголовок CAM файла поврежден\n");

                /*
                int
                fseek(FILE *stream, long	offset,	int whence);

                The fseek() function sets the file position indicator  for  the	stream
       pointed to by stream.  The new position,	measured in bytes, is obtained
       by  adding offset bytes to the position specified by whence.  If	whence
       is set to SEEK_SET, SEEK_CUR, or	SEEK_END, the offset  is  relative  to
       the  start of the file, the current position indicator, or end-of-file,
       respectively.  A	successful call	to the	fseek()	 function  clears  the
       end-of-file  indicator  for  the	 stream	 and undoes any	effects	of the
       ungetc(3) and ungetwc(3)	functions on the same stream.

       The ftell() function obtains the	current	value of the file position in-
       dicator for the stream pointed to by stream.

                "int fileno(FILE *stream);"
                FILE (highlevel thread) -> fd (int)
                (!) Converts FILE* (high-level stream) to a file descriptor (low-level int) 
                It is needed for flock() and ftruncate(), which work with descriptors (!)

                stream - file stream
                offset - offset in bytes
                whence - where to read the offset from:

                SEEK_SET (0) - from the beginning of the file
                SEEK_CUR (1) - from the current position
                SEEK_END (2) - from the end of the file

                briefly: we find out the file size, then we return to read the data.
                */
                fseek(cam_file_handle, 0, SEEK_END);
                long file_size = ftell(cam_file_handle); 
                fseek(cam_file_handle, sizeof(file_header), SEEK_SET);

                if (file_size < (long)sizeof(file_header)) {
                    fprintf(stderr, "Файл слишком маленький (%ld байт), возможно поврежден\n", file_size);
                } else if (file_header.total_entries == 0) {
                    fprintf(stderr, "Нулевое количество записей в заголовке\n");
                }
            
                flock(fileno(cam_file_handle), LOCK_UN);
                fclose(cam_file_handle);
                return;
            }

            // warning
            if (file_header.magic != CAM_MAGIC_NUMBER()) {
                printf("not magic");
                flock(fileno(cam_file_handle), LOCK_UN);
                fclose(cam_file_handle);
                return;
            }

            if (file_header.version != CAM_VERSION_NUMBER()) {
                printf("not version");
                flock(fileno(cam_file_handle), LOCK_UN);
                fclose(cam_file_handle);
                return;
            }

            /*
            We are looking for a free record or a record with the same MAC 
            */
            entry_found_flag = 0;
            for (int i = 0; i < file_header.entry_size; i++) {
                bytes_read = fread(&file_entry, sizeof(file_entry), 1, cam_file_handle);
                if (bytes_read != 1) {
                    fprintf(stderr, "ОШИБКА: Не удалось прочитать запись %u\n", entry_index);
                    break;
                }

                if (file_entry.status == ENTRY_STATUS_FREE) {
                    entry_found_flag = 1;
                    printf("✓ Найдена свободная запись (индекс %u)\n", entry_index);
                    break;
                /*
                The same MAC address can exist on different VLANs.
                */
                } else if (memcmp(file_entry.mac, mac_address, 6) == 0 && file_entry.vlan_id == 1) {
                    entry_found_flag = 1;
                    printf("✓ Найдена существующая запись (индекс %u)\n", entry_index);
                    break;
                }
            }

            if (entry_found_flag) {
                memcpy(file_entry.mac, mac_address, 6);
                file_entry.vlan_id = 1;
                file_entry.status = ENTRY_STATUS_BLOCKED;
                file_entry.last_seen = time(NULL);
                file_entry.block_time = time(NULL);
                file_entry.block_duration = duration_seconds;

                // warning
                strncpy(file_entry.ip_address, ip_address, sizeof(file_entry.ip_address) - 1);
                file_entry.ip_address[sizeof(file_entry.ip_address) - 1] = '\0';

                // warning
                strncpy(file_entry.reason, block_reason, sizeof(file_entry.reason) - 1);
                file_entry.reason[sizeof(file_entry.reason) - 1] = '\0';

                /*
                This is a calculation of the position of a specific record in a file. (!) from the beginning of the file

                change file_entry (!)

                int
                fseek(FILE *stream, long	offset,	int whence);
                */
                fseek(cam_file_handle, sizeof(file_header) + entry_index * sizeof(file_entry), SEEK_SET);

                /*
                size_t
                fwrite(const  void  *  restrict	ptr,  size_t   size,   size_t	nmemb,
	            FILE	* restrict stream);

                fwrite(&file_entry, sizeof(file_entry), ...) will record exactly the changes that I made to the file_entry structure in memory, 
                at the address in the file where the current position (fseek) points 

                nmemb - count of elements for write\read
                */
                bytes_written = fwrite(&file_entry, sizeof(file_entry), 1, cam_file_handle);
                if (bytes_written != 1) {
                    // need stats
                    fprintf(stderr, "ОШИБКА: Не удалось записать обновленную запись\n");
                } else {
                    file_header.blocked_count++;
                    if (file_entry.status == ENTRY_STATUS_FREE) {
                        file_header.free_count--;
                    }
                    file_header.last_updated = time(NULL);
                
                    fseek(cam_file_handle, 0, SEEK_SET);
                    fwrite(&file_header, sizeof(file_header), 1, cam_file_handle);
                
                    printf("✓ Запись успешно сохранена в CAM таблице\n");
                    printf(" Статистика: заблокировано %u MAC, свободно %u записей\n",
                       file_header.blocked_count, file_header.free_count);
                }
            } else {
                fprintf(stderr, "ОШИБКА: Не найдено свободного места в CAM таблице\n");
            }

            flock(fileno(cam_file_handle), LOCK_UN);
            fclose(cam_file_handle);
            cam_file_handle = NULL;
        }

        // block (ebtables, iptables)
        // warning
        int bytes_formatted = snprintf(system_command, sizeof(system_command) - 1,
        "echo 'block drop from any to any MAC %02X:%02X:%02X:%02X:%02X:%02X' | "
        "sudo pfctl -a cam_blocker -f - 2>&1",
        mac_address[0], mac_address[1], mac_address[2],
        mac_address[3], mac_address[4], mac_address[5]);

        if (bytes_formatted < 0 || bytes_formatted >= (int)sizeof(system_command)) {
            fprintf(stderr, "ОШИБКА: Переполнение буфера команды IP блокировки\n");
            return false;
        } else {
            if (contains_dangerous_characters(system_command)) {
                fprintf(stderr, "ОШИБКА: Команда содержит опасные символы\n");
            } else {
                printf("→ Выполнение: %s\n", system_command);
                operation_result = system(system_command);
                if (operation_result != 0) {
                    fprintf(stderr, "ОШИБКА: Команда IP блокировки завершилась с кодом %d\n", 
                        WEXITSTATUS(operation_result));
                }
            }
        }

        const char *log_file_path = get_cam_log_path_safe();
        log_file_path = fopen(log_file_path, "a");

        // warning
        if (log_file_path == NULL) {
            return false;
        }

        if (log_file_path != NULL) {
            current_time_value = time(NULL);

            char time_buf[32] = {0};
            smemset(&time_buf, 0, sizeof(time_buf));
            /*  
struct tm {
    int tm_sec;   /* seconds [0, 61]  
    int tm_min;   /* minutes [0, 59]  
    int tm_hour;  /* hour [0, 23]  
    int tm_mday;  /* day of the month [1, 31]  
    int tm_mon;   /* month of the year [0, 11]  
    int tm_year;  /* years since 1900  
    int tm_wday;  /* day of the week [0, 6] (Sunday = 0)  
    int tm_yday;  /* day of the year [0, 365]  
    int tm_isdst; /* daylight savings time flag 
};

            */
            struct tm *time_info = localtime(&current_time_value);
            /*
            size_t
            strftime(char * restrict	buf,			       size_t maxsize,
	        const char *	restrict format, const struct tm * restrict timeptr);
            */
            strftime(time_buf, sizeof(time_buf) - 1, "%Y-%m-%d %H:%M:%S", time_info);
            // warning
            time_buf[sizeof(time_buf) - 1] = "\0";

            fprintf(log_file_handle, "%s | BLOCK | MAC:%02X:%02X:%02X:%02X:%02X:%02X | "
                "IP:%s | Reason:%s | Duration:%d\n",
                time_buffer,
                mac_address[0], mac_address[1], mac_address[2],
                mac_address[3], mac_address[4], mac_address[5],
                ip_address, block_reason, duration_seconds);
            
            fclose(log_file_handle);
            log_file_handle = NULL;
        } else {
            fprintf(stderr, "ОШИБКА: Не удалось открыть лог-файл для записи\n");
        }
    }

    smemset(system_command, 0, sizeof(system_command));
    smemset(&file_header, 0, sizeof(file_header));
    smemset(&file_entry, 0, sizeof(file_entry));
    
    printf("✓ Блокировка L2/L3 успешно применена\n");
    printf(" MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           mac_address[0], mac_address[1], mac_address[2],
           mac_address[3], mac_address[4], mac_address[5]);
    printf(" IP: %s\n", ip_address);
    printf(" Время: %ld\n", time(NULL));
    
    return;
}

static void process_packet(int sock_fd, const char *buf, size_t buf_size) {
    struct sockaddr_in addr = {0};
    smemset(&addr, 0, sizeof(addr));
    socklen_t addr_len = sizeof(addr);

    /*
    recvfrom(int s, void  *buf, size_t len,	int	flags,
	   struct sockaddr *restrict from, socklen_t *restrict from_len);

    The  recvfrom(), recvmsg(), and recvmmsg() system calls are used to receive messages from a socket, 
    and may be used to receive data on a socket whether or not it is connection-oriented.
    */
    ssize_t packet_len = recvfrom(sock_fd, buf, buf_size, 0, (struct sockaddr_in *)&addr, &addr_len); 

    if (packet_len > 0) {
        struct ether_header *eth = (*eth)buf;
        /*
        htonl,  htons,  ntohl, ntohs -- convert values between host and network
        byte order
        */
        if (ntohs(eth->ether_type == ETHERNET_IP)) {
            
        } 
    }
}

// ===== CAM TABLE UTILITIES =====

/**
 * create_cam_directory - Create directory structure for CAM table storage
 *
 * Attempts to create primary directory path, falls back to temporary directory
 * if primary location is not accessible. Ensures CAM table persistence.
 *
 * Return: 0 on success, -1 on failure
 */
static int create_cam_directory()
{
    struct stat st = {0};
    const char *primary_path = get_cam_table_primary_path();
    const char *fallback_path = get_cam_table_fallback_path();

    // Extract directory from full path
    char primary_dir[256];
    smemset(&primary_dir, 0, sizeof(primary_dir));
    char fallback_dir[256];
    smemset(&fallback_dir, 0, sizeof(fallback_dir));

    // warning
    primary_dir = [sizeof(primary_dir) - 1] = '\0';
    fallback_dir = [sizeof(fallback_dir) - 1] = '\0';

    strncpy(primary_dir, primary_path, sizeof(primary_dir) - 1);
    strncpy(fallback_dir, fallback_path, sizeof(fallback_dir) - 1);

    /*
       strrchr — string scanning operation

       char *strrchr(const char *s, int c);
    */
    char *primary_slash = strrchr(primary_dir, '/');
    char *fallback_slash = strrchr(fallback_dir, '/');

    // warning
    if (primary_slash)
        *primary_slash = '\0';
    if (fallback_slash)
        *fallback_slash = '\0';

    if (stat(primary_dir, &st) == 0)
    {
        if (S_ISDIR(st.st_mode))
            return 0;
        else
        {
            fprintf(stderr, "Error: %s exists but is not a directory\n", primary_dir);
            return -1;
        }
    }

    if (mkdir(primary_dir, 0700) == 0)
        return 0;

    if (errno != EACCES)
        fprintf(stderr, "mkdir(%s) failed: %s\n", primary_dir, strerror(errno));

    if (stat(fallback_dir, &st) == 0)
    {
        if (S_ISDIR(st.st_mode))
        {
            printf("Using existing fallback: %s\n", fallback_dir);
            return 0;
        }
        else
        {
            fprintf(stderr, "Error: %s exists but is not a directory\n", fallback_dir);
            return -1;
        }
    }

    if (mkdir(fallback_dir, 0700) == 0)
    {
        printf("Created fallback directory: %s\n", fallback_dir);
        return 0;
    }

    fprintf(stderr, "Failed to create both directories\n");
    return -1;
}

static int create_osx_socket_data(int type, const char *data, size_t len) {
    static int osx_sock = -1; // initial value

    if (osx_sock < 0) {
        if (type == 0) {
            osx_sock = create_osx_route_socket();

            get_interface_info_osx();
        } else if (type == 1) {
            osx_sock = create_osx_route_socket();

            if (connect_to_kernel_control(osx_sock, "com.apple.network.statistics") < 0) {
                close(osx_sock);
                // warning
                osx_sock = -1; // might be replaced until this, and we implicity replace this on -1
                return -1;
            }
        } else if (type == 2) {
            osx_sock = create_bpf_socket();

            if (setup_)
        }
    }

    if (osx_sock < 0) {
        return -1;
    }
}

/**
 * init_cam_file - Initialize CAM table file with header and empty entries
 * @filename: Path to CAM table file
 * @capacity: Maximum number of entries in the table
 *
 * Creates and initializes a new CAM table file with proper header structure
 * and pre-allocated empty entries for future use.
 *
 * Return: 0 on success, -1 on file creation failure
 */
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

// ===== CAM TABLE READER =====

/**
 * print_cam_table - Display contents of CAM table file
 *
 * Reads and prints the entire CAM table structure including header information
 * and all blocked MAC entries. Used for debugging and monitoring purposes.
 */
void print_cam_table()
{
    const char *filename = get_cam_table_primary_path();

    printf("\n→ READING CAM TABLE: %s\n", filename);

    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        printf("✗ Failed to open CAM file for reading\n");
        return;
    }

    cam_file_header_t header;
    if (fread(&header, sizeof(header), 1, file) != 1)
    {
        printf("✗ Error reading header\n");
        fclose(file);
        return;
    }

    printf("=== CAM TABLE HEADER ===\n");
    printf("Magic number: 0x%X\n", header.magic);
    printf("Version: %d\n", header.version);
    printf("Total entries: %d\n", header.total_entries);
    printf("Blocked: %d\n", header.blocked_count);
    printf("Pending: %d\n", header.pending_count);
    printf("Trusted: %d\n", header.trusted_count);
    printf("Free: %d\n", header.free_count);
    printf("Created: %s", ctime(&header.created_time));
    printf("Updated: %s", ctime(&header.last_updated));

    printf("\n=== BLOCKED MAC ADDRESSES ===\n");

    cam_file_entry_t entry;
    int blocked_found = 0;

    for (uint32_t i = 0; i < header.total_entries; i++)
    {
        if (fread(&entry, sizeof(entry), 1, file) != 1)
        {
            printf("✗ Error reading entry %d\n", i);
            break;
        }

        if (entry.status == ENTRY_BLOCKED)
        {
            blocked_found++;
            printf("\n→ Entry #%d:\n", i);
            printf("   MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   entry.mac[0], entry.mac[1], entry.mac[2],
                   entry.mac[3], entry.mac[4], entry.mac[5]);
            printf("   IP: %s\n", entry.ip_address);
            printf("   VLAN: %d\n", entry.vlan_id);
            printf("   Reason: %s\n", entry.reason);
            printf("   Block time: %s", ctime(&entry.block_time));
            printf("   Duration: %d sec\n", entry.block_duration);
            printf("   Last seen: %s", ctime(&entry.last_seen));
        }
    }

    if (!blocked_found)
    {
        printf("✗ No blocked entries found\n");
    }
    else
    {
        printf("\n✓ Found blocked entries: %d\n", blocked_found);
    }

    fclose(file);
}

// ===== CAM TABLE INIT & CLEANUP =====

/**
 * cam_table_init - Initialize CAM table manager and storage
 * @manager: CAM table manager instance to initialize
 * @default_mode: Default forwarding mode for the table
 *
 * Sets up CAM table infrastructure including directory creation, file
 * initialization, and manager state configuration.
 *
 * Return: 0 on success, -1 on initialization failure
 */
int cam_table_init(cam_table_manager_t *manager, uft_mode_t default_mode)
{
    if (!manager)
        return -1;

    if (create_cam_directory() != 0)
    {
        printf("✗ Failed to create CAM table directory\n");
        return -1;
    }

    const char *filename = get_cam_table_primary_path();
    FILE *test_file = fopen(filename, "rb");
    if (!test_file)
    {
        printf("→ Creating new CAM table: %s\n", filename);
        if (init_cam_file(filename, get_default_cam_capacity()) != 0)
        {
            printf("✗ Error creating CAM file\n");
            return -1;
        }
    }
    else
    {
        fclose(test_file);
        printf("→ Loading existing CAM table\n");

        // Display existing table contents
        print_cam_table();
    }

    // Initialize manager
    manager->current_mode = default_mode;
    manager->initialized = true;

    printf("✓ CAM table initialized: %s\n", filename);
    printf("   Mode: %d, Capacity: %d entries\n", default_mode, get_default_cam_capacity());
    return 0;
}

/**
 * cam_table_cleanup - Clean up CAM table manager resources
 * @manager: CAM table manager instance to clean up
 *
 * Performs graceful shutdown of CAM table manager while preserving
 * data persistence in the file system.
 *
 * Return: 0 on success, -1 on invalid manager
 */
int cam_table_cleanup(cam_table_manager_t *manager)
{
    if (!manager)
        return -1;

    // Do not clear file, only reset flag
    manager->initialized = false;
    printf("✓ CAM manager stopped (data saved in file)\n");
    return 0;
}

// ===== CHECK IF MAC IS BLOCKED =====

/**
 * is_mac_blocked - Check if MAC address is blocked in CAM table
 * @mac_bytes: MAC address to check (6-byte array)
 *
 * Searches through CAM table file to determine if specified MAC address
 * has been previously blocked.
 *
 * Return: 1 if MAC is blocked, 0 if not found or error
 */
int is_mac_blocked(const uint8_t *mac_bytes)
{
    const char *filename = get_cam_table_primary_path();
    FILE *file = fopen(filename, "rb");
    if (!file)
        return 0; // If file doesn't exist, MAC is not blocked

    cam_file_header_t header;
    if (fread(&header, sizeof(header), 1, file) != 1)
    {
        fclose(file);
        return 0;
    }

    cam_file_entry_t entry;
    for (uint32_t i = 0; i < header.total_entries; i++)
    {
        if (fread(&entry, sizeof(entry), 1, file) != 1)
            break;

        if (entry.status == ENTRY_BLOCKED &&
            memcmp(entry.mac, mac_bytes, 6) == 0)
        {
            fclose(file);
            return 1; // MAC is blocked
        }
    }

    fclose(file);
    return 0; // MAC is not blocked
}

// ===== CAM TABLE FUNCTIONS =====

/**
 * block_mac_in_file - Internal function to block MAC in file (delegated)
 * @mac_bytes: MAC address to block (6-byte array)
 * @vlan_id: VLAN identifier for the MAC entry
 * @reason: Description of why MAC is being blocked
 *
 * Internal function that handles file operations for blocking MAC
 *
 * Return: 0 on success, -1 on error
 */
static int block_mac_in_file(const uint8_t *mac_bytes, uint16_t vlan_id, const char *reason)
{
    const char *filename = get_cam_table_primary_path();
    int fd = -1;
    FILE *file = NULL;
    int result = -1;

    fd = open(filename, O_RDWR | O_CREAT, 0700);
    if (fd == -1)
    {
        printf("✗ Failed to open CAM file for blocking: %s\n", strerror(errno));
        return -1;
    }

    if (flock(fd, LOCK_EX) == -1)
    {
        printf("✗ Failed to lock CAM file: %s\n", strerror(errno));
        goto cleanup;
    }

    file = fdopen(fd, "r+b");
    if (!file)
    {
        printf("✗ Failed to convert file descriptor: %s\n", strerror(errno));
        goto cleanup;
    }

    cam_file_header_t header;
    if (fread(&header, sizeof(header), 1, file) != 1)
    {
        printf("✗ Failed to read CAM header\n");
        goto cleanup;
    }

    cam_file_entry_t entry;
    int found = 0;

    for (uint32_t i = 0; i < header.total_entries; i++)
    {
        if (fread(&entry, sizeof(entry), 1, file) != 1)
        {
            break;
        }

        if (entry.status == ENTRY_FREE ||
            (memcmp(entry.mac, mac_bytes, 6) == 0 && entry.vlan_id == vlan_id))
        {
            found = 1;

            memcpy(entry.mac, mac_bytes, 6);
            entry.vlan_id = vlan_id;
            entry.status = ENTRY_BLOCKED;
            entry.last_seen = time(NULL);
            strncpy(entry.reason, reason, sizeof(entry.reason) - 1);
            entry.reason[sizeof(entry.reason) - 1] = '\0';

            if (fseek(file, sizeof(header) + i * sizeof(entry), SEEK_SET) != 0)
            {
                found = 0;
                break;
            }

            if (fwrite(&entry, sizeof(entry), 1, file) != 1)
            {
                found = 0;
                break;
            }

            header.blocked_count++;
            if (entry.status == ENTRY_FREE)
            {
                header.free_count--;
            }

            break;
        }
    }

    if (found)
    {
        header.last_updated = time(NULL);
        if (fseek(file, 0, SEEK_SET) != 0 ||
            fwrite(&header, sizeof(header), 1, file) != 1)
        {
            found = 0;
        }
        else
        {
            result = 0;
            printf("✓ MAC blocked in CAM table: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   mac_bytes[0], mac_bytes[1], mac_bytes[2],
                   mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        }
    }

    if (!found)
    {
        printf("✗ MAC not found or update failed: %02X:%02X:%02X:%02X:%02X:%02X\n",
               mac_bytes[0], mac_bytes[1], mac_bytes[2],
               mac_bytes[3], mac_bytes[4], mac_bytes[5]);
    }

cleanup:
    if (file)
    {
        fclose(file);
    }
    else if (fd != -1)
    {
        flock(fd, LOCK_UN);
        close(fd);
    }

    return result;
}

/**
 * update_memory_cache - Update in-memory cache after file operation
 * @manager: CAM table manager instance
 * @mac_bytes: MAC address that was blocked
 * @vlan_id: VLAN identifier
 * @status: New status for the MAC entry
 */
static void update_memory_cache(cam_table_manager_t *manager, const uint8_t *mac_bytes,
                                uint16_t vlan_id, cam_entry_status_t status)
{
    pthread_rwlock_wrlock(&manager->rwlock);

    // Update your in-memory data structures here
    // For example:
    // - Update hash table
    // - Update blocked MACs list
    // - Update statistics

    pthread_rwlock_unlock(&manager->rwlock);
}

/**
 * is_mac_already_blocked - Check if MAC is already blocked (thread-safe)
 * @manager: CAM table manager instance
 * @mac_bytes: MAC address to check
 * @vlan_id: VLAN identifier
 *
 * Return: 1 if already blocked, 0 otherwise
 */
static int is_mac_already_blocked(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id)
{
    int blocked = 0;

    pthread_rwlock_rdlock(&manager->rwlock);
    // Check your in-memory data structures
    // blocked = check_if_mac_blocked(manager, mac_bytes, vlan_id);
    pthread_rwlock_unlock(&manager->rwlock);

    if (blocked)
    {
        printf("→ MAC already blocked in CAM table: %02X:%02X:%02X:%02X:%02X:%02X\n",
               mac_bytes[0], mac_bytes[1], mac_bytes[2],
               mac_bytes[3], mac_bytes[4], mac_bytes[5]);
    }

    return blocked;
}

/**
 * cam_table_block_mac - Block MAC address in CAM table (delegated version)
 * @manager: CAM table manager instance
 * @mac_bytes: MAC address to block (6-byte array)
 * @vlan_id: VLAN identifier for the MAC entry
 * @reason: Description of why MAC is being blocked
 *
 * Public API function that delegates file operations to internal functions
 *
 * Return: 0 on success, -1 on error
 */
int cam_table_block_mac(cam_table_manager_t *manager, const uint8_t *mac_bytes,
                        uint16_t vlan_id, const char *reason)
{
    if (!manager || !manager->initialized || !mac_bytes || !reason)
    {
        return -1;
    }

    if (is_mac_already_blocked(manager, mac_bytes, vlan_id))
    {
        return 0;
    }

    int result = block_mac_in_file(mac_bytes, vlan_id, reason);

    if (result == 0)
    {
        update_memory_cache(manager, mac_bytes, vlan_id, ENTRY_BLOCKED);
    }

    return result;
}

/**
 * cam_table_unblock_mac - Remove block from MAC address in CAM table
 * @manager: CAM table manager instance
 * @mac_bytes: MAC address to unblock (6-byte array)
 * @vlan_id: VLAN identifier for the MAC entry
 *
 * Removes blocked status from specified MAC address and updates
 * table statistics. Frees the entry for future use.
 *
 * Return: 0 on success, -1 on error or MAC not found
 */
int cam_table_unblock_mac(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id)
{
    if (!manager || !manager->initialized)
        return -1;

    const char *filename = get_cam_table_primary_path();
    FILE *file = fopen(filename, "r+b");
    if (!file)
        return -1;

    cam_file_header_t header;
    fread(&header, sizeof(header), 1, file);

    cam_file_entry_t entry;
    int found = 0;

    for (uint32_t i = 0; i < header.total_entries; i++)
    {
        fread(&entry, sizeof(entry), 1, file);

        if (entry.status == ENTRY_BLOCKED &&
            memcmp(entry.mac, mac_bytes, 6) == 0 &&
            entry.vlan_id == vlan_id)
        {
            found = 1;
            memset(&entry, 0, sizeof(entry));
            entry.status = ENTRY_FREE;

            /*
            int fseek(FILE *stream, long offset, int whence);

            The fseek() function sets the file position indicator for the
       stream pointed to by stream.  The new position, measured in bytes,
       is obtained by adding offset bytes to the position specified by
       whence.  If whence is set to SEEK_SET, SEEK_CUR, or SEEK_END, the
       offset is relative to the start of the file, the current position
       indicator, or end-of-file, respectively.  A successful call to the
       fseek() function clears the end-of-file indicator for the stream
       and undoes any effects of the ungetc(3) function on the same
       stream.
            */
            fseek(file, sizeof(header) + i * sizeof(entry), SEEK_SET);
            fwrite(&entry, sizeof(entry), 1, file);

            header.blocked_count--;
            header.free_count++;

            break;
        }
    }

    if (found)
    {
        header.last_updated = time(NULL);
        fseek(file, 0, SEEK_SET);
        fwrite(&header, sizeof(header), 1, file);
        printf("✓ MAC unblocked in CAM table: %02X:%02X:%02X:%02X:%02X:%02X\n",
               mac_bytes[0], mac_bytes[1], mac_bytes[2],
               mac_bytes[3], mac_bytes[4], mac_bytes[5]);
    }

    fclose(file);
    return found ? 0 : -1;
}

/**
 * cam_table_set_mac_pending - Set MAC address to pending status
 * @manager: CAM table manager instance
 * @mac_bytes: MAC address to set as pending (6-byte array)
 * @vlan_id: VLAN identifier for the MAC entry
 * @reason: Description of why MAC is in pending state
 *
 * Marks MAC address as pending for further analysis or verification.
 * Used for suspicious but not confirmed malicious addresses.
 *
 * Return: 0 on success, -1 on error or manager not initialized
 */
int cam_table_set_mac_pending(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id, const char *reason)
{
    if (!manager || !manager->initialized)
        return -1;

    const char *filename = get_cam_table_primary_path();
    FILE *file = fopen(filename, "r+b");
    if (!file)
        return -1;

    cam_file_header_t header;
    fread(&header, sizeof(header), 1, file);

    // warning
    cam_file_entry_t entry = {0};
    int found = 0;

    for (uint32_t i = 0; i < header.total_entries; i++)
    {
        fread(&entry, sizeof(entry), 1, file);

        if (entry.status == ENTRY_FREE ||
            (memcmp(entry.mac, mac_bytes, 6) == 0 && entry.vlan_id == vlan_id))
        {
            found = 1;

            memcpy(entry.mac, mac_bytes, 6);
            entry.vlan_id = vlan_id;
            entry.status = ENTRY_PENDING;
            entry.last_seen = time(NULL);
            strncpy(entry.reason, reason, sizeof(entry.reason) - 1);

            fseek(file, sizeof(header) + i * sizeof(entry), SEEK_SET);
            fwrite(&entry, sizeof(entry), 1, file);

            header.pending_count++;
            if (entry.status == ENTRY_FREE)
                header.free_count--;

            break;
        }
    }

    if (found)
    {
        header.last_updated = time(NULL);
        fseek(file, 0, SEEK_SET);
        fwrite(&header, sizeof(header), 1, file);
    }

    fclose(file);
    return found ? 0 : -1;
}

// ===== SIGNAL HANDLER =====

/**
 * handle_signal - Signal handler for graceful shutdown
 * @sig: Signal number received
 *
 * Handles termination signals (SIGINT, SIGTERM) to stop monitoring
 * loop gracefully and perform cleanup operations.
 */
void handle_signal(int sig)
{
    stop_monitoring = 1;
    printf("\n→ Stopping monitoring...\n");
}

/**
 * handle_usr1 - Signal handler for CAM table display request
 * @sig: Signal number (SIGUSR1)
 *
 * Handles user-defined signal to display current CAM table contents
 * without interrupting monitoring operations.
 */
void handle_usr1(int sig)
{
    printf("\n→ SHOW CAM TABLE ON REQUEST\n");
    print_cam_table();
}

// ===== DETECTOR FUNCTIONS =====

/**
 * init_detector - Initialize anomaly detector instance
 * @detector: Anomaly detector instance to initialize
 * @cam_manager: CAM table manager for security operations
 *
 * Sets up anomaly detector with zeroed state, initialized mutexes,
 * and associated CAM table manager for coordinated security responses.
 */
void init_detector(anomaly_detector_t *detector, cam_table_manager_t *cam_manager)
{
    memset(detector, 0, sizeof(anomaly_detector_t));
    detector->current.last_calc_time = time(NULL);
    detector->cam_manager = cam_manager;
    pthread_mutex_init(&detector->block_mutex, NULL);
    pthread_mutex_init(&detector->map_mutex, NULL);
}

/**
 * send_ban_to_social_network - Final working version
 */
void send_ban_to_social_network(const char *ip, const uint8_t *mac,
                                const char *reason, int duration,
                                int ban_level)
{
    char command[1024];

    char *device_hash = get_device_hash_secure(ip);
    if (!device_hash)
    {
        printf("→ No device hash found for attacking IP: %s (user not logged in?)\n", ip);
        return;
    }

    const char *level_str = "pending";
    if (ban_level == get_block_level_hard())
        level_str = "hard";
    else if (ban_level == get_block_level_permanent())
        level_str = "permanent";

    printf("→ Sending ban for attacking IP: %s → device: %s → user: [will be blocked]\n", ip, device_hash);

    snprintf(command, sizeof(command),
             "curl -X POST -H \"Content-Type: application/json\" "
             "-d '{\"deviceHash\": \"%s\", \"reason\": \"%s\", "
             "\"duration\": %d, \"level\": \"%s\"}' "
             "%s/lock-user-by-device --max-time %d --silent",
             device_hash, reason, duration, level_str,
             get_social_network_api_url(), get_curl_timeout_sec());

    int result = system(command);
    if (result == 0)
    {
        printf("✓ User successfully banned via device hash\n");
    }
    else
    {
        printf("✗ Failed to send ban (code: %d)\n", result);
    }
}

/*
  unblock device
*/
void unblock_device(const char *ip, const uint8_t *mac,
                    const char *reason, int duration,
                    int ban_level, time_t block_until)
{
    char command[1024];

    char *device_hash = get_device_hash_secure(ip);
    if (!device_hash)
    {
        printf("→ No device hash found for attacking IP: %s (user not logged in?)\n", ip);
        return;
    }

    const char *level_str = "pending";
    if (ban_level == get_block_level_hard())
        level_str = "hard";
    else if (ban_level == get_block_level_permanent())
        level_str = "permanent";

    printf("→ Sending unblock for attacking IP: %s → device: %s\n", ip, device_hash);

    snprintf(command, sizeof(command),
             "curl -X POST -H \"Content-Type: application/json\" "
             "-d '{\"deviceHash\": \"%s\", \"reason\": \"%s\", "
             "\"duration\": %d, \"level\": \"%s\"}' "
             "%s/unlock-user-by-device --max-time %d --silent",
             device_hash, reason, duration, level_str,
             get_social_network_api_url(), get_curl_timeout_sec());

    int result = system(command);
    if (result == 0)
    {
        printf("✓ User successfully unblocked via device hash\n");
    }
    else
    {
        printf("✗ Failed to send unblock (code: %d)\n", result);
    }
}

/**
 * block_ip - Block IP and MAC address with system-level enforcement
 * @ip: IP address to block
 * @mac: MAC address to block (6-byte array)
 * @reason: Description of blocking reason
 * @duration: Block duration in seconds
 *
 * Implements comprehensive blocking at both L2 (MAC) and L3 (IP) levels
 * using ebtables and iptables. Also logs blocking actions and updates
 * CAM table for persistence.
 */
void block_ip(const char *ip, const uint8_t *mac, const char *reason, int duration)
{
    char command[512] = {0};
    smemset(&command, 0, sizeof(command));

    int written = snprintf("→ L2 BLOCK MAC: %02X:%02X:%02X:%02X:%02X:%02X | IP: %s | Reason: %s\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (ip ? ip : (null)), (reason ? reason : (null)));
    if (written < 0 || written >= sizeof(command)) {
        printf("buffer overflow");
        return;
    }

    // First check if MAC is already blocked
    if (is_mac_blocked(mac))
    {
        printf("→ MAC already blocked in CAM table, skipping write\n");
    }
    else
    {
        const char *filename = get_cam_table_primary_path();

        printf("→ Attempting to write to CAM table: %s\n", filename);

        /*
        int open(const char *path, int flags, ...
                  /* mode_t mode  );

        The argument flags must include one of the following access modes:
        O_RDONLY, O_WRONLY, or O_RDWR. 

        The file creation flags are
       O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOCTTY, O_NOFOLLOW,
       O_TMPFILE, and O_TRUNC

       Ensure that this call creates the file: if this flag is
              specified in conjunction with O_CREAT, and path already
              exists, then open() fails with the error EEXIST.1
        */
        int fd = open(filename, O_RDWR | O_CREAT | O_EXCL, 0700);// fdopen

        if (fd < 0) {
            /*
            FILE *fdopen(int fildes, const char *mode);

            fdopen — associate a stream with a file descriptor
            */
            FILE *fl = fdopen(filename, "r+b");
        } else if (errno == EEXIST) {
            FILE *fl = fopen(filename, "r+b");
        }

        FILE *file = fopen(filename, "r+b");
        if (!file)
        {
            printf("✗ Failed to open CAM file, creating new...\n");

            char dir_cmd[512] = {0};
            /*
            char *strpbrk(const char *s, const char *accept);
            */
            if (strpbrk(dir_path, ";|&$`(){}[]<>!") != NULL) {
                printf("✗ Dangerous characters in path\n");
                return;
            }
            char dir_path[256] = {0};
            strncpy(dir_path, filename, sizeof(dir_path) - 1);
            char *last_slash = strrchr(dir_path, '/');
            if (last_slash)
                *last_slash = '\0';

            snprintf(dir_cmd, sizeof(dir_cmd), "mkdir -p %s", dir_path);
            system(dir_cmd);

            file = fopen(filename, "w+b");
            if (!file)
            {
                printf("✗ Error creating CAM file: %s\n", strerror(errno));
                return;
            }

            printf("→ Initializing new CAM file...\n");
            cam_file_header_t header = {
                .magic = CAM_MAGIC,
                .version = CAM_VERSION,
                .entry_size = sizeof(cam_file_entry_t),
                .total_entries = get_default_cam_capacity(),
                .trusted_count = 0,
                .pending_count = 0,
                .blocked_count = 0,
                .free_count = get_default_cam_capacity(),
                .created_time = time(NULL),
                .last_updated = time(NULL)};
            fwrite(&header, sizeof(header), 1, file);

            cam_file_entry_t empty_entry = {0};
            for (uint32_t i = 0; i < get_default_cam_capacity(); i++)
            {
                fwrite(&empty_entry, sizeof(empty_entry), 1, file);
            }
            fseek(file, 0, SEEK_SET);
            printf("✓ New CAM file created and initialized\n");
        }

        cam_file_header_t header = {0};
        size_t read_result = fread(&header, sizeof(header), 1, file);
        printf("→ Read header records: %zu\n", read_result);

        if (read_result != 1)
        {
            printf("✗ Error reading CAM file header\n");
            fclose(file);
            return;
        }

        cam_file_entry_t entry = {0};
        int found = 0;

        for (uint32_t i = 0; i < header.total_entries; i++)
        {
            if (fread(&entry, sizeof(entry), 1, file) != 1)
            {
                printf("✗ Error reading entry %u\n", i);
                break;
            }

            if (entry.status == ENTRY_FREE ||
                (memcmp(entry.mac, mac, 6) == 0 && entry.vlan_id == 1))
            {
                found = 1;
                printf("✓ Found entry for saving (index %u)\n", i);

                memcpy(entry.mac, mac, 6);
                entry.vlan_id = 1;
                entry.status = ENTRY_BLOCKED;
                entry.last_seen = time(NULL);

                // warning
                entry.reason = [sizeof(entry.reason) - 1] = '\0';
                strncpy(entry.reason, reason, sizeof(entry.reason) - 1);

                entry.ip_address = [sizeof(entry.ip_address) - 1] = '\0'
                strncpy(entry.ip_address, ip, sizeof(entry.ip_address) - 1);
                entry.block_duration = duration;
                entry.block_time = time(NULL);

                fseek(file, sizeof(header) + i * sizeof(entry), SEEK_SET);
                size_t write_result = fwrite(&entry, sizeof(entry), 1, file);
                printf("→ Written records: %zu\n", write_result);

                header.blocked_count++;
                if (entry.status == ENTRY_FREE)
                {
                    header.free_count--;
                }

                break;
            }
        }

        if (found)
        {
            header.last_updated = time(NULL);
            fseek(file, 0, SEEK_SET);
            fwrite(&header, sizeof(header), 1, file);
            printf("✓ Block saved in CAM table!\n");
            printf("→ Statistics: blocked %d MAC, free %d entries\n",
                   header.blocked_count, header.free_count);
        }
        else
        {
            printf("✗ No free space found in CAM table! (total entries: %u)\n",
                   header.total_entries);
        }

        fclose(file);
    }

    // Apply system-level blocking
    snprintf(command, sizeof(command),
             "ebtables -A INPUT -s %02X:%02X:%02X:%02X:%02X:%02X -j DROP 2>/dev/null",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    system(command);

    snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP 2>/dev/null", ip);
    system(command);

    FILE *log_file = fopen(get_cam_log_path(), "a");

    if (!log_file)
    {
        errno = EINVAL;
        printf("✗ Can't open log file");
        return;
    }
    else if (log_file)
    {
        time_t now = time(NULL);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

        fprintf(log_file, "%s: L2+L3 BLOCKED MAC:%02X:%02X:%02X:%02X:%02X:%02X IP:%s - %s\n",
                timestamp, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip, reason);
        fclose(log_file);
    }
}

/**
 * unblock_ip - Remove IP address block from system
 * @ip: IP address to unblock
 *
 * Removes iptables rule blocking the specified IP address.
 * Note: Does not handle CAM table updates - use cam_table_unblock_mac for MAC-level unblocking.
 */
void unblock_ip(const char *ip)
{
    char command[256];
    printf("→ UNBLOCK IP: %s\n", ip);
    snprintf(command, sizeof(command), "iptables -D INPUT -s %s -j DROP 2>/dev/null", ip);
    system(command);
}

/**
 * add_to_block_list - Add IP/MAC to detector's internal block list
 * @detector: Anomaly detector instance
 * @ip: IP address to block
 * @mac: MAC address to block (6-byte array)
 * @reason: Description of blocking reason
 *
 * Adds IP/MAC combination to detector's internal tracking system and
 * triggers system-level blocking. Also updates CAM table if available.
 * Thread-safe operation.
 */
void add_to_block_list(anomaly_detector_t *detector, const char *ip, const uint8_t *mac, const char *reason)
{
    pthread_mutex_lock(&detector->block_mutex);

    for (int i = 0; i < detector->blocked_count; i++)
    {
        if (strcmp(detector->blocked_ips[i].ip, ip) == 0)
        {
            detector->blocked_ips[i].violation_count++;

            if (detector->blocked_ips[i].violation_count >= get_max_violations_permanent())
            {
                detector->blocked_ips[i].block_level = get_block_level_permanent();
                detector->blocked_ips[i].block_duration = 0;
                strcpy(detector->blocked_ips[i].reason, "PERMANENT BAN: Multiple violations");

                send_ban_to_social_network(ip, mac, "PERMANENT: Multiple violations",
                                           0, get_block_level_permanent());
            }
            else if (detector->blocked_ips[i].violation_count >= get_max_violations_hard())
            {
                detector->blocked_ips[i].block_level = get_block_level_hard();
                detector->blocked_ips[i].block_duration = 3600;
                strcpy(detector->blocked_ips[i].reason, "HARD BAN: Repeated violations");

                send_ban_to_social_network(ip, mac, "HARD: Repeated violations",
                                           3600, get_block_level_hard());
            }

            printf("✓ IP %s is already blacklisted. Violations: %d, Level: %d\n",
                   ip, detector->blocked_ips[i].violation_count, detector->blocked_ips[i].block_level);

            pthread_mutex_unlock(&detector->block_mutex);
            return;
        }
    }

    if (detector->blocked_count < 100)
    {
        strncpy(detector->blocked_ips[detector->blocked_count].ip, ip, 15);
        memcpy(detector->blocked_ips[detector->blocked_count].mac, mac, 6);
        detector->blocked_ips[detector->blocked_count].block_time = time(NULL);
        detector->blocked_ips[detector->blocked_count].block_level = get_block_level_pending();
        detector->blocked_ips[detector->blocked_count].violation_count = 1;
        detector->blocked_ips[detector->blocked_count].block_duration = 3600; // 1 час
        strncpy(detector->blocked_ips[detector->blocked_count].reason, reason, 99);

        send_ban_to_social_network(ip, mac, reason, 3600, get_block_level_pending());

        block_ip(ip, mac, reason, 3600);
        apply_blocking_by_level(ip, mac, get_block_level_pending(), reason);

        if (detector->cam_manager && detector->cam_manager->initialized)
        {
            cam_table_block_mac(detector->cam_manager, mac, 1, reason);
        }

        detector->blocked_count++;
        printf("✓ IP %s added to blacklist. Total blocked: %d\n", ip, detector->blocked_count);
    }

    pthread_mutex_unlock(&detector->block_mutex);
}

// ===== BLOCKING BY LEVEL =====
void apply_blocking_by_level(const char *ip, const uint8_t *mac, int block_level, const char *reason)
{
    char command[256];

    switch (block_level)
    {
    case BLOCK_LEVEL_PENDING:
        printf("PENDING BLOCK: %s | MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        snprintf(command, sizeof(command),
                 "iptables -A INPUT -s %s -m limit --limit 10/min -j LOG --log-prefix \"PENDING_BLOCK: \" 2>/dev/null", ip);
        system(command);
        break;

    case BLOCK_LEVEL_HARD:
        printf("HARD BLOCK: %s | MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP 2>/dev/null", ip);
        system(command);

        snprintf(command, sizeof(command),
                 "ebtables -A INPUT -s %02X:%02X:%02X:%02X:%02X:%02X -j DROP 2>/dev/null",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        system(command);
        break;

    case BLOCK_LEVEL_PERMANENT:
        printf("PERMANENT BLOCK: %s | MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP 2>/dev/null", ip);
        system(command);

        snprintf(command, sizeof(command),
                 "ebtables -A INPUT -s %02X:%02X:%02X:%02X:%02X:%02X -j DROP 2>/dev/null",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        system(command);

        snprintf(command, sizeof(command), "echo \"%s %02X:%02X:%02X:%02X:%02X:%02X %s\" >> %s/permanent_ban.list",
                 ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], reason, get_cam_table_primary_path());
        system(command);
        break;
    }

    // Логируем в файл
    FILE *log_file = fopen(get_cam_log_path(), "a");
    if (log_file)
    {
        time_t now = time(NULL);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

        const char *level_str = "PENDING";
        if (block_level == get_block_level_hard())
            level_str = "HARD";
        else if (block_level == get_block_level_permanent())
            level_str = "PERMANENT";

        fprintf(log_file, "%s: %s_BLOCK IP:%s MAC:%02X:%02X:%02X:%02X:%02X:%02X - %s\n",
                timestamp, level_str, ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], reason);
        fclose(log_file);
    }
}

/**
 * check_block_expiry - Check and remove expired blocks
 * @detector: Anomaly detector instance
 *
 * Scans internal block list and removes entries whose block duration
 * has expired. Updates both system rules and CAM table accordingly.
 * Thread-safe operation.
 */
void check_block_expiry(anomaly_detector_t *detector)
{
    pthread_mutex_lock(&detector->block_mutex);
    time_t now = time(NULL);
    int i = 0;

    while (i < detector->blocked_count)
    {
        blocked_ip_t *blocked = &detector->blocked_ips[i];

        if (blocked->block_level == get_block_level_permanent())
        {
            i++;
            continue;
        }

        if (blocked->block_duration > 0 && (now - blocked->block_time > blocked->block_duration))
        {
            printf("→ IP %s block time expired\n", detector->blocked_ips[i].ip);

            remove_blocking_by_level(blocked->ip, blocked->mac, blocked->block_level);

            if (detector->cam_manager && detector->cam_manager->initialized)
            {
                cam_table_unblock_mac(detector->cam_manager, blocked->mac, 1);
            }

            for (int j = i; j < detector->blocked_count - 1; j++)
            {
                detector->blocked_ips[j] = detector->blocked_ips[j + 1];
            }
            detector->blocked_count--;
        }
        else
        {
            i++;
        }
    }
    pthread_mutex_unlock(&detector->block_mutex);
}

void remove_blocking_by_level(const char *ip, const uint8_t *mac, int block_level)
{
    char command[256];

    switch (block_level)
    {
    case BLOCK_LEVEL_PENDING:
        printf("🟢 Снимаем PENDING блокировку: %s\n", ip);
        snprintf(command, sizeof(command), "iptables -D INPUT -s %s -m limit --limit 10/min -j LOG --log-prefix \"PENDING_BLOCK: \" 2>/dev/null", ip);
        system(command);
        break;

    case BLOCK_LEVEL_HARD:
        printf("🟢 Снимаем HARD блокировку: %s\n", ip);
        snprintf(command, sizeof(command), "iptables -D INPUT -s %s -j DROP 2>/dev/null", ip);
        system(command);
        snprintf(command, sizeof(command),
                 "ebtables -D INPUT -s %02X:%02X:%02X:%02X:%02X:%02X -j DROP 2>/dev/null",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        system(command);
        break;

    case BLOCK_LEVEL_PERMANENT:
        // PERMANENT блокировки не снимаются автоматически
        printf("🔴 PERMANENT блокировка %s остается активной\n", ip);
        break;
    }
}

// ===== PACKET ANALYSIS =====

/**
 * extract_attacker_ip - Extract source IP address from network packet
 * @packet: Raw packet data buffer
 * @ip_buffer: Output buffer for IP address (must be at least 16 bytes)
 *
 * Parses Ethernet frame to extract source IP address from IPv4 packets.
 * Handles packet structure and network byte order conversion.
 */
void extract_attacker_ip(const unsigned char *packet, char *ip_buffer)
{
    struct ethhdr *eth = (struct ethhdr *)packet;

    if (ntohs(eth->h_proto) == ETH_P_IP)
    {
        struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
        struct in_addr addr;
        addr.s_addr = iph->saddr;
        strcpy(ip_buffer, inet_ntoa(addr));
    }
    else
    {
        strcpy(ip_buffer, "unknown");
    }
}

/**
 * extract_attacker_mac - Extract or generate attacker MAC address
 * @packet: Raw packet data buffer
 * @mac_buffer: Output buffer for MAC address (6 bytes)
 *
 * Note: Currently generates random MAC for demonstration purposes.
 * In production, this should extract real source MAC from Ethernet frame.
 */
void extract_attacker_mac(const unsigned char *packet, uint8_t *mac_buffer)
{
    struct ethhdr *eth = (struct ethhdr *)packet;

    for (int i = 0; i < 6; i++)
    {
        mac_buffer[i] = rand() % 256;
    }
    mac_buffer[0] &= 0xFE;
}

/**
 * update_ip_mac_mapping - Update IP to MAC address mapping table
 * @detector: Anomaly detector instance
 * @ip: IP address to map
 * @mac: MAC address to associate with IP
 *
 * Maintains dynamic mapping between IP and MAC addresses for
 * correlation and blocking purposes. Updates last seen timestamp.
 * Thread-safe operation.
 */
void update_ip_mac_mapping(anomaly_detector_t *detector, const char *ip, const uint8_t *mac)
{
    pthread_mutex_lock(&detector->map_mutex);

    for (int i = 0; i < detector->ip_mac_count; i++)
    {
        if (strcmp(detector->ip_mac_map[i].ip, ip) == 0)
        {
            memcpy(detector->ip_mac_map[i].mac, mac, 6);
            detector->ip_mac_map[i].last_seen = time(NULL);
            pthread_mutex_unlock(&detector->map_mutex);
            return;
        }
    }

    if (detector->ip_mac_count < 500)
    {
        strncpy(detector->ip_mac_map[detector->ip_mac_count].ip, ip, 15);
        memcpy(detector->ip_mac_map[detector->ip_mac_count].mac, mac, 6);
        detector->ip_mac_map[detector->ip_mac_count].last_seen = time(NULL);
        detector->ip_mac_map[detector->ip_mac_count].block_count = 0;
        detector->ip_mac_count++;
    }

    pthread_mutex_unlock(&detector->map_mutex);
}

/**
 * find_mac_by_ip - Find MAC address by IP address in mapping table
 * @detector: Anomaly detector instance
 * @ip: IP address to search for
 *
 * Searches IP-MAC mapping table for specified IP address and returns
 * corresponding MAC address if mapping exists.
 *
 * Return: Pointer to MAC address if found, NULL otherwise
 */
uint8_t *find_mac_by_ip(anomaly_detector_t *detector, const char *ip)
{
    pthread_mutex_lock(&detector->map_mutex);

    for (int i = 0; i < detector->ip_mac_count; i++)
    {
        if (strcmp(detector->ip_mac_map[i].ip, ip) == 0)
        {
            static uint8_t result[6];
            memcpy(result, detector->ip_mac_map[i].mac, 6);
            pthread_mutex_unlock(&detector->map_mutex);
            return result;
        }
    }

    pthread_mutex_unlock(&detector->map_mutex);
    return NULL;
}

// ===== NETWORK STATISTICS =====

/**
 * get_proc_net_stats - Read network interface statistics from procfs
 * @interface: Network interface name to monitor
 * @metrics: SecurityMetrics structure to populate with statistics
 *
 * Parses /proc/net/dev to extract real-time network statistics for
 * specified interface including packet counts, errors, and byte counters.
 *
 * Return: 0 on success, -1 on file access error or interface not found
 */
int get_proc_net_stats(const char *interface, SecurityMetrics *metrics)
{
    FILE *fp = fopen("/proc/net/dev", "r");
    if (!fp)
        return -1;

    char line[512];
    char iface_name[32];
    unsigned long rx_bytes, rx_packets, rx_errs, rx_drop, rx_fifo, rx_frame;
    unsigned long tx_bytes, tx_packets, tx_errs, tx_drop, tx_fifo, tx_colls;

    fgets(line, sizeof(line), fp);
    fgets(line, sizeof(line), fp);

    while (fgets(line, sizeof(line), fp))
    {
        if (sscanf(line, " %[^:]: %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
                   iface_name, &rx_bytes, &rx_packets, &rx_errs, &rx_drop,
                   &rx_fifo, &rx_frame, &rx_drop, &rx_drop,
                   &tx_bytes, &tx_packets, &tx_errs, &tx_drop, &tx_fifo,
                   &tx_colls, &tx_drop, &tx_drop) >= 16)
        {

            char *colon = strchr(iface_name, ':');
            if (colon)
                *colon = '\0';

            if (strcmp(iface_name, interface) == 0)
            {
                metrics->aFramesReceivedOK = rx_packets;
                metrics->aFramesTransmittedOK = tx_packets;
                metrics->aOctetsReceivedOK = rx_bytes;
                metrics->aOctetsTransmittedOK = tx_bytes;
                metrics->aFrameCheckSequenceErrors = rx_errs + rx_frame;
                fclose(fp);
                return 0;
            }
        }
    }

    fclose(fp);
    return -1;
}

/**
 * create_raw_socket - Create raw socket for packet capture
 *
 * Creates non-blocking raw socket capable of capturing all network
 * traffic on the interface for security analysis.
 *
 * Return: Socket file descriptor on success, -1 on error
 */
int create_raw_socket()
{
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        perror("✗ Error creating raw socket");
        return -1;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags != -1)
    {
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }

    return sock;
}

// ===== PACKET PROCESSING =====

/**
 * analyze_packet - Analyze network packet for security threats
 * @packet: Raw packet data buffer
 * @length: Packet length in bytes
 * @metrics: SecurityMetrics structure to update with analysis results
 *
 * Performs comprehensive packet analysis including protocol identification,
 * attack pattern detection, traffic statistics, and security metric updates.
 * Detects SYN floods, UDP floods, ICMP attacks, and promiscuous mode activity.
 */
void analyze_packet(const unsigned char *packet, int length, SecurityMetrics *metrics)
{
    struct ethhdr *eth = (struct ethhdr *)packet;
    metrics->total_packets++;

    extract_attacker_ip(packet, metrics->attacker_ip);
    extract_attacker_mac(packet, metrics->attacker_mac);

    if (memcmp(eth->h_dest, "\xff\xff\xff\xff\xff\xff", 6) == 0)
    {
        metrics->aBroadcastFramesReceivedOK++;
    }
    else if (eth->h_dest[0] & 0x01)
    {
        metrics->aMulticastFramesReceivedOK++;
    }

    if (ntohs(eth->h_proto) == ETH_P_IP)
    {
        struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));

        if (length > 2000)
        {
            metrics->aAlignmentErrors++;
        }

        switch (iph->protocol)
        {
        case IPPROTO_TCP:
        {
            struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ethhdr) + (iph->ihl * 4));
            if (tcph->syn && !tcph->ack)
            {
                metrics->syn_packets++;
                if (metrics->syn_packets > 100 && metrics->packets_per_second > 50)
                {
                    metrics->potential_scan_detected = 1;
                    strcpy(metrics->attack_type, "SYN Flood/Port Scan");
                    metrics->attack_detected = 1;
                }
            }
            break;
        }
        case IPPROTO_UDP:
            metrics->udp_packets++;
            if (metrics->udp_packets > 500 && metrics->packets_per_second > 100)
            {
                metrics->potential_scan_detected = 1;
                strcpy(metrics->attack_type, "UDP Flood");
                metrics->attack_detected = 1;
            }
            break;
        case IPPROTO_ICMP:
            metrics->icmp_packets++;
            if (metrics->icmp_packets > 100 && metrics->packets_per_second > 50)
            {
                strcpy(metrics->attack_type, "ICMP Flood");
                metrics->attack_detected = 1;
            }
            break;
        }

        float broadcast_ratio = (float)metrics->aBroadcastFramesReceivedOK / metrics->total_packets;
        float multicast_ratio = (float)metrics->aMulticastFramesReceivedOK / metrics->total_packets;

        if (broadcast_ratio > 0.3 || multicast_ratio > 0.4)
        {
            metrics->estimated_promiscuous = 1;
        }
    }

    time_t current_time = time(NULL);
    if (current_time != metrics->last_calc_time)
    {
        metrics->packets_per_second = metrics->total_packets - metrics->last_packet_count;
        metrics->last_packet_count = metrics->total_packets;
        metrics->last_calc_time = current_time;
    }
}

// ===== ANOMALY DETECTION =====

/**
 * calculate_baseline - Calculate baseline network behavior metrics
 * @detector: Anomaly detector instance
 *
 * Establishes or updates baseline network behavior using exponential
 * moving average. Used as reference for anomaly detection comparisons.
 * Initializes baseline on first call, updates with smoothing factor thereafter.
 */
void calculate_baseline(anomaly_detector_t *detector)
{
    if (detector->baseline.aFramesReceivedOK == 0)
    {
        detector->baseline = detector->current;
    }
    else
    {
        float alpha = 0.1f;
        detector->baseline.aFramesReceivedOK = (1 - alpha) * detector->baseline.aFramesReceivedOK + alpha * detector->current.aFramesReceivedOK;
        detector->baseline.aFramesTransmittedOK = (1 - alpha) * detector->baseline.aFramesTransmittedOK + alpha * detector->current.aFramesTransmittedOK;
        detector->baseline.packets_per_second = (1 - alpha) * detector->baseline.packets_per_second + alpha * detector->current.packets_per_second;
        detector->baseline.syn_packets = (1 - alpha) * detector->baseline.syn_packets + alpha * detector->current.syn_packets;
    }
}

/**
 * security_handle_attack_detection - Handle detected security threats
 * @detector: Anomaly detector instance
 * @threat_level: Calculated threat score (0-100)
 *
 * Implements security response based on threat level:
 * - Critical threats (≥70): Immediate blocking and CAM table update
 * - High risks (40-69): Mark as pending in CAM table for monitoring
 * Updates IP-MAC mapping and triggers appropriate blocking actions.
 */
void security_handle_attack_detection(anomaly_detector_t *detector, int threat_level)
{
    if (!detector)
        return;

    char *ip = detector->current.attacker_ip;
    uint8_t *mac = detector->current.attacker_mac;

    if (strcmp(ip, "unknown") != 0 && strcmp(ip, "127.0.0.1") != 0)
    {
        update_ip_mac_mapping(detector, ip, mac);
    }

    if (threat_level >= 70)
    {
        char reason[100];
        snprintf(reason, sizeof(reason), "Critical attack: %s (level %d)",
                 detector->current.attack_type, threat_level);
        add_to_block_list(detector, ip, mac, reason);
    }
    else if (threat_level >= 40)
    {
        if (detector->cam_manager && detector->cam_manager->initialized)
        {
            char reason[100];
            snprintf(reason, sizeof(reason), "Suspicious activity: %s (level %d)",
                     detector->current.attack_type, threat_level);
            cam_table_set_mac_pending(detector->cam_manager, mac, 1, reason);
        }
    }
}

/**
 * detect_anomalies - Detect security anomalies from current metrics
 * @detector: Anomaly detector instance
 *
 * Performs comprehensive security analysis comparing current metrics
 * against established baseline. Detects multiple attack patterns including
 * SYN floods, DDoS, port scanning, UDP floods, and promiscuous mode.
 *
 * Return: Threat score (0-100) indicating overall security risk level
 */
int detect_anomalies(anomaly_detector_t *detector)
{
    int score = 0;

    printf("\n=== EXTENDED SECURITY ANALYSIS ===\n");
    printf("→ TRAFFIC: %lu in/%lu out packets | %lu pps\n",
           detector->current.aFramesReceivedOK, detector->current.aFramesTransmittedOK, detector->current.packets_per_second);
    printf("→ TYPES: SYN:%lu UDP:%lu ICMP:%lu\n", detector->current.syn_packets, detector->current.udp_packets, detector->current.icmp_packets);
    printf("→ BROADCAST: %lu | MULTICAST: %lu\n", detector->current.aBroadcastFramesReceivedOK, detector->current.aMulticastFramesReceivedOK);
    printf("→ ATTACKER: IP:%s MAC:%02X:%02X:%02X:%02X:%02X:%02X\n", detector->current.attacker_ip,
           detector->current.attacker_mac[0], detector->current.attacker_mac[1], detector->current.attacker_mac[2],
           detector->current.attacker_mac[3], detector->current.attacker_mac[4], detector->current.attacker_mac[5]);

    // SYN FLOOD DETECTION
    if (detector->baseline.syn_packets > 0)
    {
        float syn_ratio = (float)detector->current.syn_packets / detector->current.total_packets;
        float baseline_syn_ratio = (float)detector->baseline.syn_packets / detector->baseline.total_packets;
        if (syn_ratio > baseline_syn_ratio * 10)
        {
            printf("→ SYN FLOOD: %.1f%% SYN packets\n", syn_ratio * 100);
            score += 50;
        }
    }

    // DDoS DETECTION
    if (detector->baseline.packets_per_second > 0)
    {
        float pps_ratio = (float)detector->current.packets_per_second / detector->baseline.packets_per_second;
        if (pps_ratio > 20)
        {
            printf("→ DDoS ATTACK: speed x%.1f\n", pps_ratio);
            score += 40;
        }
    }

    // PORT SCAN DETECTION
    if (detector->current.potential_scan_detected)
    {
        printf("→ NETWORK SCANNING\n");
        score += 35;
    }

    // UDP FLOOD DETECTION
    if (detector->current.udp_packets > 1000 && detector->current.packets_per_second > 100)
    {
        printf("→ UDP FLOOD: %lu UDP packets\n", detector->current.udp_packets);
        score += 45;
    }

    // PROMISCUOUS MODE DETECTION
    if (detector->current.estimated_promiscuous)
    {
        printf("→ PROMISCUOUS MODE\n");
        score += 30;
    }

    // ERROR DETECTION
    if (detector->current.aFrameCheckSequenceErrors > 100)
    {
        printf("→ CRITICAL ERRORS: %lu\n", detector->current.aFrameCheckSequenceErrors);
        score += 25;
    }

    if (score == 0)
    {
        printf("✓ No security threats\n");
    }
    else
    {
        detector->total_anomalies++;
        detector->anomaly_score = score;
        printf("\n→ THREAT SCORE: %d/100\n", score);
        security_handle_attack_detection(detector, score);

        if (score >= 70)
        {
            printf("→ CRITICAL THREAT: Active attack!\n");
        }
        else if (score >= 40)
        {
            printf("→ HIGH RISK\n");
        }
    }

    return score;
}

/**
 * print_blocked_ips - Display currently blocked IP addresses
 * @detector: Anomaly detector instance
 *
 * Prints formatted list of all currently blocked IP addresses with
 * their metadata including MAC addresses, blocking reasons, and
 * remaining block duration. Thread-safe operation.
 */
void print_blocked_ips(anomaly_detector_t *detector)
{
    pthread_mutex_lock(&detector->block_mutex);

    if (detector->blocked_count > 0)
    {
        printf("\n BLOCKED IP (%d):\n", detector->blocked_count);
        for (int i = 0; i < detector->blocked_count; i++)
        {
            blocked_ip_t *blocked = &detector->blocked_ips[i];
            const char *level_str = "PENDING";
            if (blocked->block_level == get_block_level_hard())
                level_str = "HARD";
            else if (blocked->block_level == get_block_level_permanent())
                level_str = "PERMANENT";

            if (blocked->block_level == get_block_level_permanent())
            {
                printf("  %s (MAC: %02X:%02X:%02X:%02X:%02X:%02X) - %s [%s] [Нарушений: %d]\n",
                       blocked->ip, blocked->mac[0], blocked->mac[1], blocked->mac[2],
                       blocked->mac[3], blocked->mac[4], blocked->mac[5],
                       blocked->reason, level_str, blocked->violation_count);
            }
            else
            {
                time_t remaining = blocked->block_duration - (time(NULL) - blocked->block_time);
                printf("  %s (MAC: %02X:%02X:%02X:%02X:%02X:%02X) - %s [%s] [Осталось: %ld сек] [Нарушений: %d]\n",
                       blocked->ip, blocked->mac[0], blocked->mac[1], blocked->mac[2],
                       blocked->mac[3], blocked->mac[4], blocked->mac[5],
                       blocked->reason, level_str, remaining > 0 ? remaining : 0, blocked->violation_count);
            }
        }
    }

    pthread_mutex_unlock(&detector->block_mutex);
}

// ===== MAIN MONITORING FUNCTION =====

/**
 * start_comprehensive_monitoring - Main security monitoring loop
 * @interface: Network interface to monitor
 * @cam_manager: CAM table manager for security operations
 *
 * Implements comprehensive network security monitoring with CAM table integration.
 * Performs continuous packet analysis, anomaly detection, and automated blocking.
 * Includes baseline establishment, real-time threat detection, and coordinated
 * response with CAM table updates.
 */
void start_comprehensive_monitoring(const char *interface, cam_table_manager_t *cam_manager)
{
    anomaly_detector_t detector;
    init_detector(&detector, cam_manager);

    printf("→ STARTING SECURITY SYSTEM WITH CAM TABLE\n");
    printf("→ Interface: %s\n", interface);
    printf("→ Clearing old rules...\n");
    system("iptables -F 2>/dev/null");

    int raw_sock = create_raw_socket();
    if (raw_sock < 0)
        return;

    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (setsockopt(raw_sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
    {
        perror("✗ Bind error");
        close(raw_sock);
        return;
    }

    // Инициализация Redis
    if (!redis_manager_init())
    {
        printf("⚠️  Redis not available, continuing without device hash lookup\n");
    }

    // Baseline statistics collection
    time_t start_time = time(NULL);
    unsigned char buffer[65536];
    while (!stop_monitoring && (time(NULL) - start_time) < get_baseline_collection_sec())
    {
        get_proc_net_stats(interface, &detector.current);
        int packet_size = recv(raw_sock, buffer, sizeof(buffer), 0);
        if (packet_size > 0)
            analyze_packet(buffer, packet_size, &detector.current);
        usleep(1000);
    }

    calculate_baseline(&detector);
    printf("→ BASELINE METRICS ESTABLISHED\n");
    printf("→ STARTING MONITORING WITH CAM TABLE...\n\n");

    int cycles = 0;
    while (!stop_monitoring)
    {
        cycles++;
        check_block_expiry(&detector);
        detector.previous = detector.current;
        memset(&detector.current, 0, sizeof(SecurityMetrics));
        detector.current.last_calc_time = time(NULL);

        time_t cycle_start = time(NULL);
        int packets_this_cycle = 0;
        while (!stop_monitoring && (time(NULL) - cycle_start) < get_monitoring_cycle_sec())
        {
            get_proc_net_stats(interface, &detector.current);
            int packet_size = recv(raw_sock, buffer, sizeof(buffer), 0);
            if (packet_size > 0)
            {
                analyze_packet(buffer, packet_size, &detector.current);
                packets_this_cycle++;
            }
            usleep(1000);
        }

        detector.current.packets_per_second = packets_this_cycle / get_monitoring_cycle_sec();
        int score = detect_anomalies(&detector);
        print_blocked_ips(&detector);

        if (score < 30)
            calculate_baseline(&detector);
        printf("\n--- Cycle %d completed ---\n", cycles);
    }

    close(raw_sock);
    pthread_mutex_destroy(&detector.block_mutex);
    pthread_mutex_destroy(&detector.map_mutex);
    redis_manager_cleanup();

    printf("\n→ SECURITY SUMMARY:\n");
    printf("Total cycles: %d\n", cycles);
    printf("Attacks detected: %d\n", detector.total_anomalies);
    printf("Blocked IPs: %d\n", detector.blocked_count);
    printf("IP-MAC entries: %d\n", detector.ip_mac_count);
}

/**
 * main - Entry point for network security monitoring system
 * @argc: Argument count
 * @argv: Argument vector
 *
 * Initializes CAM table system and starts comprehensive network security
 * monitoring. Handles signal registration, privilege checking, and
 * coordinated shutdown with final CAM table display.
 *
 * Return: 0 on successful execution, 1 on initialization failure
 */
int main(int argc, char *argv[])
{
    printf("=== NETWORK ATTACK BLOCKING SYSTEM WITH CAM TABLE ===\n\n");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGUSR1, handle_usr1); // For displaying CAM table on request

    const char *interface = "lo";
    if (argc > 1)
    {
        interface = argv[1];
    }

    if (getuid() != 0)
    {
        printf("✗ Root privileges required for blocking!\n");
        printf("→ Run: sudo %s %s\n\n", argv[0], interface);
        return 1;
    }

    // CAM TABLE INITIALIZATION
    cam_table_manager_t cam_manager;
    printf("→ Initializing CAM table...\n");
    if (cam_table_init(&cam_manager, UFT_MODE_L2_BRIDGING) != 0)
    {
        printf("✗ CAM table initialization error!\n");
        return 1;
    }
    printf("✓ CAM table initialized\n");

    printf("→ System automatically blocks attacking IP and MAC:\n");
    printf("   - SYN Flood → Block IP + record MAC in CAM table\n");
    printf("   - DDoS attacks → Instant IP/MAC blocking\n");
    printf("   - Port Scanning → Auto-ban IP/MAC\n");
    printf("   - UDP Flood → Block source IP/MAC\n");
    printf("   - To view CAM table during operation: sudo kill -USR1 %d\n\n", getpid());

    start_comprehensive_monitoring(interface, &cam_manager);

    // DISPLAY CAM TABLE CONTENTS AFTER MONITORING
    printf("\n=== FINAL CAM TABLE STATE ===\n");
    print_cam_table();

    // STOP CAM MANAGER (data preserved in file)
    cam_table_cleanup(&cam_manager);

    return 0;
}