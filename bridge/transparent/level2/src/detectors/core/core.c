#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h> 
#include <Network/Network.h>
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include "/Users/dimaeremin/kryosette-servers-macos/third-party/smemset/include/smemset.h"
#include "/Users/dimaeremin/kryosette-servers-macos/bridge/transparent/level2/src/detectors/core/include/core.h"
#include "/Users/dimaeremin/kryosette-servers-macos/bridge/transparent/level2/src/ethernet/fdb/core/cam_table/include/cam_table_operations.h"
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ifaddrs.h>

static bool is_mac_address_valid(const uint8_t *mac_address);
static bool is_ip_address_valid(const char *ip_address);
static int create_bpf_socket(const char *interface);

static const uint32_t CAM_MAGIC_NUMBER = 0xC4D3F00D; 
static const uint16_t CAM_VERSION_NUMBER = 0x0001; 
static const size_t MAX_COMMAND_LENGTH = 512; 
static const size_t MAX_PATH_LENGTH = 256;
static const size_t MAX_REASON_LENGTH = 128; 
static const size_t MAX_IP_LENGTH = 46; 

struct nlattr {
    uint16_t nla_len;
    uint16_t nla_type;
};

// IP header structure for macOS
struct iphdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#else
    unsigned int version:4;
    unsigned int ihl:4;
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
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
        fprintf(stderr, "ОШИБКА ЦЕЛОСТНОСТИ: Время создания в будущем: %llu\n",
        (unsigned long long)header->created_time);
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
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    return sock;
}

static int get_kernel_control_id(const char *control_name) {
    struct ctl_info ctl;
    smemset(&ctl, 0, sizeof(ctl));
    
    strlcpy(ctl.ctl_name, control_name, sizeof(ctl.ctl_name));

    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    if (ioctl(sock, CTLIOCGINFO, &ctl) < 0) {
        close(sock);
        return -1;
    }

    close(sock);
    return ctl.ctl_id;
}

static int connect_to_kernel_control(int sockfd, const char *control_name) {
    struct sockaddr_ctl sock_ctl;
    smemset(&sock_ctl, 0, sizeof(sock_ctl));

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
    sock_ctl.sc_unit = 0;
    // sock_ctl.ss_sysaddr = SYSPROTO_CONTROL;

    sock_ctl.sc_reserved[0] = 0;
    sock_ctl.sc_reserved[1] = 0;
    sock_ctl.sc_reserved[2] = 0;
    sock_ctl.sc_reserved[3] = 0;
    sock_ctl.sc_reserved[4] = 0;

    if (connect(sockfd, (struct sockaddr *)&sock_ctl, sizeof(sock_ctl)) < 0) {
        perror("connect err");
        return -1;
    }

    return 0;
}

static int create_osx_route_socket(void) {
    int r_sock = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if (r_sock < 0) {
        perror("route socket err");
        return -1;
    }

    int flags = fcntl(r_sock, F_GETFL, 0);
    fcntl(r_sock, F_SETFL, flags | O_NONBLOCK);

    return r_sock;
}

static int get_interface_info_osx(void) {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST, 0};
    size_t len = 0;

    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
        perror("sysctl err");
        return -1;
    }

    char *buf = calloc(1, len);
    if (!buf) return -1;

    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        perror("sysctl err buf");
        free(buf);
        return -1;
    }

    char *next = buf;
    struct if_msghdr *ifhdr = NULL;

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

static int create_bpf_socket(const char *interface) {
    int bpf_fd = -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    struct stat st;

    for (int i = 0; i < 128; i++) {
        char bpf_dev[32];
        snprintf(bpf_dev, sizeof(bpf_dev), "/dev/bpf%d", i);

        if (stat(bpf_dev, &st) < 0) {
            perror("bpf device not found!");
            return -1;
        }

        if (!(st.st_mode & S_IRUSR) || !(st.st_mode & S_IWUSR)) {
            fprintf(stderr, "BPF device %s has wrong permissions: %o\n", 
                    bpf_dev, st.st_mode & 0700);
            return -1;
        }

        if (!S_ISCHR(st.st_mode)) {
            fprintf(stderr, "%s is not a character device\n", bpf_dev);
            return -1;
        }

        bpf_fd = open(bpf_dev, O_RDWR | O_CLOEXEC);

        if (bpf_fd >= 0) {
            printf("Opened BPF device: %s\n", bpf_dev);
            break;
        }
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

    strlcpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));

    int test_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (test_sock >= 0) {
        if (ioctl(test_sock, SIOCGIFFLAGS, &ifr) < 0) {
            close(test_sock);
            close(bpf_fd);
            return -1;
        }
        close(test_sock);
    }

    if (ioctl(bpf_fd, BIOCSETIF, &ifr) < 0) {
        if (errno == ENXIO) {
            fprintf(stderr, "Interface '%s' not found\n", interface);
            fprintf(stderr, "Available interfaces:\n");
            
            struct ifaddrs *ifap, *ifa;
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

// Function to create raw socket for packet capture (macOS version)
static int create_raw_socket(void) {
    // Use BPF on macOS instead of AF_PACKET
    return create_bpf_socket("en0");
}

static int block_ip_simple(const char *ip) {
    char cmd[256] = {0};
    snprintf(cmd, sizeof(cmd), "echo 'block in from %s to any' | pfctl -a cam_blocker -f - 2>&1", ip);
    return system(cmd);
}

static const char* get_cam_table_path_safe(void) {
    static char path_buffer[MAX_PATH_LENGTH];
    smemset(&path_buffer, 0, sizeof(path_buffer));

    const char *home = getenv("HOME");
    
    snprintf(path_buffer, sizeof(path_buffer) - 1, 
             "%s/.cam_table.dat", home ? home : "/tmp");
        
    return path_buffer;
}

static const char* get_cam_log_path_safe(void) {
    static char log_path_buffer[MAX_PATH_LENGTH];
    smemset(&log_path_buffer, 0, sizeof(log_path_buffer));

    const char *home = getenv("HOME");
    
    snprintf(log_path_buffer, sizeof(log_path_buffer),
         "%s/.cam_block.log", 
         home && *home ? home : "/tmp");
    
    return log_path_buffer;
}

static bool is_ip_address_valid(const char *ip_address) {
    if (ip_address == NULL || ip_address[0] == '\0') {
        return false;
    }

    size_t len = strlen(ip_address);
    if (len == 0 || len > INET6_ADDRSTRLEN - 1) {
        return false;
    }

    struct in6_addr addr6;
    smemset(&addr6, 0, sizeof(addr6));

    if (inet_pton(AF_INET6, ip_address, &addr6) == 1) {
        return true;
    }
    
    struct in_addr addr4;
    smemset(&addr4, 0, sizeof(addr4));
    
    if (inet_pton(AF_INET, ip_address, &addr4) == 1) {
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

        if (mac_address[i] != 0xFF) {
            is_all_one = false;
        }
    }
    
    return !is_all_zero && !is_all_one;
}

static bool create_dir_safe(const char *dir_path) {
    if (dir_path == NULL) return false;

    size_t len = strlen(dir_path);
    char copy_dir_path[len + 1];
    smemset(&copy_dir_path, 0, sizeof(copy_dir_path));
    strncpy(copy_dir_path, dir_path, len);
    copy_dir_path[len] = '\0';

    const char *dir_components_copy = copy_dir_path;
    char *slash_pointer = NULL;

    while ((slash_pointer = strchr(dir_components_copy, '/')) != NULL) {
        if (slash_pointer != dir_components_copy) {
            char original_char = *slash_pointer;
            *slash_pointer = '\0';   

            mkdir(copy_dir_path, 0700);

            *slash_pointer = original_char;
        }
        dir_components_copy = slash_pointer + 1;
    }

    if (strlen(copy_dir_path) > 0) {
        mkdir(copy_dir_path, 0700);
    }

    return true;
}

static bool block_ip_secure(
    const char *ip_address,
    const uint8_t *mac_address,
    const char *block_reason,
    int duration_seconds
) {
    char system_command[MAX_COMMAND_LENGTH] = {0};
    cam_file_header_t file_header;
    cam_file_entry_t file_entry;
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
        return false;
    }
    
    if (block_reason == NULL) {
        fprintf(stderr, "ОШИБКА: Причина блокировки не может быть NULL\n");
        return false;
    }
    
    if (!is_ip_address_valid(ip_address) || !is_mac_address_valid(mac_address)) {
        fprintf(stderr, "ОШИБКА: Неверный формат IP адреса: %s\n", ip_address);
        return false;
    }
    
    // Note: contains_dangerous_characters is not defined in this file
    // You'll need to implement it or remove this check
    /*
    if (contains_dangerous_characters(block_reason)) {
        fprintf(stderr, "ОШИБКА: Причина блокировки содержит опасные символы\n");
        return false;
    }
    */
    
    if (strlen(block_reason) >= MAX_REASON_LENGTH || duration_seconds < 0) {
        fprintf(stderr, "ОШИБКА: Причина блокировки слишком длинная\n");
        return false;
    }

    printf("→ Начало блокировки L2/L3:\n");
    printf(" MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           mac_address[0], mac_address[1], mac_address[2],
           mac_address[3], mac_address[4], mac_address[5]);
    printf(" IP: %s\n", ip_address);
    printf(" Причина: %s\n", block_reason);
    printf(" Длительность: %d секунд\n", duration_seconds);
    
    // Note: is_mac_address_blocked_safe is not defined in this file
    // You'll need to implement it or adjust this logic
    /*
    if (is_mac_address_blocked_safe(mac_address)) {
        printf("→ MAC адрес уже заблокирован в CAM таблице, пропускаем запись\n");
    } else {
        printf("→ MAC адрес не найден в блокировках, продолжаем...\n");
    }
    */
    
    const char *cam_file_path = get_cam_table_path_safe();
    printf("→ Работа с CAM файлом: %s\n", cam_file_path);
    
    cam_file_handle = fopen(cam_file_path, "r+b");
    
    if (cam_file_handle == NULL) {
        printf("→ CAM файл не найден, создаем новый...\n");
        
        char directory_path_copy[MAX_PATH_LENGTH] = {0};
        smemset(&directory_path_copy, 0, sizeof(directory_path_copy));
        strncpy(directory_path_copy, cam_file_path, sizeof(directory_path_copy) - 1);
        directory_path_copy[sizeof(directory_path_copy) - 1] = '\0';
        
        char *last_slash_position = strrchr(directory_path_copy, '/');
        if (last_slash_position != NULL) {
            *last_slash_position = '\0';
            
            if (!create_dir_safe(directory_path_copy)) {
                fprintf(stderr, "ОШИБКА: Не удалось создать директорию\n");
                return false;
            }
        }
        
        int file_descriptor = open(cam_file_path, O_RDWR | O_CREAT | O_EXCL, 0600);
        
        if (file_descriptor < 0) {
            if (errno == EEXIST) {
                cam_file_handle = fopen(cam_file_path, "r+b");
            } else {
                fprintf(stderr, "ОШИБКА: Не удалось создать CAM файл: %s\n", strerror(errno));
                return false;
            }
        } else {
            cam_file_handle = fdopen(file_descriptor, "w+b");
            
            if (cam_file_handle == NULL) {
                close(file_descriptor);
                fprintf(stderr, "ОШИБКА: Не удалось открыть созданный файл\n");
                return false;
            }
            
            smemset(&file_header, 0, sizeof(file_header));
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
                return false;
            }
            
            cam_file_entry_t empty_entry;
            smemset(&empty_entry, 0, sizeof(empty_entry));
            
            for (uint32_t fill_index = 0; fill_index < file_header.total_entries; fill_index++) {
                bytes_written = fwrite(&empty_entry, sizeof(empty_entry), 1, cam_file_handle);
                if (bytes_written != 1) {
                    fprintf(stderr, "ОШИБКА: Не удалось инициализировать запись %u\n", fill_index);
                    fclose(cam_file_handle);
                    return false;
                }
            }
            
            fseek(cam_file_handle, 0, SEEK_SET);
        }
    }

    if (cam_file_handle != NULL) {
        int lock_result = flock(fileno(cam_file_handle), LOCK_EX);
        if (lock_result < 0) {
            perror("lock_file");
            fclose(cam_file_handle);
            return false;
        }

        fseek(cam_file_handle, 0, SEEK_SET);
        bytes_read = fread(&file_header, sizeof(file_header), 1, cam_file_handle);
        if (bytes_read != 1) {
            fprintf(stderr, "ОШИБКА: Не удалось прочитать заголовок\n");
            flock(fileno(cam_file_handle), LOCK_UN);
            fclose(cam_file_handle);
            return false;
        }

        if (!is_file_header_valid(&file_header)) {
            fprintf(stderr, "ОШИБКА: Заголовок CAM файла поврежден\n");

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
            return false;
        }

        if (file_header.magic != CAM_MAGIC_NUMBER) {
            printf("ОШИБКА: Неверное магическое число\n");
            flock(fileno(cam_file_handle), LOCK_UN);
            fclose(cam_file_handle);
            return false;
        }

        if (file_header.version != CAM_VERSION_NUMBER) {
            printf("ОШИБКА: Неверная версия\n");
            flock(fileno(cam_file_handle), LOCK_UN);
            fclose(cam_file_handle);
            return false;
        }

        entry_found_flag = 0;
        for (entry_index = 0; entry_index < file_header.total_entries; entry_index++) {
            bytes_read = fread(&file_entry, sizeof(file_entry), 1, cam_file_handle);
            if (bytes_read != 1) {
                fprintf(stderr, "ОШИБКА: Не удалось прочитать запись %u\n", entry_index);
                break;
            }

            if (file_entry.status == ENTRY_STATUS_FREE) {
                entry_found_flag = 1;
                printf("✓ Найдена свободная запись (индекс %u)\n", entry_index);
                break;
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

            strncpy(file_entry.ip_address, ip_address, sizeof(file_entry.ip_address) - 1);
            file_entry.ip_address[sizeof(file_entry.ip_address) - 1] = '\0';

            strncpy(file_entry.reason, block_reason, sizeof(file_entry.reason) - 1);
            file_entry.reason[sizeof(file_entry.reason) - 1] = '\0';

            fseek(cam_file_handle, sizeof(file_header) + entry_index * sizeof(file_entry), SEEK_SET);

            bytes_written = fwrite(&file_entry, sizeof(file_entry), 1, cam_file_handle);
            if (bytes_written != 1) {
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

    int bytes_formatted = snprintf(system_command, sizeof(system_command) - 1,
    "echo 'block drop from any to any MAC %02X:%02X:%02X:%02X:%02X:%02X' | "
    "sudo pfctl -a cam_blocker -f - 2>&1",
    mac_address[0], mac_address[1], mac_address[2],
    mac_address[3], mac_address[4], mac_address[5]);

    if (bytes_formatted < 0 || bytes_formatted >= (int)sizeof(system_command)) {
        fprintf(stderr, "ОШИБКА: Переполнение буфера команды IP блокировки\n");
        return false;
    } else {
        // Note: contains_dangerous_characters is not defined
        // You'll need to implement it or remove this check
        /*
        if (contains_dangerous_characters(system_command)) {
            fprintf(stderr, "ОШИБКА: Команда содержит опасные символы\n");
            return false;
        } else {
        */
        printf("→ Выполнение: %s\n", system_command);
        operation_result = system(system_command);
        if (operation_result != 0) {
            fprintf(stderr, "ОШИБКА: Команда IP блокировки завершилась с кодом %d\n", 
                WEXITSTATUS(operation_result));
        }
        // }
    }

    const char *log_file_path = get_cam_log_path_safe();
    log_file_handle = fopen(log_file_path, "a");

    if (log_file_handle == NULL) {
        fprintf(stderr, "ОШИБКА: Не удалось открыть лог-файл для записи\n");
        return false;
    }

    if (log_file_handle != NULL) {
        current_time_value = time(NULL);

        char time_buf[32] = {0};
        smemset(&time_buf, 0, sizeof(time_buf));
        
        struct tm *time_info = localtime(&current_time_value);
        strftime(time_buf, sizeof(time_buf) - 1, "%Y-%m-%d %H:%M:%S", time_info);
        time_buf[sizeof(time_buf) - 1] = '\0';

        fprintf(log_file_handle, "%s | BLOCK | MAC:%02X:%02X:%02X:%02X:%02X:%02X | "
            "IP:%s | Reason:%s | Duration:%d\n",
            time_buf,
            mac_address[0], mac_address[1], mac_address[2],
            mac_address[3], mac_address[4], mac_address[5],
            ip_address, block_reason, duration_seconds);
        
        fclose(log_file_handle);
        log_file_handle = NULL;
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
    
    return true;
}

static void process_packet(int sock_fd, const char *buf, size_t buf_size) {
    struct sockaddr_in addr;
    smemset(&addr, 0, sizeof(addr));
    socklen_t addr_len = sizeof(addr);

    ssize_t packet_len = recvfrom(sock_fd, (void *)buf, buf_size, 0, (struct sockaddr *)&addr, &addr_len);

    if (packet_len > 0) {
        struct ethhdr *eth = (struct ethhdr *)buf;
        if (ntohs(eth->h_proto) == ETH_P_IP) {
            // Process IP packet
        } 
    }
}

static int create_cam_directory(void) {
    struct stat st = {0};
    const char *primary_path = get_cam_table_path_safe();
    const char *fallback_path = "/tmp/.cam_table";

    char primary_dir[MAX_PATH_LENGTH];
    smemset(&primary_dir, 0, sizeof(primary_dir));
    char fallback_dir[MAX_PATH_LENGTH];
    smemset(&fallback_dir, 0, sizeof(fallback_dir));

    strncpy(primary_dir, primary_path, sizeof(primary_dir) - 1);
    primary_dir[sizeof(primary_dir) - 1] = '\0';
    strncpy(fallback_dir, fallback_path, sizeof(fallback_dir) - 1);
    fallback_dir[sizeof(fallback_dir) - 1] = '\0';

    char *primary_slash = strrchr(primary_dir, '/');
    char *fallback_slash = strrchr(fallback_dir, '/');

    if (primary_slash)
        *primary_slash = '\0';
    if (fallback_slash)
        *fallback_slash = '\0';

    if (stat(primary_dir, &st) == 0) {
        if (S_ISDIR(st.st_mode))
            return 0;
        else {
            fprintf(stderr, "Error: %s exists but is not a directory\n", primary_dir);
            return -1;
        }
    }

    if (mkdir(primary_dir, 0700) == 0)
        return 0;

    if (errno != EACCES)
        fprintf(stderr, "mkdir(%s) failed: %s\n", primary_dir, strerror(errno));

    if (stat(fallback_dir, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            printf("Using existing fallback: %s\n", fallback_dir);
            return 0;
        } else {
            fprintf(stderr, "Error: %s exists but is not a directory\n", fallback_dir);
            return -1;
        }
    }

    if (mkdir(fallback_dir, 0700) == 0) {
        printf("Created fallback directory: %s\n", fallback_dir);
        return 0;
    }

    fprintf(stderr, "Failed to create both directories\n");
    return -1;
}

static int create_osx_socket_data(int type, const char *data, size_t len) {
    static int osx_sock = -1;

    if (osx_sock < 0) {
        if (type == 0) {
            osx_sock = create_osx_route_socket();
            get_interface_info_osx();
        } else if (type == 1) {
            osx_sock = create_osx_route_socket();
            if (connect_to_kernel_control(osx_sock, "com.apple.network.statistics") < 0) {
                close(osx_sock);
                osx_sock = -1;
                return -1;
            }
        } else if (type == 2) {
            osx_sock = create_bpf_socket("en0");
            // Note: setup_ function is not defined
            // You'll need to implement it or adjust this logic
        }
    }

    if (osx_sock < 0) {
        return -1;
    }

    // Send data through the socket
    return send(osx_sock, data, len, 0);
}

static int init_cam_file(const char *filename, uint32_t capacity) {
    FILE *file = fopen(filename, "wb");
    if (!file)
        return -1;

    cam_file_header_t header;
    smemset(&header, 0, sizeof(header));
    header.magic = CAM_MAGIC_NUMBER;
    header.version = CAM_VERSION_NUMBER;
    header.entry_size = sizeof(cam_file_entry_t);
    header.total_entries = capacity;
    header.trusted_count = 0;
    header.pending_count = 0;
    header.blocked_count = 0;
    header.free_count = capacity;
    header.created_time = time(NULL);
    header.last_updated = time(NULL);

    fwrite(&header, sizeof(header), 1, file);

    cam_file_entry_t empty_entry;
    smemset(&empty_entry, 0, sizeof(empty_entry));
    for (uint32_t i = 0; i < capacity; i++) {
        fwrite(&empty_entry, sizeof(empty_entry), 1, file);
    }

    fclose(file);
    return 0;
}

// ===== CAM TABLE READER =====

void print_cam_table(void)
{
    const char *filename = get_cam_table_path_safe();

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

        if (entry.status == ENTRY_STATUS_BLOCKED)
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

static const uint32_t DEFAULT_CAM_CAPACITY = 256000;

int cam_table_init(cam_table_manager_t *manager, uft_mode_t default_mode)
{
    if (!manager)
        return -1;

    if (create_cam_directory() != 0)
    {
        printf("✗ Failed to create CAM table directory\n");
        return -1;
    }

    const char *filename = get_cam_table_path_safe();
    FILE *test_file = fopen(filename, "rb");
    if (!test_file)
    {
        printf("→ Creating new CAM table: %s\n", filename);
        if (init_cam_file(filename, DEFAULT_CAM_CAPACITY) != 0)
        {
            printf("✗ Error creating CAM file\n");
            return -1;
        }
    }
    else
    {
        fclose(test_file);
        printf("→ Loading existing CAM table\n");

        print_cam_table();
    }

    manager->current_mode = default_mode;
    manager->initialized = true;

    printf("✓ CAM table initialized: %s\n", filename);
    printf("   Mode: %d, Capacity: %d entries\n", default_mode, DEFAULT_CAM_CAPACITY);
    return 0;
}

int cam_table_cleanup(cam_table_manager_t *manager)
{
    if (!manager)
        return -1;

    manager->initialized = false;
    printf("✓ CAM manager stopped (data saved in file)\n");
    return 0;
}

// ===== CHECK IF MAC IS BLOCKED =====

int is_mac_blocked(const uint8_t *mac_bytes)
{
    const char *filename = get_cam_table_path_safe();
    FILE *file = fopen(filename, "rb");
    if (!file)
        return 0;

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

        if (entry.status == ENTRY_STATUS_BLOCKED &&
            memcmp(entry.mac, mac_bytes, 6) == 0)
        {
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

// ===== CAM TABLE FUNCTIONS =====

static int block_mac_in_file(const uint8_t *mac_bytes, uint16_t vlan_id, const char *reason)
{
    const char *filename = get_cam_table_path_safe();
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

        if (entry.status == ENTRY_STATUS_FREE ||
            (memcmp(entry.mac, mac_bytes, 6) == 0 && entry.vlan_id == vlan_id))
        {
            found = 1;

            memcpy(entry.mac, mac_bytes, 6);
            entry.vlan_id = vlan_id;
            entry.status = ENTRY_STATUS_BLOCKED;
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
            if (entry.status == ENTRY_STATUS_FREE)
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

static void update_memory_cache(cam_table_manager_t *manager, const uint8_t *mac_bytes,
                                uint16_t vlan_id, uint8_t status)
{
    pthread_rwlock_wrlock(&manager->rwlock);

    pthread_rwlock_unlock(&manager->rwlock);
}

static int is_mac_already_blocked(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id)
{
    int blocked = 0;

    pthread_rwlock_rdlock(&manager->rwlock);
    pthread_rwlock_unlock(&manager->rwlock);

    if (blocked)
    {
        printf("→ MAC already blocked in CAM table: %02X:%02X:%02X:%02X:%02X:%02X\n",
               mac_bytes[0], mac_bytes[1], mac_bytes[2],
               mac_bytes[3], mac_bytes[4], mac_bytes[5]);
    }

    return blocked;
}

int cam_table_block_mac(cam_table_manager_t *manager, const uint8_t *mac_bytes,
                        uint16_t vlan_id, const char *reason)
{
    if (!manager || !mac_bytes || !reason)
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
        update_memory_cache(manager, mac_bytes, vlan_id, ENTRY_STATUS_BLOCKED);
    }

    return result;
}

int cam_table_unblock_mac(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id)
{
    if (!manager)
        return -1;

    const char *filename = get_cam_table_path_safe();
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

        if (entry.status == ENTRY_STATUS_BLOCKED &&
            memcmp(entry.mac, mac_bytes, 6) == 0 &&
            entry.vlan_id == vlan_id)
        {
            found = 1;
            smemset(&entry, 0, sizeof(entry));
            entry.status = ENTRY_STATUS_FREE;

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

int cam_table_set_mac_pending(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id, const char *reason)
{
    if (!manager)
        return -1;

    const char *filename = get_cam_table_path_safe();
    FILE *file = fopen(filename, "r+b");
    if (!file)
        return -1;

    cam_file_header_t header;
    fread(&header, sizeof(header), 1, file);

    cam_file_entry_t entry;
    smemset(&entry, 0, sizeof(entry));
    int found = 0;

    for (uint32_t i = 0; i < header.total_entries; i++)
    {
        fread(&entry, sizeof(entry), 1, file);

        if (entry.status == ENTRY_STATUS_FREE ||
            (memcmp(entry.mac, mac_bytes, 6) == 0 && entry.vlan_id == vlan_id))
        {
            found = 1;

            memcpy(entry.mac, mac_bytes, 6);
            entry.vlan_id = vlan_id;
            entry.status = ENTRY_STATUS_PENDING;
            entry.last_seen = time(NULL);
            strncpy(entry.reason, reason, sizeof(entry.reason) - 1);
            entry.reason[sizeof(entry.reason) - 1] = '\0';

            fseek(file, sizeof(header) + i * sizeof(entry), SEEK_SET);
            fwrite(&entry, sizeof(entry), 1, file);

            header.pending_count++;
            if (entry.status == ENTRY_STATUS_FREE)
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

volatile sig_atomic_t stop_monitoring = 0;

void handle_signal(int sig)
{
    stop_monitoring = 1;
    printf("\n→ Stopping monitoring...\n");
}

void handle_usr1(int sig)
{
    printf("\n→ SHOW CAM TABLE ON REQUEST\n");
    print_cam_table();
}

// ===== DETECTOR FUNCTIONS =====

void init_detector(anomaly_detector_t *detector, cam_table_manager_t *cam_manager)
{
    smemset(detector, 0, sizeof(anomaly_detector_t));
    detector->current.last_calc_time = time(NULL);
    detector->cam_manager = cam_manager;
    pthread_mutex_init(&detector->block_mutex, NULL);
    pthread_mutex_init(&detector->map_mutex, NULL);
}

// Helper function prototypes (you need to implement these)
static const char* get_device_hash_secure(const char *ip);
static const int get_block_level_hard(void);
static const int get_block_level_permanent(void);
static const char* get_social_network_api_url(void);
static const int get_curl_timeout_sec(void);

void send_ban_to_social_network(const char *ip, const uint8_t *mac,
                                const char *reason, int duration,
                                int ban_level)
{
    char command[1024];

    char *device_hash = (char*)get_device_hash_secure(ip);
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

void unblock_device(const char *ip, const uint8_t *mac,
                    const char *reason, int duration,
                    int ban_level, time_t block_until)
{
    char command[1024];

    char *device_hash = (char*)get_device_hash_secure(ip);
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

static const int BLOCK_LEVEL_PENDING = 1;
static const int BLOCK_LEVEL_HARD = 2;
static const int BLOCK_LEVEL_PERMANENT = 3;

void block_ip(const char *ip, const uint8_t *mac, const char *reason, int duration)
{
    char command[512] = {0};
    smemset()

    int written = snprintf(command, sizeof(command), 
        "→ L2 BLOCK MAC: %02X:%02X:%02X:%02X:%02X:%02X | IP: %s | Reason: %s\n",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 
        (ip ? ip : "(null)"), (reason ? reason : "(null)"));
    
    if (written < 0 || written >= (int)sizeof(command)) {
        printf("buffer overflow");
        return;
    }

    printf("%s", command);

    // First check if MAC is already blocked
    if (is_mac_blocked(mac))
    {
        printf("→ MAC already blocked in CAM table, skipping write\n");
    }
    else
    {
        const char *filename = get_cam_table_path_safe();

        printf("→ Attempting to write to CAM table: %s\n", filename);

        int fd = open(filename, O_RDWR | O_CREAT | O_EXCL, 0700);
        FILE *file = NULL;

        if (fd < 0) {
            if (errno == EEXIST) {
                file = fopen(filename, "r+b");
            }
        } else {
            file = fdopen(fd, "r+b");
        }

        if (!file)
        {
            printf("✗ Failed to open CAM file, creating new...\n");

            char dir_path[256] = {0};
            strncpy(dir_path, filename, sizeof(dir_path) - 1);
            char *last_slash = strrchr(dir_path, '/');
            if (last_slash)
                *last_slash = '\0';

            char dir_cmd[512] = {0};
            snprintf(dir_cmd, sizeof(dir_cmd), "mkdir -p %s", dir_path);
            system(dir_cmd);

            file = fopen(filename, "w+b");
            if (!file)
            {
                printf("✗ Error creating CAM file: %s\n", strerror(errno));
                return;
            }

            printf("→ Initializing new CAM file...\n");
            cam_file_header_t header;
            smemset(&header, 0, sizeof(header));
            header.magic = CAM_MAGIC_NUMBER;
            header.version = CAM_VERSION_NUMBER;
            header.entry_size = sizeof(cam_file_entry_t);
            header.total_entries = DEFAULT_CAM_CAPACITY;
            header.trusted_count = 0;
            header.pending_count = 0;
            header.blocked_count = 0;
            header.free_count = DEFAULT_CAM_CAPACITY;
            header.created_time = time(NULL);
            header.last_updated = time(NULL);
            
            fwrite(&header, sizeof(header), 1, file);

            cam_file_entry_t empty_entry;
            smemset(&empty_entry, 0, sizeof(empty_entry));
            for (uint32_t i = 0; i < DEFAULT_CAM_CAPACITY; i++)
            {
                fwrite(&empty_entry, sizeof(empty_entry), 1, file);
            }
            fseek(file, 0, SEEK_SET);
            printf("✓ New CAM file created and initialized\n");
        }

        cam_file_header_t header;
        smemset(&header, 0, sizeof(header));
        size_t read_result = fread(&header, sizeof(header), 1, file);
        printf("→ Read header records: %zu\n", read_result);

        if (read_result != 1)
        {
            printf("✗ Error reading CAM file header\n");
            fclose(file);
            return;
        }

        cam_file_entry_t entry;
        smemset(&entry, 0, sizeof(entry));
        int found = 0;

        for (uint32_t i = 0; i < header.total_entries; i++)
        {
            if (fread(&entry, sizeof(entry), 1, file) != 1)
            {
                printf("✗ Error reading entry %u\n", i);
                break;
            }

            if (entry.status == ENTRY_STATUS_FREE ||
                (memcmp(entry.mac, mac, 6) == 0 && entry.vlan_id == 1))
            {
                found = 1;
                printf("✓ Found entry for saving (index %u)\n", i);

                memcpy(entry.mac, mac, 6);
                entry.vlan_id = 1;
                entry.status = ENTRY_STATUS_BLOCKED;
                entry.last_seen = time(NULL);

                strncpy(entry.reason, reason, sizeof(entry.reason) - 1);
                entry.reason[sizeof(entry.reason) - 1] = '\0';

                strncpy(entry.ip_address, ip, sizeof(entry.ip_address) - 1);
                entry.ip_address[sizeof(entry.ip_address) - 1] = '\0';
                
                entry.block_duration = duration;
                entry.block_time = time(NULL);

                fseek(file, sizeof(header) + i * sizeof(entry), SEEK_SET);
                size_t write_result = fwrite(&entry, sizeof(entry), 1, file);
                printf("→ Written records: %zu\n", write_result);

                header.blocked_count++;
                if (entry.status == ENTRY_STATUS_FREE)
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

    // Apply system-level blocking (macOS uses pfctl instead of ebtables/iptables)
    snprintf(command, sizeof(command),
             "echo 'block drop from any to any MAC %02X:%02X:%02X:%02X:%02X:%02X' | "
             "sudo pfctl -a cam_blocker -f - 2>&1",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    system(command);

    snprintf(command, sizeof(command), 
             "echo 'block in from %s to any' | sudo pfctl -a cam_blocker -f - 2>&1", ip);
    system(command);

    const char *log_file_path = get_cam_log_path_safe();
    FILE *log_file = fopen(log_file_path, "a");

    if (!log_file)
    {
        printf("✗ Can't open log file\n");
        return;
    }
    
    time_t now = time(NULL);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(log_file, "%s: L2+L3 BLOCKED MAC:%02X:%02X:%02X:%02X:%02X:%02X IP:%s - %s\n",
            timestamp, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip, reason);
    fclose(log_file);
}

void unblock_ip(const char *ip)
{
    char command[256];
    printf("→ UNBLOCK IP: %s\n", ip);
    snprintf(command, sizeof(command), 
             "echo 'pass in from %s to any' | sudo pfctl -a cam_blocker -f - 2>&1", ip);
    system(command);
}

// Helper functions for blocking levels
static const int get_max_violations_permanent(void) { return 5; }
static const int get_max_violations_hard(void) { return 3; }
static const int get_block_level_pending(void) { return BLOCK_LEVEL_PENDING; }

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
                detector->blocked_ips[i].block_level = BLOCK_LEVEL_PERMANENT;
                detector->blocked_ips[i].block_duration = 0;
                strcpy(detector->blocked_ips[i].reason, "PERMANENT BAN: Multiple violations");

                send_ban_to_social_network(ip, mac, "PERMANENT: Multiple violations",
                                           0, BLOCK_LEVEL_PERMANENT);
            }
            else if (detector->blocked_ips[i].violation_count >= get_max_violations_hard())
            {
                detector->blocked_ips[i].block_level = BLOCK_LEVEL_HARD;
                detector->blocked_ips[i].block_duration = 3600;
                strcpy(detector->blocked_ips[i].reason, "HARD BAN: Repeated violations");

                send_ban_to_social_network(ip, mac, "HARD: Repeated violations",
                                           3600, BLOCK_LEVEL_HARD);
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
        detector->blocked_ips[detector->blocked_count].block_duration = 3600;
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
                 "echo 'block in from %s to any' | sudo pfctl -a cam_blocker -f - 2>&1", ip);
        system(command);
        break;

    case BLOCK_LEVEL_HARD:
        printf("HARD BLOCK: %s | MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        snprintf(command, sizeof(command), 
                 "echo 'block in from %s to any' | sudo pfctl -a cam_blocker -f - 2>&1", ip);
        system(command);

        snprintf(command, sizeof(command),
                 "echo 'block drop from any to any MAC %02X:%02X:%02X:%02X:%02X:%02X' | "
                 "sudo pfctl -a cam_blocker -f - 2>&1",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        system(command);
        break;

    case BLOCK_LEVEL_PERMANENT:
        printf("PERMANENT BLOCK: %s | MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        snprintf(command, sizeof(command), 
                 "echo 'block in from %s to any' | sudo pfctl -a cam_blocker -f - 2>&1", ip);
        system(command);

        snprintf(command, sizeof(command),
                 "echo 'block drop from any to any MAC %02X:%02X:%02X:%02X:%02X:%02X' | "
                 "sudo pfctl -a cam_blocker -f - 2>&1",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        system(command);

        // Log permanent ban to file
        const char *cam_table_path = get_cam_table_path_safe();
        char permanent_file[MAX_PATH_LENGTH];
        snprintf(permanent_file, sizeof(permanent_file), "%s/permanent_ban.list", cam_table_path);
        
        FILE *perm_file = fopen(permanent_file, "a");
        if (perm_file) {
            fprintf(perm_file, "%s %02X:%02X:%02X:%02X:%02X:%02X %s\n",
                    ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], reason);
            fclose(perm_file);
        }
        break;
    }

    FILE *log_file = fopen(get_cam_log_path_safe(), "a");
    if (log_file)
    {
        time_t now = time(NULL);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

        const char *level_str = "PENDING";
        if (block_level == BLOCK_LEVEL_HARD)
            level_str = "HARD";
        else if (block_level == BLOCK_LEVEL_PERMANENT)
            level_str = "PERMANENT";

        fprintf(log_file, "%s: %s_BLOCK IP:%s MAC:%02X:%02X:%02X:%02X:%02X:%02X - %s\n",
                timestamp, level_str, ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], reason);
        fclose(log_file);
    }
}

void check_block_expiry(anomaly_detector_t *detector)
{
    pthread_mutex_lock(&detector->block_mutex);
    time_t now = time(NULL);
    int i = 0;

    while (i < detector->blocked_count)
    {
        blocked_ip_t *blocked = &detector->blocked_ips[i];

        if (blocked->block_level == BLOCK_LEVEL_PERMANENT)
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
        snprintf(command, sizeof(command), 
                 "echo 'pass in from %s to any' | sudo pfctl -a cam_blocker -f - 2>&1", ip);
        system(command);
        break;

    case BLOCK_LEVEL_HARD:
        printf("🟢 Снимаем HARD блокировку: %s\n", ip);
        snprintf(command, sizeof(command), 
                 "echo 'pass in from %s to any' | sudo pfctl -a cam_blocker -f - 2>&1", ip);
        system(command);
        
        snprintf(command, sizeof(command),
                 "echo 'pass from any to any MAC %02X:%02X:%02X:%02X:%02X:%02X' | "
                 "sudo pfctl -a cam_blocker -f - 2>&1",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        system(command);
        break;

    case BLOCK_LEVEL_PERMANENT:
        printf("🔴 PERMANENT блокировка %s остается активной\n", ip);
        break;
    }
}

// ===== PACKET ANALYSIS =====

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

void extract_attacker_mac(const unsigned char *packet, uint8_t *mac_buffer)
{
    struct ethhdr *eth = (struct ethhdr *)packet;
    memcpy(mac_buffer, eth->h_source, 6);
}

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

// ===== NETWORK STATISTICS (macOS version) =====

int get_macos_net_stats(const char *interface, SecurityMetrics *metrics)
{
    // On macOS, we can use sysctl to get network statistics
    int mib[] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST, 0};
    size_t len = 0;
    
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
        return -1;
    }
    
    char *buf = malloc(len);
    if (!buf) return -1;
    
    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        free(buf);
        return -1;
    }
    
    // Parse the interface list to find our interface
    char *next = buf;
    struct if_msghdr *ifm = {0};
    smemset(&ifm, 0, sizeof(ifm));
    
    while (next < buf + len) {
        ifm = (struct if_msghdr *)next;
        
        if (ifm->ifm_type == RTM_IFINFO) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)(ifm + 1);
            char ifname[IFNAMSIZ];
            strncpy(ifname, sdl->sdl_data, sdl->sdl_nlen);
            ifname[sdl->sdl_nlen] = '\0';
            
            if (strcmp(ifname, interface) == 0) {
                metrics->aFramesReceivedOK = ifm->ifm_data.ifi_ipackets;
                metrics->aFramesTransmittedOK = ifm->ifm_data.ifi_opackets;
                metrics->aOctetsReceivedOK = ifm->ifm_data.ifi_ibytes;
                metrics->aOctetsTransmittedOK = ifm->ifm_data.ifi_obytes;
                metrics->aFrameCheckSequenceErrors = ifm->ifm_data.ifi_ierrors;
                
                free(buf);
                return 0;
            }
        }
        next += ifm->ifm_msglen;
    }
    
    free(buf);
    return -1;
}

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
            // warning
            if ((tcph->th_flags & TH_SYN) && !(tcph->th_flags & TH_ACK))
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
            if (blocked->block_level == BLOCK_LEVEL_HARD)
                level_str = "HARD";
            else if (blocked->block_level == BLOCK_LEVEL_PERMANENT)
                level_str = "PERMANENT";

            if (blocked->block_level == BLOCK_LEVEL_PERMANENT)
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

// Helper constants for monitoring
static const int BASELINE_COLLECTION_SEC = 30;
static const int MONITORING_CYCLE_SEC = 10;

// ===== MAIN MONITORING FUNCTION =====

void start_comprehensive_monitoring(const char *interface, cam_table_manager_t *cam_manager)
{
    anomaly_detector_t detector;
    init_detector(&detector, cam_manager);

    printf("→ STARTING SECURITY SYSTEM WITH CAM TABLE\n");
    printf("→ Interface: %s\n", interface);
    printf("→ Clearing old rules...\n");
    system("sudo pfctl -a cam_blocker -F all 2>/dev/null");

    // Create BPF socket for packet capture on macOS
    int bpf_fd = create_bpf_socket(interface);
    if (bpf_fd < 0) {
        printf("✗ Failed to create BPF socket\n");
        return;
    }

    // Configure BPF to capture all packets
    unsigned int enable = 1;
    if (ioctl(bpf_fd, BIOCPROMISC, &enable) < 0) {
        perror("BIOCPROMISC failed");
        close(bpf_fd);
        return;
    }

    // Set immediate mode for real-time packet capture
    if (ioctl(bpf_fd, BIOCIMMEDIATE, &enable) < 0) {
        perror("BIOCIMMEDIATE failed");
        close(bpf_fd);
        return;
    }

    // Note: Redis initialization would go here if needed
    // if (!redis_manager_init()) {
    //     printf("⚠️  Redis not available, continuing without device hash lookup\n");
    // }

    // Baseline statistics collection
    time_t start_time = time(NULL);
    unsigned char buffer[65536];
    while (!stop_monitoring && (time(NULL) - start_time) < BASELINE_COLLECTION_SEC)
    {
        get_macos_net_stats(interface, &detector.current);
        
        // Read packets from BPF
        ssize_t packet_size = read(bpf_fd, buffer, sizeof(buffer));
        if (packet_size > 0) {
            analyze_packet(buffer, (int)packet_size, &detector.current);
        }
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
        smemset(&detector.current, 0, sizeof(SecurityMetrics));
        detector.current.last_calc_time = time(NULL);

        time_t cycle_start = time(NULL);
        int packets_this_cycle = 0;
        while (!stop_monitoring && (time(NULL) - cycle_start) < MONITORING_CYCLE_SEC)
        {
            get_macos_net_stats(interface, &detector.current);
            
            ssize_t packet_size = read(bpf_fd, buffer, sizeof(buffer));
            if (packet_size > 0)
            {
                analyze_packet(buffer, (int)packet_size, &detector.current);
                packets_this_cycle++;
            }
            usleep(1000);
        }

        detector.current.packets_per_second = packets_this_cycle / MONITORING_CYCLE_SEC;
        int score = detect_anomalies(&detector);
        print_blocked_ips(&detector);

        if (score < 30)
            calculate_baseline(&detector);
        printf("\n--- Cycle %d completed ---\n", cycles);
    }

    close(bpf_fd);
    pthread_mutex_destroy(&detector.block_mutex);
    pthread_mutex_destroy(&detector.map_mutex);
    
    // Note: Redis cleanup would go here if needed
    // redis_manager_cleanup();

    printf("\n→ SECURITY SUMMARY:\n");
    printf("Total cycles: %d\n", cycles);
    printf("Attacks detected: %d\n", detector.total_anomalies);
    printf("Blocked IPs: %d\n", detector.blocked_count);
    printf("IP-MAC entries: %d\n", detector.ip_mac_count);
}

// ===== MAIN FUNCTION =====

int main(int argc, char *argv[])
{
    printf("=== NETWORK ATTACK BLOCKING SYSTEM WITH CAM TABLE ===\n\n");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGUSR1, handle_usr1);

    const char *interface = "en0";  // Default to en0 on macOS
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
    if (cam_table_init(&cam_manager, 1) != 0)  // 1 = UFT_MODE_L2_BRIDGING
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

    printf("\n=== FINAL CAM TABLE STATE ===\n");
    print_cam_table();

    cam_table_cleanup(&cam_manager);

    return 0;
}