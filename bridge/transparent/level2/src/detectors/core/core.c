#define _POSIX_C_SOURCE 200112L
#define GNU_SOURCE

#include "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/transparent/level2/src/detectors/core/include/core.h"
#include "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/config/redis/socket/constants.h"
#include "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/config/redis/socket/redis_manager.h"
#include <linux/netlink.h>
#include <unistd.h>
#include <stdint.h>

// ===== GLOBAL VARIABLES =====
volatile sig_atomic_t stop_monitoring = 0;

struct nlattr {
    uint16_t nla_len;
    uint16_t nla_type;
};

static int send_netlink_socket(int type, const char *data, size_t len) {
    static int n_sock = -1;
    /*
    struct sockaddr_nl {
               sa_family_t     nl_family;  /* AF_NETLINK 
               unsigned short  nl_pad;     /* Zero  
               pid_t           nl_pid;     /* Port ID 
               __u32           nl_groups;  /* Multicast groups mask 
           };
    */
    struct sockaddr_nl snl = {0};
    struct nlmsghdr *nlh = {0};
    struct iovec iov = {0};
    struct msghdr msg = {0};
    char buf[4092] = {0};

    /*
    (via the ENOBUFS error returned by recvmsg(2))
    */
    if (errno == ENOBUFS) {
        printf("buffer overflow");
        return -1;
    }

    uint8_t check_mask = 0; 

    if (validate_netlink_params(type, data, len) != 0) {
        return -1;
    }

    if (n_sock < 0) {
        n_sock = socket(AF_NETLINK, SOCK_STREAM, NETLINK_NETFILTER);
        if (n_sock < 0) {
            set_socket_state_bit(get_err_socket_mask());
            printf("sock err");
            return -1;
        } else if (errno == EACCES) {
            prinf("acces error");
            return -1
        }

        set_socket_state_bit(get_sock_created_mask());

        memset(&snl, 0, sizeof(snl));
        sa.nl_family = AF_NETLINK;
        sa.nl_pad = 0;
        /*
        nl_pid is the unicast address of netlink socket.  It's always 0 if
       the destination is in the kernel.

       However, nl_pid identifies a netlink socket, not a
       process.
        */
        sa.pid = getpid();
        /*
        A sockaddr_nl can be either unicast (only sent
        to one peer) or sent to netlink multicast groups (nl_groups not
        equal 0).
        */
        sa.nl_groups = 0;

        set_check_bit(&check_mask, get_check_snl_mask());

        /*
        int bind(int sockfd, const struct sockaddr *addr,
                socklen_t addrlen);

        When bind(2) is called on the socket, the nl_groups field
       in the sockaddr_nl should be set to a bit mask of the groups which
       it wishes to listen to. 
        */
        if (bind(n_sock, (struct sockaddr*)&nls, sizeof(snl)) < 0) {
            if (errno == EACCES) {
                set_socket_state_bit(get_err_eacces_mask());
                perror("access error");
            } else {
                set_socket_state_bit(get_err_bind_mask());
                perror("bind error");
            }
            
            close(n_sock);
            n_sock = -1;
            clear_socket_state_bit(get_sock_created_mask());
            return -1;
        }
        
        set_socket_state_bit(get_sock_bound_mask());

        if (!is_socket_ready()) {
            printf("Сокет не готов к отправке\n");
            print_socket_state();
            return -1;
        }

        memset(buf, 0, sizeof(buf));
        /*
        struct nlmsghdr {
               __u32 nlmsg_len;    /* Size of message including header 
               __u16 nlmsg_type;   /* Type of message content 
               __u16 nlmsg_flags;  /* Additional flags  
               __u32 nlmsg_seq;    /* Sequence number
               __u32 nlmsg_pid;    /* Sender port ID  
           };

        For reliable
       transfer the sender can request an acknowledgement from the
       receiver by setting the NLM_F_ACK flag. 

       The
       kernel tries to send an NLMSG_ERROR message for every failed
       packet!!
        */
        nlh = (struct nlmsghdr*)buf;
        nlh->nlmsg_len = NLMSG_SPACE(len);
        nlh->nlmsg_type = type;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
        nlh->nlmsg_seq = time(NULL);
        nlh->nlmsg_pid = getpid();

        set_check_bit(&check_mask, get_check_nlhdr_mask());

        if (data && len > 0) {
            /*
            NLMSG_DATA()
              Return a pointer to the payload associated with the passed
              nlmsghdr.
            */
            // memcpy(NLMSG_DATA(hlh), data, len); // warning
            memcpy((void*)nlh, data, len);
            set_check_bit(&check_mask, get_check_data_mask());
        }

        /*
        Describes a region of memory, beginning at iov_base address and
       with the size of iov_len bytes.  System calls use arrays of this
       structure, where each element of the array represents a memory
       region, and the whole array represents a vector of memory regions.
       The maximum number of iovec structures in that array is limited by
       IOV_MAX (defined in <limits.h>, or accessible via the call
       sysconf(_SC_IOV_MAX)).
        */
        iov.iov_base = buf;
        iov.iov_len = len;

        set_check_bit(&check_mask, get_check_data_mask());

        memset(&msg, 0, sizeof(msg));
        msg.msg_name = &sa;
        msg.msg_namelen = sizeof(sa);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        set_check_bit(&check_mask, get_check_msg_mask());

        // warning
        /*
        ssize_t sendmsg(int socket, const struct msghdr *message, int flags);

        The sendmsg() function shall send a message through a connection-
       mode or connectionless-mode socket. If the socket is a
       connectionless-mode socket, the message shall be sent to the
       address specified by msghdr if no pre-specified peer address has
       been set. If a peer address has been pre-specified, either the
       message shall be sent to the address specified in msghdr
       (overriding the pre-specified peer address), or the function shall
       return -1 and set errno to [EISCONN].  If the socket is
       connection-mode, the destination address in msghdr shall be
       ignored.
        */
        // if (sendmsg(n_sock, &msg, 0) < 0) {
        //     perror("sendmsg error");
        //     errno = EISCONN;
        //     return -1;
        // }

        uint8_t required_checks = get_required_checks_mask();
    
        if ((check_mask & required_checks) != required_checks) {
            printf("Ошибка: не все структуры инициализированы\n");
            printf("  Ожидалось: 0x%02X\n", required_checks);
            printf("  Получено:  0x%02X\n", check_mask);
        
            uint8_t missing = required_checks & ~check_mask;
        
            if (missing & get_check_nlhdr_mask()) printf("    - nlmsghdr не инициализирован\n");
            if (missing & get_check_iov_mask())   printf("    - iovec не инициализирован\n");
            if (missing & get_check_msg_mask())   printf("    - msghdr не инициализирован\n");
            if (missing & get_check_snl_mask())   printf("    - sockaddr_nl не инициализирован\n");
        
            return -1;
        }

        /*
        If a peer address has been pre-specified, either the
       message shall be sent to the address specified in msghdr
       (overriding the pre-specified peer address), or the function shall
       return -1 and set errno to [EISCONN].
        */
        int send_result = sendmsg(n_sock, &msg, 0);
    
        if (send_result < 0) {
            if (errno == EISCONN) {
                set_socket_state_bit(get_err_eisconn_mask());
                printf("Сокет уже подключен\n");
            } else {
                set_socket_state_bit(get_err_sendmsg_mask());
                perror("sendmsg error");
            }
            return -1;
        }
    
        reset_socket_errors();
    
        set_socket_state_bit(get_sock_valid_mask());

        return 0;
    }

}

static void add_attr(struct nlmsghdr *nlh, int maxlen, int type, 
                     const void *data, int datalen) {
    struct nlattr* nla = {0};
    int pad = 0;

    /*
    NLMSG_ALIGN()
              Round the size of a netlink message up to align it
              properly.
    */
    pad = ((nlh->nlmsg_len + 3) & ~3) - nlh->nlmsg_len;
    if (pad > 0 && nlh->nlmsg_len + pad <= maxlen) {
        memset((void*)nlh + nlh->nlmsg_len, 0, pad);
        nlh->nlmsg_len += pad;
    }

    // warning NLA_HDRLEN 
    if (nlh->nlmsg_len + NLA_HDRLEN + datalen > maxlen) {
        fprintf(stderr, "Netlink message too long\n");
        return;
    }

    /*
        struct nlmsghdr {
               __u32 nlmsg_len;    /* Size of message including header 
               __u16 nlmsg_type;   /* Type of message content 
               __u16 nlmsg_flags;  /* Additional flags  
               __u32 nlmsg_seq;    /* Sequence number
               __u32 nlmsg_pid;    /* Sender port ID  
           };
        */
    nla = (struct nlattr*)((void*)nlh + nlh->nlmsg_len);
    nla->nlmsg_type;
    // warning NLA_HDRLEN
    nla->nlmsg_len = sizeof(nla->nlmsg_len) + datalen;

    /*
    void *memcpy(size_t n;
                    void dest[restrict n], const void src[restrict n],
                    size_t n);
    */
    if (data > 0 || data != NULL) {
        memcpy((void*)nlh + sizeof(datalen), data, datalen);
    }

    nlh->nlmsg_len += ((nlh->lnmsg_len + 3) & ~3);
}

static int block_ip_nftlink(const char *ip) {
    int sock, res = -1;

    sock = send_netlink_socket();

    if (sock < 0) return -1;

    if (nft_table_create(sock, "filter", "INPUT", ip)) {
        printf("already exist");
    }

    res = nft_add_rule(sock, "filter", "INPUT", NFTPROTO_IPV6, ip);

    close(sock);

    return 0;
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
    char primary_dir[256] = {0};
    char fallback_dir[256] = {0};

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