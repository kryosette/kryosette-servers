#include "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/transparent/src/detectors/core/include/core.h"

// ===== GLOBAL VARIABLES =====
volatile sig_atomic_t stop_monitoring = 0;

// ===== CAM TABLE UTILITIES =====
static int create_cam_directory()
{
    struct stat st = {0};
    static const char *primary_path = "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/var/lib/cam-table";
    static const char *fallback_path = "/tmp/cam-table";

    if (stat(primary_path, &st) == 0)
    {
        if (S_ISDIR(st.st_mode))
            return 0;
        else
        {
            fprintf(stderr, "Error: %s exists but is not a directory\n", primary_path);
            return -1;
        }
    }

    if (mkdir(primary_path, 0700) == 0)
        return 0;

    if (errno != EACCES)
        fprintf(stderr, "mkdir(%s) failed: %s\n", primary_path, strerror(errno));

    if (stat(fallback_path, &st) == 0)
    {
        if (S_ISDIR(st.st_mode))
        {
            printf("Using existing fallback: %s\n", fallback_path);
            return 0;
        }
        else
        {
            fprintf(stderr, "Error: %s exists but is not a directory\n", fallback_path);
            return -1;
        }
    }

    if (mkdir(fallback_path, 0700) == 0)
    {
        printf("Created fallback directory: %s\n", fallback_path);
        return 0;
    }

    fprintf(stderr, "Failed to create both directories\n");
    return -1;
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

// ===== CAM TABLE READER =====
void print_cam_table()
{
    const char *filename = "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/var/lib/cam-table/cam.bin";

    printf("\n📖 ЧТЕНИЕ CAM ТАБЛИЦЫ: %s\n", filename);

    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        printf("❌ Не удалось открыть CAM файл для чтения\n");
        return;
    }

    cam_file_header_t header;
    if (fread(&header, sizeof(header), 1, file) != 1)
    {
        printf("❌ Ошибка чтения заголовка\n");
        fclose(file);
        return;
    }

    printf("=== CAM TABLE HEADER ===\n");
    printf("Магическое число: 0x%X\n", header.magic);
    printf("Версия: %d\n", header.version);
    printf("Всего записей: %d\n", header.total_entries);
    printf("Заблокировано: %d\n", header.blocked_count);
    printf("В ожидании: %d\n", header.pending_count);
    printf("Доверенных: %d\n", header.trusted_count);
    printf("Свободно: %d\n", header.free_count);
    printf("Создана: %s", ctime(&header.created_time));
    printf("Обновлена: %s", ctime(&header.last_updated));

    printf("\n=== ЗАБЛОКИРОВАННЫЕ MAC АДРЕСА ===\n");

    cam_file_entry_t entry;
    int blocked_found = 0;

    for (uint32_t i = 0; i < header.total_entries; i++)
    {
        if (fread(&entry, sizeof(entry), 1, file) != 1)
        {
            printf("❌ Ошибка чтения записи %d\n", i);
            break;
        }

        if (entry.status == ENTRY_BLOCKED)
        {
            blocked_found++;
            printf("\n🔒 Запись #%d:\n", i);
            printf("   MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   entry.mac[0], entry.mac[1], entry.mac[2],
                   entry.mac[3], entry.mac[4], entry.mac[5]);
            printf("   IP: %s\n", entry.ip_address);
            printf("   VLAN: %d\n", entry.vlan_id);
            printf("   Причина: %s\n", entry.reason);
            printf("   Время блокировки: %s", ctime(&entry.block_time));
            printf("   Длительность: %d сек\n", entry.block_duration);
            printf("   Последний раз видели: %s", ctime(&entry.last_seen));
        }
    }

    if (!blocked_found)
    {
        printf("❌ Заблокированных записей не найдено\n");
    }
    else
    {
        printf("\n✅ Найдено заблокированных записей: %d\n", blocked_found);
    }

    fclose(file);
}

// ===== CAM TABLE INIT & CLEANUP =====
int cam_table_init(cam_table_manager_t *manager, uft_mode_t default_mode)
{
    if (!manager)
        return -1;

    if (create_cam_directory() != 0)
    {
        printf("❌ Не удалось создать директорию для CAM таблицы\n");
        return -1;
    }

    const char *filename = "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/var/lib/cam-table/cam.bin";
    FILE *test_file = fopen(filename, "rb");
    if (!test_file)
    {
        printf("🆕 Создаю новую CAM таблицу: %s\n", filename);
        if (init_cam_file(filename, DEFAULT_CAPACITY) != 0)
        {
            printf("❌ Ошибка создания CAM файла\n");
            return -1;
        }
    }
    else
    {
        fclose(test_file);
        printf("📂 Загружаю существующую CAM таблицу\n");

        // Покажем что уже есть в таблице
        print_cam_table();
    }

    // Инициализация менеджера
    manager->current_mode = default_mode;
    manager->initialized = true;

    printf("✅ CAM таблица инициализирована: %s\n", filename);
    printf("   Режим: %d, Емкость: %d записей\n", default_mode, DEFAULT_CAPACITY);
    return 0;
}

int cam_table_cleanup(cam_table_manager_t *manager)
{
    if (!manager)
        return -1;

    // НЕ очищаем файл, только сбрасываем флаг
    manager->initialized = false;
    printf("✅ CAM менеджер остановлен (данные сохранены в файле)\n");
    return 0;
}

// ===== CHECK IF MAC IS BLOCKED =====
int is_mac_blocked(const uint8_t *mac_bytes)
{
    const char *filename = "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/var/lib/cam-table/cam.bin";
    FILE *file = fopen(filename, "rb");
    if (!file)
        return 0; // Если файла нет, значит MAC не заблокирован

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
            return 1; // MAC заблокирован
        }
    }

    fclose(file);
    return 0; // MAC не заблокирован
}

// ===== CAM TABLE FUNCTIONS =====
int cam_table_block_mac(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id, const char *reason)
{
    if (!manager || !manager->initialized)
        return -1;

    // Сначала проверим, не заблокирован ли уже этот MAC
    if (is_mac_blocked(mac_bytes))
    {
        printf("⚠️ MAC уже заблокирован в CAM таблице: %02X:%02X:%02X:%02X:%02X:%02X\n",
               mac_bytes[0], mac_bytes[1], mac_bytes[2],
               mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        return 0;
    }

    const char *filename = "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/var/lib/cam-table/cam.bin";
    FILE *file = fopen(filename, "r+b");
    if (!file)
    {
        printf("❌ Не удалось открыть CAM файл для блокировки\n");
        return -1;
    }

    cam_file_header_t header;
    fread(&header, sizeof(header), 1, file);

    cam_file_entry_t entry;
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
            entry.status = ENTRY_BLOCKED;
            entry.last_seen = time(NULL);
            strncpy(entry.reason, reason, sizeof(entry.reason) - 1);

            fseek(file, sizeof(header) + i * sizeof(entry), SEEK_SET);
            fwrite(&entry, sizeof(entry), 1, file);

            header.blocked_count++;
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
        printf("✅ MAC заблокирован в CAM таблице: %02X:%02X:%02X:%02X:%02X:%02X\n",
               mac_bytes[0], mac_bytes[1], mac_bytes[2],
               mac_bytes[3], mac_bytes[4], mac_bytes[5]);
    }

    fclose(file);
    return found ? 0 : -1;
}

int cam_table_unblock_mac(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id)
{
    if (!manager || !manager->initialized)
        return -1;

    const char *filename = "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/var/lib/cam-table/cam.bin";
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
        printf("✅ MAC разблокирован в CAM таблице: %02X:%02X:%02X:%02X:%02X:%02X\n",
               mac_bytes[0], mac_bytes[1], mac_bytes[2],
               mac_bytes[3], mac_bytes[4], mac_bytes[5]);
    }

    fclose(file);
    return found ? 0 : -1;
}

int cam_table_set_mac_pending(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id, const char *reason)
{
    if (!manager || !manager->initialized)
        return -1;

    const char *filename = "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/var/lib/cam-table/cam.bin";
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
void handle_signal(int sig)
{
    stop_monitoring = 1;
    printf("\n🛑 Остановка мониторинга...\n");
}

void handle_usr1(int sig)
{
    printf("\n📊 ПОКАЗАТЬ CAM ТАБЛИЦУ ПО ЗАПРОСУ\n");
    print_cam_table();
}

// ===== DETECTOR FUNCTIONS =====
void init_detector(anomaly_detector_t *detector, cam_table_manager_t *cam_manager)
{
    memset(detector, 0, sizeof(anomaly_detector_t));
    detector->current.last_calc_time = time(NULL);
    detector->cam_manager = cam_manager;
    pthread_mutex_init(&detector->block_mutex, NULL);
    pthread_mutex_init(&detector->map_mutex, NULL);
}

void block_ip(const char *ip, const uint8_t *mac, const char *reason, int duration)
{
    char command[256];

    printf("🔒 L2 БЛОКИРОВКА MAC: %02X:%02X:%02X:%02X:%02X:%02X | IP: %s | Причина: %s\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip, reason);

    // Сначала проверим, не заблокирован ли уже этот MAC
    if (is_mac_blocked(mac))
    {
        printf("⚠️ MAC уже заблокирован в CAM таблице, пропускаем запись\n");
    }
    else
    {
        const char *filename = "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/var/lib/cam-table/cam.bin";

        printf("🔄 Попытка записи в CAM таблицу: %s\n", filename);

        FILE *file = fopen(filename, "r+b");
        if (!file)
        {
            printf("❌ Не удалось открыть CAM файл, создаем новый...\n");

            char dir_cmd[512];
            snprintf(dir_cmd, sizeof(dir_cmd), "mkdir -p /mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/var/lib/cam-table/");
            system(dir_cmd);

            file = fopen(filename, "w+b");
            if (!file)
            {
                printf("❌ Ошибка создания CAM файла: %s\n", strerror(errno));
                return;
            }

            printf("🆕 Инициализируем новый CAM файл...\n");
            cam_file_header_t header = {
                .magic = CAM_MAGIC,
                .version = CAM_VERSION,
                .entry_size = sizeof(cam_file_entry_t),
                .total_entries = DEFAULT_CAPACITY,
                .trusted_count = 0,
                .pending_count = 0,
                .blocked_count = 0,
                .free_count = DEFAULT_CAPACITY,
                .created_time = time(NULL),
                .last_updated = time(NULL)};
            fwrite(&header, sizeof(header), 1, file);

            cam_file_entry_t empty_entry = {0};
            for (uint32_t i = 0; i < DEFAULT_CAPACITY; i++)
            {
                fwrite(&empty_entry, sizeof(empty_entry), 1, file);
            }
            fseek(file, 0, SEEK_SET);
            printf("✅ Новый CAM файл создан и инициализирован\n");
        }

        cam_file_header_t header;
        size_t read_result = fread(&header, sizeof(header), 1, file);
        printf("📖 Прочитано записей заголовка: %zu\n", read_result);

        if (read_result != 1)
        {
            printf("❌ Ошибка чтения заголовка CAM файла\n");
            fclose(file);
            return;
        }

        cam_file_entry_t entry;
        int found = 0;

        for (uint32_t i = 0; i < header.total_entries; i++)
        {
            if (fread(&entry, sizeof(entry), 1, file) != 1)
            {
                printf("❌ Ошибка чтения записи %u\n", i);
                break;
            }

            if (entry.status == ENTRY_FREE ||
                (memcmp(entry.mac, mac, 6) == 0 && entry.vlan_id == 1))
            {
                found = 1;
                printf("✅ Найдена запись для сохранения (индекс %u)\n", i);

                memcpy(entry.mac, mac, 6);
                entry.vlan_id = 1;
                entry.status = ENTRY_BLOCKED;
                entry.last_seen = time(NULL);
                strncpy(entry.reason, reason, sizeof(entry.reason) - 1);
                strncpy(entry.ip_address, ip, sizeof(entry.ip_address) - 1);
                entry.block_duration = duration;
                entry.block_time = time(NULL);

                fseek(file, sizeof(header) + i * sizeof(entry), SEEK_SET);
                size_t write_result = fwrite(&entry, sizeof(entry), 1, file);
                printf("📝 Записано записей: %zu\n", write_result);

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
            printf("✅ Блокировка сохранена в CAM таблицу!\n");
            printf("📊 Статистика: заблокировано %d MAC, свободно %d записей\n",
                   header.blocked_count, header.free_count);
        }
        else
        {
            printf("❌ Не найдено свободное место в CAM таблице! (всего записей: %u)\n",
                   header.total_entries);
        }

        fclose(file);
    }

    // Применяем блокировки в системе
    snprintf(command, sizeof(command),
             "ebtables -A INPUT -s %02X:%02X:%02X:%02X:%02X:%02X -j DROP 2>/dev/null",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    system(command);

    snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP 2>/dev/null", ip);
    system(command);

    FILE *log_file = fopen("ddos_block.log", "a");
    if (log_file)
    {
        time_t now = time(NULL);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

        fprintf(log_file, "%s: L2+L3 BLOCKED MAC:%02X:%02X:%02X:%02X:%02X:%02X IP:%s - %s\n",
                timestamp, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip, reason);
        fclose(log_file);
    }
}

void unblock_ip(const char *ip)
{
    char command[256];
    printf("🔓 РАЗБЛОКИРУЕМ IP: %s\n", ip);
    snprintf(command, sizeof(command), "iptables -D INPUT -s %s -j DROP 2>/dev/null", ip);
    system(command);
}

void add_to_block_list(anomaly_detector_t *detector, const char *ip, const uint8_t *mac, const char *reason)
{
    pthread_mutex_lock(&detector->block_mutex);

    for (int i = 0; i < detector->blocked_count; i++)
    {
        if (strcmp(detector->blocked_ips[i].ip, ip) == 0)
        {
            pthread_mutex_unlock(&detector->block_mutex);
            return;
        }
    }

    if (detector->blocked_count < 100)
    {
        strncpy(detector->blocked_ips[detector->blocked_count].ip, ip, 15);
        memcpy(detector->blocked_ips[detector->blocked_count].mac, mac, 6);
        detector->blocked_ips[detector->blocked_count].block_time = time(NULL);
        detector->blocked_ips[detector->blocked_count].block_duration = 300;
        strncpy(detector->blocked_ips[detector->blocked_count].reason, reason, 99);

        block_ip(ip, mac, reason, 300);

        if (detector->cam_manager && detector->cam_manager->initialized)
        {
            cam_table_block_mac(detector->cam_manager, mac, 1, reason);
        }

        detector->blocked_count++;
        printf("✅ IP %s добавлен в черный список. Всего заблокировано: %d\n", ip, detector->blocked_count);
    }

    pthread_mutex_unlock(&detector->block_mutex);
}

void check_block_expiry(anomaly_detector_t *detector)
{
    pthread_mutex_lock(&detector->block_mutex);
    time_t now = time(NULL);
    int i = 0;

    while (i < detector->blocked_count)
    {
        if (now - detector->blocked_ips[i].block_time > detector->blocked_ips[i].block_duration)
        {
            printf("⏰ Время блокировки IP %s истекло\n", detector->blocked_ips[i].ip);
            unblock_ip(detector->blocked_ips[i].ip);

            if (detector->cam_manager && detector->cam_manager->initialized)
            {
                cam_table_unblock_mac(detector->cam_manager, detector->blocked_ips[i].mac, 1);
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

    for (int i = 0; i < 6; i++)
    {
        mac_buffer[i] = rand() % 256;
    }
    mac_buffer[0] &= 0xFE;
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

// ===== NETWORK STATISTICS =====
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

int create_raw_socket()
{
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        perror("❌ Ошибка создания raw socket");
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

    printf("\n=== РАСШИРЕННЫЙ АНАЛИЗ БЕЗОПАСНОСТИ ===\n");
    printf("📊 ТРАФИК: %lu вх/%lu исх пакетов | %lu pps\n",
           detector->current.aFramesReceivedOK, detector->current.aFramesTransmittedOK, detector->current.packets_per_second);
    printf("🎯 ТИПЫ: SYN:%lu UDP:%lu ICMP:%lu\n", detector->current.syn_packets, detector->current.udp_packets, detector->current.icmp_packets);
    printf("🌐 BROADCAST: %lu | MULTICAST: %lu\n", detector->current.aBroadcastFramesReceivedOK, detector->current.aMulticastFramesReceivedOK);
    printf("🎯 АТАКУЮЩИЙ: IP:%s MAC:%02X:%02X:%02X:%02X:%02X:%02X\n", detector->current.attacker_ip,
           detector->current.attacker_mac[0], detector->current.attacker_mac[1], detector->current.attacker_mac[2],
           detector->current.attacker_mac[3], detector->current.attacker_mac[4], detector->current.attacker_mac[5]);

    // SYN FLOOD DETECTION
    if (detector->baseline.syn_packets > 0)
    {
        float syn_ratio = (float)detector->current.syn_packets / detector->current.total_packets;
        float baseline_syn_ratio = (float)detector->baseline.syn_packets / detector->baseline.total_packets;
        if (syn_ratio > baseline_syn_ratio * 10)
        {
            printf("🚨 SYN FLOOD: %.1f%% SYN пакетов\n", syn_ratio * 100);
            score += 50;
        }
    }

    // DDoS DETECTION
    if (detector->baseline.packets_per_second > 0)
    {
        float pps_ratio = (float)detector->current.packets_per_second / detector->baseline.packets_per_second;
        if (pps_ratio > 20)
        {
            printf("🚨 DDoS АТАКА: скорость x%.1f\n", pps_ratio);
            score += 40;
        }
    }

    // PORT SCAN DETECTION
    if (detector->current.potential_scan_detected)
    {
        printf("🚨 СЕТЕВОЕ СКАНИРОВАНИЕ\n");
        score += 35;
    }

    // UDP FLOOD DETECTION
    if (detector->current.udp_packets > 1000 && detector->current.packets_per_second > 100)
    {
        printf("🚨 UDP FLOOD: %lu UDP пакетов\n", detector->current.udp_packets);
        score += 45;
    }

    // PROMISCUOUS MODE DETECTION
    if (detector->current.estimated_promiscuous)
    {
        printf("🚨 PROMISCUOUS MODE\n");
        score += 30;
    }

    // ERROR DETECTION
    if (detector->current.aFrameCheckSequenceErrors > 100)
    {
        printf("🚨 КРИТИЧЕСКИЕ ОШИБКИ: %lu\n", detector->current.aFrameCheckSequenceErrors);
        score += 25;
    }

    if (score == 0)
    {
        printf("✅ Нет угроз безопасности\n");
    }
    else
    {
        detector->total_anomalies++;
        detector->anomaly_score = score;
        printf("\n📊 ОЦЕНКА УГРОЗ: %d/100\n", score);
        security_handle_attack_detection(detector, score);

        if (score >= 70)
        {
            printf("🔴 КРИТИЧЕСКАЯ УГРОЗА: Активная атака!\n");
        }
        else if (score >= 40)
        {
            printf("🟡 ВЫСОКИЙ РИСК\n");
        }
    }

    return score;
}

void print_blocked_ips(anomaly_detector_t *detector)
{
    pthread_mutex_lock(&detector->block_mutex);

    if (detector->blocked_count > 0)
    {
        printf("\n📋 ЗАБЛОКИРОВАННЫЕ IP (%d):\n", detector->blocked_count);
        for (int i = 0; i < detector->blocked_count; i++)
        {
            time_t remaining = detector->blocked_ips[i].block_duration - (time(NULL) - detector->blocked_ips[i].block_time);
            printf("  %s (MAC: %02X:%02X:%02X:%02X:%02X:%02X) - %s (осталось: %ld сек)\n",
                   detector->blocked_ips[i].ip, detector->blocked_ips[i].mac[0], detector->blocked_ips[i].mac[1],
                   detector->blocked_ips[i].mac[2], detector->blocked_ips[i].mac[3], detector->blocked_ips[i].mac[4],
                   detector->blocked_ips[i].mac[5], detector->blocked_ips[i].reason, remaining > 0 ? remaining : 0);
        }
    }

    pthread_mutex_unlock(&detector->block_mutex);
}

// ===== MAIN MONITORING FUNCTION =====
void start_comprehensive_monitoring(const char *interface, cam_table_manager_t *cam_manager)
{
    anomaly_detector_t detector;
    init_detector(&detector, cam_manager);

    printf("🎯 ЗАПУСК СИСТЕМЫ ЗАЩИТЫ С CAM ТАБЛИЦЕЙ\n");
    printf("📡 Интерфейс: %s\n", interface);
    printf("🧹 Очистка старых правил...\n");
    system("iptables -F 2>/dev/null");

    int raw_sock = create_raw_socket();
    if (raw_sock < 0)
        return;

    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (setsockopt(raw_sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
    {
        perror("❌ Ошибка привязки");
        close(raw_sock);
        return;
    }

    // Базовая статистика
    time_t start_time = time(NULL);
    unsigned char buffer[65536];
    while (!stop_monitoring && (time(NULL) - start_time) < 8)
    {
        get_proc_net_stats(interface, &detector.current);
        int packet_size = recv(raw_sock, buffer, sizeof(buffer), 0);
        if (packet_size > 0)
            analyze_packet(buffer, packet_size, &detector.current);
        usleep(1000);
    }

    calculate_baseline(&detector);
    printf("📊 БАЗОВЫЕ ПОКАЗАТЕЛИ УСТАНОВЛЕНЫ\n");
    printf("🎯 НАЧАЛО МОНИТОРИНГА С CAM ТАБЛИЦЕЙ...\n\n");

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
        while (!stop_monitoring && (time(NULL) - cycle_start) < 3)
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

        detector.current.packets_per_second = packets_this_cycle / 3;
        int score = detect_anomalies(&detector);
        print_blocked_ips(&detector);

        if (score < 30)
            calculate_baseline(&detector);
        printf("\n--- Цикл %d завершен ---\n", cycles);
    }

    close(raw_sock);
    pthread_mutex_destroy(&detector.block_mutex);
    pthread_mutex_destroy(&detector.map_mutex);

    printf("\n📈 ИТОГИ ЗАЩИТЫ:\n");
    printf("Всего циклов: %d\n", cycles);
    printf("Обнаружено атак: %d\n", detector.total_anomalies);
    printf("Заблокировано IP: %d\n", detector.blocked_count);
    printf("IP-MAC записей: %d\n", detector.ip_mac_count);
}

int main(int argc, char *argv[])
{
    printf("=== 🐧 СИСТЕМА АВТОМАТИЧЕСКОЙ БЛОКИРОВКИ АТАК С CAM ТАБЛИЦЕЙ ===\n\n");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGUSR1, handle_usr1); // Для показа CAM таблицы по запросу

    const char *interface = "lo";
    if (argc > 1)
    {
        interface = argv[1];
    }

    if (getuid() != 0)
    {
        printf("❌ Требуются права root для блокировки!\n");
        printf("💡 Запусти: sudo %s %s\n\n", argv[0], interface);
        return 1;
    }

    // ИНИЦИАЛИЗАЦИЯ CAM ТАБЛИЦЫ
    cam_table_manager_t cam_manager;
    printf("🔄 Инициализация CAM таблицы...\n");
    if (cam_table_init(&cam_manager, UFT_MODE_L2_BRIDGING) != 0)
    {
        printf("❌ Ошибка инициализации CAM таблицы!\n");
        return 1;
    }
    printf("✅ CAM таблица инициализирована\n");

    printf("💡 Система автоматически блокирует атакующие IP и MAC:\n");
    printf("   - SYN Flood → Блокировка IP + запись MAC в CAM таблицу\n");
    printf("   - DDoS атаки → Мгновенная блокировка IP/MAC\n");
    printf("   - Port Scanning → Авто-бан IP/MAC\n");
    printf("   - UDP Flood → Блокировка источника IP/MAC\n");
    printf("   - Для просмотра CAM таблицы во время работы: sudo kill -USR1 %d\n\n", getpid());

    start_comprehensive_monitoring(interface, &cam_manager);

    // ПОКАЗАТЬ СОДЕРЖИМОЕ CAM ТАБЛИЦЫ ПОСЛЕ МОНИТОРИНГА
    printf("\n=== ФИНАЛЬНОЕ СОСТОЯНИЕ CAM ТАБЛИЦЫ ===\n");
    print_cam_table();

    // ОСТАНОВКА CAM МЕНЕДЖЕРА (данные сохраняются в файле)
    cam_table_cleanup(&cam_manager);

    return 0;
}