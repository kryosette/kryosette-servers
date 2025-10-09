#include "core.h"

// ===== SIGNAL HANDLER =====
void handle_signal(int sig)
{
    stop_monitoring = 1;
    printf("\n🛑 Остановка мониторинга...\n");
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

// ===== CAM TABLE STUBS =====
int cam_table_block_mac(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id, const char *reason)
{
    return 0;
}

int cam_table_unblock_mac(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id)
{
    return 0;
}

int cam_table_set_mac_pending(cam_table_manager_t *manager, const uint8_t *mac_bytes, uint16_t vlan_id, const char *reason)
{
    return 0;
}

int cam_table_init(cam_table_manager_t *manager, uft_mode_t default_mode)
{
    if (!manager)
        return -1;

    if (create_cam_directory() != 0)
    {
        printf("❌ Не удалось создать директорию для CAM таблицы\n");
        return -1;
    }

    const char *filename = "/var/lib/cam-table/cam.bin";
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
    }

    manager->current_mode = default_mode;
    manager->cam_table = cam_table_create(DEFAULT_CAPACITY);
    manager->initialized = true;
    manager->magic_number = 0xDEADBEEF;

    printf("✅ CAM таблица инициализирована: %s\n", filename);
    printf("   Режим: %d, Емкость: %d записей\n", default_mode, DEFAULT_CAPACITY);
    return 0;
}

int cam_table_cleanup(cam_table_manager_t *manager)
{
    return 0;
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