#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

// Структура для заблокированных IP
typedef struct
{
    char ip[16];
    time_t block_time;
    int block_duration;
    char reason[100];
} blocked_ip_t;

// Структура для метрик безопасности
typedef struct
{
    // BASIC TRAFFIC
    unsigned long aFramesTransmittedOK;
    unsigned long aFramesReceivedOK;
    unsigned long aOctetsTransmittedOK;
    unsigned long aOctetsReceivedOK;

    // ERROR METRICS
    unsigned long aFrameCheckSequenceErrors;
    unsigned long aAlignmentErrors;

    // BROADCAST/MULTICAST
    unsigned long aBroadcastFramesReceivedOK;
    unsigned long aMulticastFramesReceivedOK;
    unsigned long aBroadcastFramesXmittedOK;
    unsigned long aMulticastFramesXmittedOK;

    // SECURITY FLAGS
    int estimated_promiscuous;
    int potential_scan_detected;

    // ДОПОЛНИТЕЛЬНЫЕ МЕТРИКИ
    unsigned long syn_packets;
    unsigned long udp_packets;
    unsigned long icmp_packets;
    unsigned long total_packets;
    unsigned long packets_per_second;
    time_t last_calc_time;
    unsigned long last_packet_count;

    // ДЕТЕКТОР АТАК
    char attacker_ip[16];
    int attack_detected;
    char attack_type[50];
} SecurityMetrics;

typedef struct
{
    SecurityMetrics baseline;
    SecurityMetrics current;
    SecurityMetrics previous;
    int anomaly_score;
    int total_anomalies;

    // СИСТЕМА БЛОКИРОВКИ
    blocked_ip_t blocked_ips[100];
    int blocked_count;
    pthread_mutex_t block_mutex;
} anomaly_detector_t;

volatile sig_atomic_t stop_monitoring = 0;

void handle_signal(int sig)
{
    stop_monitoring = 1;
    printf("\n🛑 Остановка мониторинга...\n");
}

void init_detector(anomaly_detector_t *detector)
{
    memset(detector, 0, sizeof(anomaly_detector_t));
    detector->current.last_calc_time = time(NULL);
    pthread_mutex_init(&detector->block_mutex, NULL);
}

// БЛОКИРОВКА IP через iptables
void block_ip(const char *ip, const char *reason, int duration)
{
    char command[256];

    printf("🔒 БЛОКИРУЕМ IP: %s | Причина: %s | На %d сек\n", ip, reason, duration);

    // Блокировка через iptables
    snprintf(command, sizeof(command),
             "iptables -A INPUT -s %s -j DROP 2>/dev/null", ip);
    system(command);

    // Логируем блокировку
    snprintf(command, sizeof(command),
             "echo \"$(date): BLOCKED %s - %s\" >> /var/log/ddos_block.log", ip, reason);
    system(command);
}

// РАЗБЛОКИРОВКА IP
void unblock_ip(const char *ip)
{
    char command[256];

    printf("🔓 РАЗБЛОКИРУЕМ IP: %s\n", ip);

    snprintf(command, sizeof(command),
             "iptables -D INPUT -s %s -j DROP 2>/dev/null", ip);
    system(command);
}

// ДОБАВЛЕНИЕ IP В СПИСОК БЛОКИРОВКИ
void add_to_block_list(anomaly_detector_t *detector, const char *ip, const char *reason)
{
    pthread_mutex_lock(&detector->block_mutex);

    // Проверяем, не заблокирован ли уже
    for (int i = 0; i < detector->blocked_count; i++)
    {
        if (strcmp(detector->blocked_ips[i].ip, ip) == 0)
        {
            pthread_mutex_unlock(&detector->block_mutex);
            return;
        }
    }

    // Добавляем в список
    if (detector->blocked_count < 100)
    {
        strncpy(detector->blocked_ips[detector->blocked_count].ip, ip, 15);
        detector->blocked_ips[detector->blocked_count].block_time = time(NULL);
        detector->blocked_ips[detector->blocked_count].block_duration = 300; // 5 минут
        strncpy(detector->blocked_ips[detector->blocked_count].reason, reason, 99);

        // Блокируем через iptables
        block_ip(ip, reason, 300);

        detector->blocked_count++;
        printf("✅ IP %s добавлен в черный список. Всего заблокировано: %d\n",
               ip, detector->blocked_count);
    }

    pthread_mutex_unlock(&detector->block_mutex);
}

// ПРОВЕРКА ИСТЕЧЕНИЯ ВРЕМЕНИ БЛОКИРОВКИ
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

            // Удаляем из списка
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

// ПОЛУЧЕНИЕ IP ИЗ ПАКЕТА
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

void analyze_packet(const unsigned char *packet, int length, SecurityMetrics *metrics)
{
    struct ethhdr *eth = (struct ethhdr *)packet;

    metrics->total_packets++;

    // Извлекаем IP атакующего
    extract_attacker_ip(packet, metrics->attacker_ip);

    // Анализ MAC адреса
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

void calculate_baseline(anomaly_detector_t *detector)
{
    if (detector->baseline.aFramesReceivedOK == 0)
    {
        detector->baseline = detector->current;
    }
    else
    {
        float alpha = 0.1f;

        detector->baseline.aFramesReceivedOK =
            (1 - alpha) * detector->baseline.aFramesReceivedOK +
            alpha * detector->current.aFramesReceivedOK;

        detector->baseline.aFramesTransmittedOK =
            (1 - alpha) * detector->baseline.aFramesTransmittedOK +
            alpha * detector->current.aFramesTransmittedOK;

        detector->baseline.packets_per_second =
            (1 - alpha) * detector->baseline.packets_per_second +
            alpha * detector->current.packets_per_second;

        detector->baseline.syn_packets =
            (1 - alpha) * detector->baseline.syn_packets +
            alpha * detector->current.syn_packets;
    }
}

int detect_anomalies(anomaly_detector_t *detector)
{
    int score = 0;

    printf("\n=== РАСШИРЕННЫЙ АНАЛИЗ БЕЗОПАСНОСТИ ===\n");

    printf("📊 ТРАФИК: %lu вх/%lu исх пакетов | %lu pps\n",
           detector->current.aFramesReceivedOK,
           detector->current.aFramesTransmittedOK,
           detector->current.packets_per_second);

    printf("🎯 ТИПЫ: SYN:%lu UDP:%lu ICMP:%lu\n",
           detector->current.syn_packets,
           detector->current.udp_packets,
           detector->current.icmp_packets);

    printf("🌐 BROADCAST: %lu | MULTICAST: %lu\n",
           detector->current.aBroadcastFramesReceivedOK,
           detector->current.aMulticastFramesReceivedOK);

    // SYN FLOOD DETECTION
    if (detector->baseline.syn_packets > 0)
    {
        float syn_ratio = (float)detector->current.syn_packets / detector->current.total_packets;
        float baseline_syn_ratio = (float)detector->baseline.syn_packets / detector->baseline.total_packets;

        if (syn_ratio > baseline_syn_ratio * 10)
        {
            printf("🚨 SYN FLOOD: %.1f%% SYN пакетов\n", syn_ratio * 100);
            score += 50;

            // АВТОМАТИЧЕСКАЯ БЛОКИРОВКА при критической атаке
            if (strcmp(detector->current.attacker_ip, "unknown") != 0 &&
                strcmp(detector->current.attacker_ip, "127.0.0.1") != 0)
            {
                add_to_block_list(detector, detector->current.attacker_ip, "SYN Flood Attack");
            }
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

            if (strcmp(detector->current.attacker_ip, "unknown") != 0 &&
                strcmp(detector->current.attacker_ip, "127.0.0.1") != 0)
            {
                add_to_block_list(detector, detector->current.attacker_ip, "DDoS Attack");
            }
        }
    }

    // PORT SCAN DETECTION
    if (detector->current.potential_scan_detected)
    {
        printf("🚨 СЕТЕВОЕ СКАНИРОВАНИЕ\n");
        score += 35;

        if (strcmp(detector->current.attacker_ip, "unknown") != 0 &&
            strcmp(detector->current.attacker_ip, "127.0.0.1") != 0)
        {
            add_to_block_list(detector, detector->current.attacker_ip, "Port Scanning");
        }
    }

    // UDP FLOOD DETECTION
    if (detector->current.udp_packets > 1000 && detector->current.packets_per_second > 100)
    {
        printf("🚨 UDP FLOOD: %lu UDP пакетов\n", detector->current.udp_packets);
        score += 45;

        if (strcmp(detector->current.attacker_ip, "unknown") != 0 &&
            strcmp(detector->current.attacker_ip, "127.0.0.1") != 0)
        {
            add_to_block_list(detector, detector->current.attacker_ip, "UDP Flood");
        }
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
            time_t remaining = detector->blocked_ips[i].block_duration -
                               (time(NULL) - detector->blocked_ips[i].block_time);
            printf("  %s - %s (осталось: %ld сек)\n",
                   detector->blocked_ips[i].ip,
                   detector->blocked_ips[i].reason,
                   remaining > 0 ? remaining : 0);
        }
    }

    pthread_mutex_unlock(&detector->block_mutex);
}

void start_comprehensive_monitoring(const char *interface)
{
    anomaly_detector_t detector;
    init_detector(&detector);

    printf("🎯 ЗАПУСК СИСТЕМЫ ЗАЩИТЫ С АВТОБЛОКИРОВКОЙ\n");
    printf("📡 Интерфейс: %s\n", interface);

    // Очищаем старые правила iptables при запуске
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

    // Сбор базовой статистики
    time_t start_time = time(NULL);
    unsigned char buffer[65536];

    while (!stop_monitoring && (time(NULL) - start_time) < 8)
    {
        get_proc_net_stats(interface, &detector.current);

        int packet_size = recv(raw_sock, buffer, sizeof(buffer), 0);
        if (packet_size > 0)
        {
            analyze_packet(buffer, packet_size, &detector.current);
        }
        usleep(1000);
    }

    calculate_baseline(&detector);

    printf("📊 БАЗОВЫЕ ПОКАЗАТЕЛИ УСТАНОВЛЕНЫ\n");
    printf("🎯 НАЧАЛО МОНИТОРИНГА С АВТОБЛОКИРОВКОЙ...\n\n");

    int cycles = 0;
    while (!stop_monitoring)
    {
        cycles++;

        // Проверяем истекшие блокировки
        check_block_expiry(&detector);

        // Сбрасываем счетчики
        detector.previous = detector.current;
        memset(&detector.current, 0, sizeof(SecurityMetrics));
        detector.current.last_calc_time = time(NULL);

        // Слушаем трафик 3 секунды
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

        // Детектируем и блокируем
        int score = detect_anomalies(&detector);

        // Показываем заблокированные IP
        print_blocked_ips(&detector);

        if (score < 30)
        {
            calculate_baseline(&detector);
        }

        printf("\n--- Цикл %d завершен ---\n", cycles);
    }

    close(raw_sock);
    pthread_mutex_destroy(&detector.block_mutex);

    printf("\n📈 ИТОГИ ЗАЩИТЫ:\n");
    printf("Всего циклов: %d\n", cycles);
    printf("Обнаружено атак: %d\n", detector.total_anomalies);
    printf("Заблокировано IP: %d\n", detector.blocked_count);
}

int main(int argc, char *argv[])
{
    printf("=== 🐧 СИСТЕМА АВТОМАТИЧЕСКОЙ БЛОКИРОВКИ АТАК ===\n\n");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

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

    printf("💡 Система автоматически блокирует атакующие IP:\n");
    printf("   - SYN Flood → Блокировка на 5 минут\n");
    printf("   - DDoS атаки → Мгновенная блокировка\n");
    printf("   - Port Scanning → Авто-бан\n");
    printf("   - UDP Flood → Блокировка источника\n\n");

    start_comprehensive_monitoring(interface);

    return 0;
}