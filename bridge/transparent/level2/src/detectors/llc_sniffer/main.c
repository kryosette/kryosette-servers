#include "llc_parser.h"
#include <getopt.h>
#include "structures.h"

void print_usage(const char *prog_name) {
    printf("Использование: %s [опции]\n", prog_name);
    printf("Опции:\n");
    printf(" -i <интерфейс> Сетевой интерфейс (по умолчанию: eth0/ en0)\n");
    printf(" -o <файл> Выходной бинарный файл (по умолчанию: llc_capture.bin)\n");
    printf(" -f <dsap> Фильтр по DSAP (например: 0xAA)\n");
    printf(" -p Promiscuous mode\n");
    printf(" -v Подробный вывод\n");
    printf(" -c <число> Максимальное количество пакетов\n");
    printf(" -h Эта справка\n");
    printf("\nПримеры:\n");
    printf(" %s -i eth0 -o capture.bin -v\n", prog_name);
    printf(" %s -i en0 -f 0xAA -c 1000\n", prog_name);
}

int main(int argc, char *argv[]) {
    ParserConfig config;
    
    // Значения по умолчанию
    strcpy(config.interface, "eth0");
    #ifdef __APPLE__
        strcpy(config.interface, "en0");
    #endif
    strcpy(config.output_file, "llc_capture.bin");
    config.filter_dsap[0] = '\0';
    config.promisc_mode = 1;
    config.save_raw = 1;
    config.max_packets = 0;
    config.verbose = 0;
    config.pcap_format = 0;
    
    // Разбор аргументов командной строки
    int opt;
    while ((opt = getopt(argc, argv, "i:o:f:c:pvh")) != -1) {
        switch (opt) {
            case 'i':
                strncpy(config.interface, optarg, sizeof(config.interface) - 1);
                break;
            case 'o':
                strncpy(config.output_file, optarg, sizeof(config.output_file) - 1);
                break;
            case 'f':
                strncpy(config.filter_dsap, optarg, sizeof(config.filter_dsap) - 1);
                break;
            case 'p':
                config.promisc_mode = 1;
                break;
            case 'v':
                config.verbose = 1;
                break;
            case 'c':
                config.max_packets = atoi(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    printf("=== LLC Sniffer ===\n");
    printf("Интерфейс: %s\n", config.interface);
    printf("Выходной файл: %s\n", config.output_file);
    if (config.filter_dsap[0]) {
        printf("Фильтр DSAP: %s\n", config.filter_dsap);
    }
    printf("Promiscuous mode: %s\n", config.promisc_mode ? "ВКЛ" : "ВЫКЛ");
    printf("Макс. пакетов: %s\n", config.max_packets ? config.max_packets : "бесконечно");
    printf("===================\n\n");
    
    // Инициализация
    if (init_llc_sniffer(&config) < 0) {
        fprintf(stderr, "Ошибка инициализации!\n");
        return 1;
    }
    
    // Запуск захвата
    start_sniffing(&config);
    
    // Очистка
    cleanup_sniffer();
    
    // Конвертируем в pcap если нужно
    if (config.pcap_format) {
        char pcap_file[256];
        snprintf(pcap_file, sizeof(pcap_file), "%s.pcap", config.output_file);
        convert_to_pcap(config.output_file, pcap_file);
        printf("[*] Конвертировано в pcap: %s\n", pcap_file);
    }
    
    return 0;
}