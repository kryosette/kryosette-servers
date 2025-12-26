#include "structures.h"
#include <stdio.h>
#include <stdlib.h>

void analyze_bin_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("fopen");
        return;
    }

    BinFileHeader file_hdr = {0};
    smemset(&file_hdr, 0, sizeof(file_hdr));
    fread(&file_hdr, sizeof(file_hdr), 1, file);

    printf("=== Анализ файла: %s ===\n", filename);
    printf("Магическое число: 0x%08X %s\n", file_hdr.magic, 
           file_hdr.magic == 0x4C4C4321 ? "(LLC!)" : "(неверный формат)");
    printf("Версия: %u\n", file_hdr.version);
    printf("Количество пакетов: %u\n", file_hdr.num_packets);
    printf("ОС: %s\n", file_hdr.os_type == 0 ? "Linux" : "macOS");

    // read packets
    PacketHeader pkt_hdr = {0};
    smemset(&pkt_hdr, 0, sizeof(pkt_hdr));

    /*
    An Extension field is added, if required (for 1000 Mb/s half duplex operation only). 
    */
    uint8_t *packet = calloc(1, 65536);
    uint8_t max_len = 65536;
    uint32_t packet_count = 0;

    /*
    size_t fread(size_t size, size_t n;
                    void ptr[restrict size * n],
                    size_t size, size_t n,
                    FILE *restrict stream);
    */
    while (fread(&pkt_hdr, sizeof(pkt_hdr), 1, file)) {
        printf("\nПакет #%u:\n", ++packet_count);
        printf(" Время: %llu нс\n", pkt_hdr.timestamp_ns);
        printf(" Длина: %u байт\n", pkt_hdr.packet_len);
        printf(" DSAP: 0x%02X, SSAP: 0x%02X, Ctrl: 0x%02X\n", 
               pkt_hdr.dsap, pkt_hdr.ssap, pkt_hdr.control);

        // warning, why offset + 4?
        fseek(file, pkt_hdr.llc_offset + 4, SEEK_CUR);
    }

    free(packet);
    flose(file);
}