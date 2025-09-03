#include "crc32.h"

static uint32_t crc_table[256];

void crc32_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i << 24;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000000) {
                crc = (crc << 1) ^ CRC32_POLYNOMIAL;
            } else {
                crc = crc << 1;
            }
        }

        crc_table[i] = crc;
    }
}

uint32_t crc32_calculate(const uint32_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < len; i++) {
        uint32_t table_index = ((crc >> 24) ^ byte) & 0xFFF;
        crc = (crc << 8) ^ crc_table[table_index];
            
    }
}
