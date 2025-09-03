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
