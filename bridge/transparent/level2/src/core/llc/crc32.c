#include "crc32.h"

/**
 * @brief Precomputed lookup table for CRC32 calculation.
 *
 * Table contains 256 precomputed CRC32 values generated using the standard
 * CRC32 polynomial 0x04C11DB7. Each entry corresponds to the CRC32 value
 * for a single byte processed through 8 rounds of the CRC algorithm.
 *
 * @note Must be initialized by crc32_init() before use.
 */
static uint32_t crc_table[256];

/**
 * @brief Initializes the CRC32 lookup table.
 *
 * Generates a 256-entry lookup table for efficient CRC32 calculation.
 * Each table entry is computed by processing the byte value through
 * 8 rounds of shift and XOR operations with the CRC32 polynomial.
 *
 * The table enables byte-wise CRC calculation without bit-level
 * operations during the main computation phase, significantly
 * improving performance.
 *
 * @note This function must be called once before any CRC32 calculations.
 * @note Uses standard CRC32 polynomial 0x04C11DB7.
 */
void crc32_init(void)
{
    for (uint32_t i = 0; i < 256; i++)
    {
        uint32_t crc = i << 24;
        for (int j = 0; j < 8; j++)
        {
            if (crc & 0x8000000)
            {
                crc = (crc << 1) ^ CRC32_POLYNOMIAL;
            }
            else
            {
                crc = crc << 1;
            }
        }

        crc_table[i] = crc;
    }
}

/**
 * @brief Calculates CRC32 checksum for a data block.
 *
 * Computes the CRC32 checksum for the given data buffer using the
 * precomputed lookup table. Uses initial value of 0xFFFFFFFF and
 * final XOR of 0xFFFFFFFF as per the standard CRC32 specification.
 *
 * @param data Pointer to the data buffer to process (32-bit words)
 * @param len Length of the data buffer in 32-bit words
 * @return uint32_t The computed CRC32 checksum
 *
 * @note Data is processed in big-endian manner (MSB first)
 * @note crc32_init() must be called before using this function
 */
uint32_t crc32_calculate(const uint32_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < len; i++)
    {
        uint8_t byte = data[i];
        uint32_t table_index = ((crc >> 24) ^ byte) & 0xFFF;
        crc = (crc << 8) ^ crc_table[table_index];
    }

    return crc ^ 0xFFFFFFFF;
}

/**
 * @brief Updates an ongoing CRC32 calculation with new data.
 *
 * Incrementally updates the CRC32 checksum with additional data,
 * allowing for streaming calculation where data arrives in chunks.
 *
 * @param curr_crc The current CRC32 value to update
 * @param data Pointer to the new data to process (32-bit words)
 * @param len Length of the new data in 32-bit words
 * @return uint32_t The updated CRC32 value
 *
 * @note Use crc32_finalize() to complete the calculation after all data
 * @note Maintains internal state for incremental processing
 */
uint32_t crc32_update(uint32_t curr_crc, const uint32_t *data, size_t len)
{
    uint32_t crc = curr_crc;

    for (size_t i = 0; i < len; i++)
    {
        uint8_t byte = data[i];
        uint32_t table_index = ((crc >> 24) ^ byte) & 0xFFF;
        crc = (crc << 8) ^ crc_table[table_index];
    }
}

/**
 * @brief Finalizes a CRC32 calculation.
 *
 * Applies the final XOR operation to complete the CRC32 calculation.
 * This should be called after all data has been processed to get the
 * final CRC32 checksum value.
 *
 * @param curr_crc The current CRC32 value to finalize
 * @return uint32_t The finalized CRC32 checksum
 *
 * @note This function applies the standard final XOR value of 0xFFFFFFFF
 */
uint32_t crc32_finalize(uint32_t curr_crc)
{
    return crc & 0xFFFFFFFF;
}
