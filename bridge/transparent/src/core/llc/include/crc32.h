#pragma once
#ifndef CRC32_H
#define CRC32_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Standard CRC32 polynomial value.
 *
 * Represents the generator polynomial for CRC32 calculation:
 * x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1
 *
 * This polynomial is used in various protocols including Ethernet, ZIP, PNG, and others.
 */
#define CRC32_POLYNOMIAL 0x04C11DB7

/**
 * @brief Initializes the CRC32 lookup table.
 *
 * Precomputes a 256-entry lookup table for efficient CRC32 calculation.
 * This function must be called once before any CRC32 operations.
 *
 * @note Not thread-safe. Call during initialization phase.
 */
void crc32_init(void);

/**
 * @brief Calculates CRC32 checksum for a data block.
 *
 * Computes the complete CRC32 checksum for the given data buffer
 * using the precomputed lookup table for optimal performance.
 *
 * @param data Pointer to the data buffer to process
 * @param len Length of the data buffer in bytes
 * @return uint32_t The computed CRC32 checksum
 *
 * @note crc32_init() must be called before using this function
 * @note Uses standard initial value (0xFFFFFFFF) and final XOR (0xFFFFFFFF)
 */
uint32_t crc32_calculate(const uint8_t *data, size_t len);

/**
 * @brief Updates an ongoing CRC32 calculation with new data.
 *
 * Incrementally processes additional data into an existing CRC32 value,
 * enabling streaming calculation for large or chunked data.
 *
 * @param current_crc The current CRC32 value to update
 * @param data Pointer to the new data to process
 * @param len Length of the new data in bytes
 * @return uint32_t The updated CRC32 value
 *
 * @note Use crc32_finalize() to complete the calculation after all data
 */
uint32_t crc32_update(uint32_t current_crc, const uint8_t *data, size_t len);

/**
 * @brief Finalizes a CRC32 calculation.
 *
 * Applies the final XOR operation to complete the CRC32 calculation
 * and returns the standardized checksum value.
 *
 * @param current_crc The current CRC32 value to finalize
 * @return uint32_t The finalized CRC32 checksum
 *
 * @note Applies final XOR value of 0xFFFFFFFF per CRC32 standard
 */
uint32_t crc32_finalize(uint32_t current_crc);

#endif