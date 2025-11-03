/**
 * @file smemset.h
 * @brief Secure memset implementation that prevents compiler optimization
 */

/**
 * @brief Secure memset function that guarantees memory zeroing/initialization
 *
 * This function is designed to securely set memory regions while preventing
 * compiler optimizations that might remove "unnecessary" memset calls. It's
 * particularly useful for:
 * - Clearing sensitive data (passwords, keys, tokens)
 * - Memory initialization for security-critical operations
 * - Preventing dead store elimination optimizations
 *
 * Key features:
 * - Uses volatile pointers to prevent compiler optimization
 * - Implements memory barriers for proper memory ordering
 * - Optimized for different architectures (x86_64, AArch64, others)
 * - Handles unaligned memory addresses efficiently
 * - Uses word-sized operations for better performance on large buffers
 *
 * Memory barrier behavior:
 * - x86_64: Uses MFENCE instruction for full memory barrier
 * - AArch64: Uses DMB SY instruction for system-wide data memory barrier
 * - Other architectures: Uses compiler barrier only
 *
 * Optimization strategy:
 * 1. Handle small buffers (<8 bytes) with byte-wise operations
 * 2. Align to architecture word size (OPSIZ) for larger buffers
 * 3. Use 8x unrolled loops for maximum throughput on large buffers
 * 4. Fall back to appropriate chunk sizes for remaining data
 *
 * @param dstpp Pointer to the destination memory region to set
 * @param c Value to set (interpreted as unsigned char)
 * @param len Number of bytes to set
 *
 * @return Original dstpp pointer (same as standard memset)
 *
 * @note This function is slower than standard memset but provides security
 *       guarantees that the memory will actually be modified.
 * @warning Unlike standard memset, this function uses volatile stores which
 *          may have different performance characteristics.
 * @see memset() for standard memory setting function
 */
#include "/mnt/c/Users/dmako/kryosette/kryosette-servers/third-party/smemset/include/smemset.h"
#include <stdint.h>

typedef unsigned char byte;

#ifdef __x86_64__
typedef uint64_t op_t;
#define OPSIZ 8
#elif defined(__aarch64__)
typedef uint64_t op_t;
#define OPSIZ 8
#else
typedef uint32_t op_t;
#define OPSIZ 4
#endif

void *smemset(void *dstpp, int c, size_t len)
{
    if (dstpp == NULL || len == 0)
    {
        return dstpp;
    }

    uintptr_t dstp = (uintptr_t)dstpp;

#if defined(__x86_64__)
    __asm__ __volatile__("mfence" ::: "memory");
#elif defined(__aarch64__)
    __asm__ __volatile__("dmb sy" ::: "memory");
#else
    __asm__ __volatile__("" ::: "memory");
#endif

    if (len >= 8)
    {
        size_t xlen;
        op_t cccc;

        cccc = (unsigned char)c;
        cccc |= cccc << 8;
        cccc |= cccc << 16;
        if (OPSIZ > 4)
            cccc |= (cccc << 16) << 16;

        while (dstp % OPSIZ != 0 && len > 0)
        {
            *((volatile byte *)dstp) = c;
            dstp += 1;
            len -= 1;
        }

        __asm__ __volatile__("" ::: "memory");

        xlen = len / (OPSIZ * 8);
        while (xlen > 0)
        {
            for (int i = 0; i < 8; i++)
            {
                *((volatile op_t *)(dstp + i * OPSIZ)) = cccc;
            }
            dstp += 8 * OPSIZ;
            xlen -= 1;
        }
        len %= OPSIZ * 8;

        xlen = len / OPSIZ;
        while (xlen > 0)
        {
            *((volatile op_t *)dstp) = cccc;
            dstp += OPSIZ;
            xlen -= 1;
        }
        len %= OPSIZ;
    }

    while (len > 0)
    {
        *((volatile byte *)dstp) = c;
        dstp += 1;
        len -= 1;
    }

#if defined(__x86_64__)
    __asm__ __volatile__("mfence" ::: "memory");
#elif defined(__aarch64__)
    __asm__ __volatile__("dmb sy" ::: "memory");
#else
    __asm__ __volatile__("" ::: "memory");
#endif

    return dstpp;
}