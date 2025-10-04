#pragma once
#ifndef DTE_TYPES_H
#define DTE_TYPES_H

#include <stdint.h>

// Common types for Layer Management procedures

// Large counter type (see footnote 36)
// Using uint32_t as a reasonable default for large counters
typedef uint32_t CounterLarge;

// Alternative implementation if you need specific range:
// typedef enum {
//     COUNTER_LARGE_MIN = 0,
//     COUNTER_LARGE_MAX = 4294967295  // 2^32 - 1
// } CounterLarge;

// Other common types
typedef uint16_t CounterSmall;
typedef uint8_t Boolean;
typedef int32_t TimeInterval;

#endif // DTE_TYPES_H