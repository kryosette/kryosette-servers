#pragma once
#ifndef DTE_CONSTANTS_H
#define DTE_CONSTANTS_H

// Common constants for Layer Management procedures

// Maximum defer time calculation:
// For operating speeds <= 100 Mb/s: 2 × (maxBasicFrameSize × 8)
// For operating speeds > 100 Mb/s: 2 × (burstLimit + maxBasicFrameSize × 8 + headerSize)
// Unit: bits (error timer limit for maxDeferTime)
#define MAX_DEFER_TIME 16000 // Example value - adjust based on your specific requirements

// Other common constants
#define MAX_BASIC_FRAME_SIZE 1518 // Standard Ethernet frame size
#define HEADER_SIZE 22            // Typical header size
#define BURST_LIMIT 65536         // Example burst limit

// Speed thresholds
#define SPEED_100MBPS 100000000 // 100 Mb/s in bits per second
#define SPEED_1GBPS 1000000000  // 1 Gb/s in bits per second

#endif // DTE_CONSTANTS_H