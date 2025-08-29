/**
 * @file pdu.h
 * @brief LLC Protocol Data Unit (PDU) Structures and Utilities
 * @description Complete implementation of IEEE 802.2 LLC PDU format
 * @conforms IEEE Std 802.2-1985, Section 3-5
 * @version 1.0
 */

#pragma once
#ifndef PDU_H
#define PDU_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ========================================================================= */
/*                          IEEE 802.2 CONSTANTS                             */
/* ========================================================================= */

/**
 * @defgroup supervisory_masks Supervisory Format Bit Masks
 * @brief Bit masks for S-format PDU control field extraction
 * @conforms IEEE 802.2 Section 5.4.2.2
 * @{
 */
#define S_FORMAT_MASK 0x0003   /**< Mask for format identifier bits (bits 0-1) */
#define S_FORMAT_VALUE 0x0001  /**< Value '01' for supervisory format */
#define S_CODE_MASK 0x000C     /**< Mask for supervisory code bits (bits 2-3) */
#define S_RESERVED_MASK 0x00F0 /**< Mask for reserved bits (bits 4-7) - must be 0 */
#define S_PF_MASK 0x0100       /**< Mask for Poll/Final bit (bit 8) */
#define S_NR_MASK 0xFE00       /**< Mask for Receive Sequence Number N(R) (bits 9-15) */
/** @} */

/**
 * @defgroup supervisory_codes Supervisory Function Codes
 * @brief Command/response codes for supervisory format PDU
 * @conforms IEEE 802.2 Section 5.4.2.2.1-2.3
 */
typedef enum
{
    S_RR = 0,  /**< 00 - Receive Ready (RR) - Ready to receive I-frames */
    S_REJ = 1, /**< 01 - Reject (REJ) - Request retransmission starting from N(R) */
    S_RNR = 2  /**< 10 - Receive Not Ready (RNR) - Temporary busy condition */
} supervisory_code_t;

/* ========================================================================= */
/*                     IEEE 802.2 PDU STRUCTURES                            */
/* ========================================================================= */

/**
 * @defgroup address_structures Service Access Point Address Structures
 * @brief DSAP and SSAP address field formats
 * @conforms IEEE 802.2 Section 3.3.1.1
 */

#pragma pack(push, 1)

/**
 * @struct dsap_address_t
 * @brief Destination Service Access Point Address field
 * @description Contains 7-bit DSAP address and group/individual designation
 * @note Bit order: LSB first (bit 0 transmitted first)
 * @conforms IEEE 802.2 Figure 3-2a
 */
typedef struct
{
    uint8_t address : 7; /**< 7-bit DSAP address (bits 1-7) */
    bool is_group : 1;   /**< Address type designation (bit 0):
                          *   - 0 = Individual DSAP address
                          *   - 1 = Group DSAP address */
} dsap_address_t;

/**
 * @struct ssap_address_t
 * @brief Source Service Access Point Address field
 * @description Contains 7-bit SSAP address and command/response designation
 * @note Bit order: LSB first (bit 0 transmitted first)
 * @conforms IEEE 802.2 Figure 3-2a
 */
typedef struct
{
    uint8_t address : 7;  /**< 7-bit SSAP address (bits 1-7) */
    bool is_response : 1; /**< Command/Response indicator (bit 0):
                           *   - 0 = LLC PDU is a command
                           *   - 1 = LLC PDU is a response */
} ssap_address_t;

#pragma pack(pop)

/**
 * @union control_field_t
 * @brief LLC Control Field union
 * @description Represents the control field in various formats
 * @conforms IEEE 802.2 Section 3.3.2
 */
typedef union
{
    uint8_t as_byte;  /**< Access as 8-bit value (for U-format) */
    uint16_t as_word; /**< Access as 16-bit value (for I and S formats) */
} control_field_t;

/**
 * @struct info_field_t
 * @brief LLC Information Field structure
 * @description Contains optional information field data
 * @conforms IEEE 802.2 Section 3.3.3
 * @note The information field consists of any integral number of octets (including zero)
 */
typedef struct
{
    uint8_t *data; /**< Pointer to information field data */
    size_t length; /**< Length of information field in octets */
} info_field_t;

/**
 * @struct llc_pdu_t
 * @brief Complete LLC Protocol Data Unit structure
 * @description Full LLC PDU containing all mandatory and optional fields
 * @conforms IEEE 802.2 Section 3.2, Figure 3-1
 */
typedef struct
{
    dsap_address_t dsap;      /**< Destination Service Access Point address field (8 bits) */
    ssap_address_t ssap;      /**< Source Service Access Point address field (8 bits) */
    control_field_t control;  /**< Control field (8 or 16 bits) */
    info_field_t information; /**< Information field (8*M bits, M ≥ 0) */
} llc_pdu_t;

/* ========================================================================= */
/*                  IEEE 802.2 PDU MANIPULATION FUNCTIONS                    */
/* ========================================================================= */

/**
 * @defgroup supervisory_functions Supervisory Format Functions
 * @brief Functions for working with supervisory format PDU
 * @conforms IEEE 802.2 Section 5.4.2.2
 */

/**
 * @brief Check if control field indicates supervisory format
 * @param control 16-bit control field value
 * @return true if format identifier bits equal '01' (supervisory format)
 * @conforms IEEE 802.2 Section 5.4.2.2
 */
static inline bool is_supervisory_format(uint16_t control)
{
    return (control & S_FORMAT_MASK) == S_FORMAT_VALUE;
}

/**
 * @brief Extract supervisory function code from control field
 * @param control 16-bit control field value
 * @return supervisory_code_t indicating the supervisory function
 * @retval S_RR Receive Ready
 * @retval S_REJ Reject
 * @retval S_RNR Receive Not Ready
 * @conforms IEEE 802.2 Section 5.4.2.2.1-2.3
 */
static inline supervisory_code_t get_supervisory_code(uint16_t control)
{
    return (supervisory_code_t)((control & S_CODE_MASK) >> 2);
}

/**
 * @brief Extract Poll/Final bit from control field
 * @param control 16-bit control field value
 * @return true if Poll/Final bit is set (1), false otherwise (0)
 * @conforms IEEE 802.2 Section 5.3.2.3
 */
static inline bool get_poll_final(uint16_t control)
{
    return (control & S_PF_MASK) != 0;
}

/**
 * @brief Extract receive sequence number N(R) from control field
 * @param control 16-bit control field value
 * @return Receive sequence number N(R) (0-127)
 * @conforms IEEE 802.2 Section 5.4.2.2
 */
static inline uint8_t get_receive_sequence(uint16_t control)
{
    return (uint8_t)((control & S_NR_MASK) >> 9);
}

/**
 * @brief Create supervisory format control field value
 * @param code Supervisory function code
 * @param poll_final Poll/Final bit value
 * @param nr Receive sequence number N(R) (0-127)
 * @return 16-bit control field value for supervisory format PDU
 * @conforms IEEE 802.2 Section 5.4.2.2
 */
static inline uint16_t create_supervisory(supervisory_code_t code,
                                          bool poll_final,
                                          uint8_t nr)
{
    return S_FORMAT_VALUE |               // Format identifier '01' (bits 0-1)
           ((uint16_t)code << 2) |        // Supervisory code (bits 2-3)
           (poll_final ? S_PF_MASK : 0) | // Poll/Final bit (bit 8)
           (((uint16_t)nr & 0x7F) << 9);  // Receive sequence number N(R) (bits 9-15)
}

#endif /* PDU_H */