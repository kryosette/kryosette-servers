#pragma once
#ifndef LLC_TYPES_H
#define LLC_TYPES_H

#include <stdint.h>

/**
 * @brief LLC frame type identifiers.
 *
 * Defines the control field values for different LLC frame types
 * used in Logical Link Control protocol operations.
 */
#define LLC_I_FRAME 0x00   /**< Information frame - carries user data */
#define LLC_RR_FRAME 0x01  /**< Receive Ready - positive acknowledgment */
#define LLC_RNR_FRAME 0x05 /**< Receive Not Ready - temporary busy condition */
#define LLC_REJ_FRAME 0x09 /**< Reject - negative acknowledgment/retransmission request */
#define LLC_SABME 0x6F     /**< Set Async Balanced Mode Extended - connection setup command */
#define LLC_DISC 0x43      /**< Disconnect - connection termination command */
#define LLC_UA 0x63        /**< Unnumbered Acknowledgment - connection acknowledgment */
#define LLC_DM 0x0F        /**< Disconnected Mode - "not in connection" response */
#define LLC_FRMR 0x87      /**< Frame Reject - protocol error indication */

/**
 * @brief LLC connection state enumeration.
 *
 * Defines the possible states of an LLC connection during its lifecycle,
 * from establishment through data transfer to termination and error recovery.
 */
typedef enum
{
    LLC_STATE_DISCONNECTED, /**< Connection is disconnected - no active session */
    LLC_STATE_SETUP,        /**< Connection in setup phase - SABME sent, awaiting UA */
    LLC_STATE_READY,        /**< Connection established - ready for data exchange */
    LLC_STATE_BUSY,         /**< Connection established but temporarily busy (RNR received) */
    LLC_STATE_REJECT        /**< Protocol error occurred - requires recovery procedure */
} llc_state_t;

/**
 * @brief LLC connection context structure.
 *
 * Contains all state information and control variables for managing
 * a single LLC connection between two stations, including sequence
 * numbers, timers, and link parameters.
 */
typedef struct llc_connection
{
    uint8_t remote_mac[ETH_ALEN]; /**< MAC address of the remote station */
    llc_state_t state;            /**< Current state of the LLC connection */

    uint8_t v_s; /**< Send state variable - next sequence number to send */
    uint8_t v_r; /**< Receive state variable - next expected sequence number */
    uint8_t v_a; /**< Acknowledgment state variable - last acknowledged sequence number */

    int t1_timeout; /**< T1 timer value for acknowledgment timeout (milliseconds) */
    int poll_flag;  /**< Poll flag indicator (1 = Poll, 0 = Final) */

    struct llc_connection *next; /**< Pointer to next connection in linked list */
} llc_connection_t;

#endif