#pragma once
#ifndef LLC_FSM_H
#define LLC_FSM_H

#include <stdint.h>
#include "llc_connection.h"

/**
 * @brief LLC Finite State Machine event types.
 *
 * Enumerates all possible events that can trigger state transitions
 * in the LLC (Logical Link Control) Finite State Machine.
 * Includes command events, response events, and timeout events.
 */
typedef enum
{
    LLC_EVENT_SABME_CMD,  /**< Set Asynchronous Balanced Mode Extended command */
    LLC_EVENT_DISC_CMD,   /**< Disconnect command */
    LLC_EVENT_UA_RSP,     /**< Unnumbered Acknowledgment response */
    LLC_EVENT_DM_RSP,     /**< Disconnected Mode response */
    LLC_EVENT_I_CMD,      /**< Information command */
    LLC_EVENT_RR_CMD,     /**< Receive Ready command */
    LLC_EVENT_RR_RSP,     /**< Receive Ready response */
    LLC_EVENT_RNR_CMD,    /**< Receive Not Ready command */
    LLC_EVENT_RNR_RSP,    /**< Receive Not Ready response */
    LLC_EVENT_REJ_CMD,    /**< Reject command */
    LLC_EVENT_REJ_RSP,    /**< Reject response */
    LLC_EVENT_FRMR_RSP,   /**< Frame Reject response */
    LLC_EVENT_TIMEOUT_T1, /**< Timer T1 timeout (acknowledgment timer) */
    LLC_EVENT_TIMEOUT_T2  /**< Timer T2 timeout (P-bit timer) */
} llc_event_type_t;

/**
 * @brief LLC FSM event structure.
 *
 * Contains all relevant information for an LLC state machine event,
 * including event type, addressing information, control parameters,
 * and optional information field data.
 */
typedef struct
{
    llc_event_type_t type; /**< Type of the LLC event */
    uint8_t dsap;          /**< Destination Service Access Point */
    uint8_t ssap;          /**< Source Service Access Point */
    uint8_t pf_bit;        /**< Poll/Final bit (1 = Poll, 0 = Final) */
    uint8_t nr;            /**< Receive sequence number */
    uint8_t ns;            /**< Send sequence number */
    const uint8_t *info;   /**< Pointer to information field data (optional) */
    uint16_t info_len;     /**< Length of information field in bytes */
} llc_event_t;

/**
 * @brief LLC state handler function pointer type.
 *
 * Defines the signature for LLC state handler functions that process
 * events and determine state transitions.
 *
 * @param conn Pointer to the LLC connection context
 * @param event Pointer to the LLC event to process
 * @return llc_state_t New state after processing the event
 */
typedef llc_state_t (*llc_state_handler_fn)(llc_connection_t *conn, const llc_event_t *event);

/**
 * @brief Registers LLC FSM state transition handlers.
 *
 * Initializes the Finite State Machine by registering all state
 * handler functions for each possible state. This function must be
 * called once during LLC layer initialization.
 *
 * @note Should be called during system initialization phase
 */
void llc_fsm_register_handlers(void);

/**
 * @brief Dispatches an event to the LLC Finite State Machine.
 *
 * Processes an LLC event through the FSM based on the current
 * connection state and returns the new state after processing.
 *
 * @param conn Pointer to the LLC connection context
 * @param event Pointer to the LLC event to process
 * @return llc_state_t New state of the connection after event processing
 *
 * @note This is the main entry point for LLC event processing
 * @note The connection state is updated based on the event handling
 */
llc_state_t llc_fsm_dispatch_event(llc_connection_t *conn, const llc_event_t *event);

#endif