#pragma once
#ifndef LLC_MODES_H
#define LLC_MODES_H

#include <stdint.h>

typedef struct llc_connection llc_connection_t;

/**
 * @brief Asynchronous Balanced Mode (ABM) operational data.
 *
 * Contains statistical counters and configuration parameters for
 * LLC stations operating in Asynchronous Balanced Mode (ABM).
 * ABM is the normal operational mode for peer-to-peer communication
 * where both stations can initiate commands and responses.
 */
typedef struct
{
  llc_connection_t *active_connection; /**< Pointer to the currently active connection */

  uint32_t total_i_frames_sent;     /**< Total number of Information frames sent */
  uint32_t total_i_frames_received; /**< Total number of Information frames received */
  uint32_t total_rr_sent;           /**< Total number of Receive Ready (RR) commands sent */
  uint32_t rej_sent_count;          /**< Total number of Reject (REJ) commands sent (retransmission requests) */
  uint32_t timeout_events;          /**< Total number of timeout events occurred */

  uint16_t max_information_field_size; /**< Maximum size of information field accepted (in bytes) */
  uint32_t t1_timeout_value_ms;        /**< Base timeout value for retransmission timer T1 (in milliseconds) */
} llc_abm_data_t;

/**
 * @brief Asynchronous Disconnected Mode (ADM) operational data.
 *
 * Contains statistical counters and configuration parameters for
 * LLC stations operating in Asynchronous Disconnected Mode (ADM).
 * ADM is used when no data link connection is established or when
 * in a disconnected state awaiting connection setup.
 */
typedef struct
{
  uint32_t sabme_received_count;   /**< Total number of SABME (Set ABM Extended) commands received */
  uint32_t dm_sent_count;          /**< Total number of Disconnected Mode (DM) responses sent */
  uint32_t ua_sent_count;          /**< Total number of Unnumbered Acknowledgment (UA) responses sent */
  uint8_t default_response_policy; /**< Default policy for responding to unanticipated commands */
} llc_adm_data_t;

/**
 * @brief Global LLC station operational mode state.
 *
 * Represents the overall operational mode of an LLC station,
 * which can be either Asynchronous Balanced Mode (ABM) for
 * connected peer-to-peer communication or Asynchronous
 * Disconnected Mode (ADM) for disconnected state.
 */
typedef struct
{
  /**
   * @brief Current operational mode of the LLC station.
   */
  enum
  {
    LLC_GLOBAL_MODE_ABM, /**< Asynchronous Balanced Mode - connected state */
    LLC_GLOBAL_MODE_ADM  /**< Asynchronous Disconnected Mode - disconnected state */
  } current_mode;

  /**
   * @brief Union containing mode-specific operational data.
   */
  union
  {
    llc_abm_data_t abm_data; /**< ABM-specific operational data and statistics */
    llc_adm_data_t adm_data; /**< ADM-specific operational data and statistics */
  } mode_data;
} llc_station_global_state_t;

/**
 * @brief Switches the LLC station to Asynchronous Balanced Mode.
 *
 * Transitions the station from ADM to ABM operational mode,
 * initializing ABM-specific parameters and establishing an
 * active connection context for peer-to-peer communication.
 *
 * @param state Pointer to the global station state structure
 * @param conn Pointer to the LLC connection to activate
 *
 * @note This function should be called after successful SABME/UA exchange
 * @note Initializes ABM counters and timers to default values
 */
void llc_switch_to_abm_mode(llc_station_global_state_t *state, llc_connection_t *conn);

/**
 * @brief Switches the LLC station to Asynchronous Disconnected Mode.
 *
 * Transitions the station from ABM to ADM operational mode,
 * cleaning up ABM resources and preparing for disconnected
 * operation or new connection establishment.
 *
 * @param state Pointer to the global station state structure
 *
 * @note This function should be called after DISC/UA exchange or connection failure
 * @note Preserves ADM statistics while resetting ABM-specific data
 */
void llc_switch_to_adm_mode(llc_station_global_state_t *state);

#endif