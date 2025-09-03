#pragma once
#ifndef LLC_MODES_H
#define LLC_MODES_H

#include <stdint>

typedef struct llc_connection llc_connection_t; 

typedef struct {
    llc_connection_t *active_connection;

    uint32_t total_i_frames_sent;     // Сколько всего I-фреймов отправили
    uint32_t total_i_frames_received; // Сколько всего I-фреймов приняли
    uint32_t total_rr_sent;           // Сколько всего RR отправили
    uint32_t rej_sent_count;          // Сколько раз говорили "Повтори" (REJ)
    uint32_t timeout_events;          // Сколько раз срабатывал таймер

    uint16_t max_information_field_size; // Макс. размер данных, который готов принимать
    uint32_t t1_timeout_value_ms;        // Базовая величина таймаута для retransmission
} llc_abm_data_t;

typedef struct {
    uint32_t sabme_received_count;       
    uint32_t dm_sent_count;           
    uint32_t ua_sent_count;
    uint8_t default_response_policy;  
} llc_adm_data_t;

typedef struct {
  enum {
    LLC_GLOBAL_MODE_ABM,
    LLC_GLOBAL_MODE_ADM
  } current_mode;

  union {
    llc_abm_data_t abm_data;
    llc_adm_data_t abm_data;
  }
} llc_station_global_state_t;

void llc_switch_to_abm_mode(llc_station_global_state_t *state,llc_connection *conn);
void llc_switch_to_adm_mode(llc_station_global_state_t *state);

#endif
