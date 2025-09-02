#pragma once
#ifndef LLC_MODES_H
#define LLC_MODES_H

#include <stdint>

typedef struct llc_connection llc_connection_t; 

typedef struct {
  llc_connection_t *active_connection;
} llc_abm_data_t;

typedef struct {
  uint8_t dm_response_count;
  int is_listening_for_setup;
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

void llc_switch_to_abm_mode(llc_connection *conn);

#endif
