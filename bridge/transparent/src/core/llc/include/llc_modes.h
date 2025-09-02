#pragma once
#ifndef LLC_MODES_H
#define LLC_MODES_H

#include <stdint>

typedef struct llc_connection llc_connection_t; 

typedef struct {
  llc_connection_t *active_connection;
  uint8_t dm_response_count;
  int is_listening_for_setup;
} llc_abm_data_t;



#endif
