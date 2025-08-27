#pragma once
#ifndef MY_HEADER_H
#define MY_HEADER_H

#include "llc_types.h"
#include "llc_sap.h"
#include "llc_pdu.h"

// Инициализация LLC модуля
int llc_init(void);
void llc_deinit(void);

// Главная функция приёма! Вызывается из drivers/ports/ethernet.c
void llc_receive_frame(port_id_t port, const uint8_t *frame_data, size_t frame_len);

#endif