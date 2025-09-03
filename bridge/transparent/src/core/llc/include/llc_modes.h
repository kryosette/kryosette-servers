#pragma once
#ifndef LLC_MODES_H
#define LLC_MODES_H

#include <stdint.h>
#include "llc_fsm.h" // Предположим, что у тебя есть FSM для соединения

/**
 * @brief Асинхронный сбалансированный режим (Asynchronous Balanced Mode).
 *        Активный режим, в котором работает установленное соединение.
 */
typedef struct
{
    llc_connection_t *active_connection; // Указатель на структуру активного соединения, если оно есть.
    // Здесь могут быть глобальные счетчики, таймеры, буферы передачи,
    // относящиеся к работе в этом режиме.
    // Например:
    // uint32_t total_i_frames_sent; // Общее количество переданных I-фреймов
    // uint32_t total_i_frames_received; // Общее количество принятых I-фреймов
} llc_abm_mode_t;

/**
 * @brief Асинхронный режим разъединения (Asynchronous Disconnected Mode).
 *        Режим по умолчанию, когда узел не участвует в connection-oriented общении.
 */
typedef struct
{
    // В этом режиме нет активных соединений, но узел может иметь
    // конфигурацию и статистику, относящуюся к этому состоянию.
    // Например:
    uint8_t dm_response_count; // Счетчик, сколько раз мы отправили DM в ответ на SABME
    // Флаг, разрешающий отвечать на SABME (или всегда игнорировать)
    int is_listening_for_setup;
} llc_adm_mode_t;

/**
 * @brief Глобальный контекст LLC станции.
 *        Определяет, в каком из двух фундаментальных режимов находится узел.
 */
typedef struct
{
    llc_abm_mode_t abm; // Данные для ABM-режима
    llc_adm_mode_t adm; // Данные для ADM-режима
    // Текущий режим работы узла. Это критически важный флаг.
    // Он определяет, какую логику применять к входящим кадрам.
    enum
    {
        LLC_GLOBAL_MODE_ADM, // Узел находится в режиме разъединения
        LLC_GLOBAL_MODE_ABM  // Узел находится в сбалансированном режиме (есть активное соединение)
    } current_global_mode;
} llc_station_global_state_t;

#endif // LLC_MODES_H