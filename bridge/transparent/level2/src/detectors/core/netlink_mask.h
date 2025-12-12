#pragma once

#include <stdint.h>
#include <stdbool.h>

static const uint8_t _SOCK_CREATED    = (1 << 0);   // Сокет создан
static const uint8_t _SOCK_BOUND      = (1 << 1);   // Сокет привязан
static const uint8_t _SOCK_VALID      = (1 << 2);   // Сокет валиден
static const uint8_t _ERR_SOCKET      = (1 << 3);   // Ошибка создания сокета
static const uint8_t _ERR_BIND        = (1 << 4);   // Ошибка bind
static const uint8_t _ERR_SENDMSG     = (1 << 5);   // Ошибка sendmsg
static const uint8_t _ERR_EACCES      = (1 << 6);   // Ошибка доступа
static const uint8_t _ERR_EISCONN     = (1 << 7);   // Сокет уже подключен

static inline uint8_t get_sock_created_mask(void)    { return _SOCK_CREATED; }
static inline uint8_t get_sock_bound_mask(void)      { return _SOCK_BOUND; }
static inline uint8_t get_sock_valid_mask(void)      { return _SOCK_VALID; }
static inline uint8_t get_err_socket_mask(void)      { return _ERR_SOCKET; }
static inline uint8_t get_err_bind_mask(void)        { return _ERR_BIND; }
static inline uint8_t get_err_sendmsg_mask(void)     { return _ERR_SENDMSG; }
static inline uint8_t get_err_eacces_mask(void)      { return _ERR_EACCES; }
static inline uint8_t get_err_eisconn_mask(void)     { return _ERR_EISCONN; }

static inline uint8_t get_sock_ready_mask(void) {
    return _SOCK_CREATED | _SOCK_BOUND;
}

static inline uint8_t get_all_errors_mask(void) {
    return _ERR_SOCKET | _ERR_BIND | _ERR_SENDMSG | _ERR_EACCES | _ERR_EISCONN;
}

static inline uint8_t get_all_states_mask(void) {
    return _SOCK_CREATED | _SOCK_BOUND | _SOCK_VALID;
}

static const uint8_t _CHECK_NLHDR     = (1 << 0);   // Заголовок nlmsghdr
static const uint8_t _CHECK_IOV       = (1 << 1);   // Структура iovec
static const uint8_t _CHECK_MSG       = (1 << 2);   // Структура msghdr
static const uint8_t _CHECK_DATA      = (1 << 3);   // Данные для отправки
static const uint8_t _CHECK_SNL       = (1 << 4);   // Структура sockaddr_nl

static inline uint8_t get_check_nlhdr_mask(void)     { return _CHECK_NLHDR; }
static inline uint8_t get_check_iov_mask(void)       { return _CHECK_IOV; }
static inline uint8_t get_check_msg_mask(void)       { return _CHECK_MSG; }
static inline uint8_t get_check_data_mask(void)      { return _CHECK_DATA; }
static inline uint8_t get_check_snl_mask(void)       { return _CHECK_SNL; }

static inline uint8_t get_required_checks_mask(void) {
    return _CHECK_NLHDR | _CHECK_IOV | _CHECK_MSG | _CHECK_SNL;
}

uint8_t get_socket_state(void);

void set_socket_state_bit(uint8_t bit_mask);
void clear_socket_state_bit(uint8_t bit_mask);

bool is_socket_ready(void);
bool has_socket_errors(void);
bool is_socket_created(void);
bool is_socket_bound(void);

void reset_socket_errors(void);

int validate_netlink_params(int type, const char* data, size_t len);
