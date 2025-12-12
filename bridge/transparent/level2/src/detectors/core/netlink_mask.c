#include "netlink_mask.h"
#include <stdio.h>
#include <string.h>

static uint8_t socket_state = 0;

uint8_t get_socket_state(void) {
    return socket_state;
}

void set_socket_state_bit(uint8_t bit_mask) {
    socket_state |= bit_mask;
}

void clear_socket_state_bit(uint8_t bit_mask) {
    socket_state &= ~bit_mask;
}

bool is_socket_ready(void) {
    uint8_t ready_mask = get_sock_ready_mask();
    return (socket_state & ready_mask) == ready_mask;
}

bool has_socket_errors(void) {
    uint8_t error_mask = get_all_errors_mask();
    return (socket_state & error_mask) != 0;
}

bool is_socket_created(void) {
    return (socket_state & get_sock_created_mask()) != 0;
}

bool is_socket_bound(void) {
    return (socket_state & get_sock_bound_mask()) != 0;
}

void reset_socket_errors(void) {
    uint8_t error_mask = get_all_errors_mask();
    socket_state &= ~error_mask;
}

void print_socket_state(void) {
    printf("Socket state (0x%02X):\n", socket_state);
    
    struct {
        const char* name;
        uint8_t mask;
    } flags[] = {
        {"SOCK_CREATED", get_sock_created_mask()},
        {"SOCK_BOUND", get_sock_bound_mask()},
        {"SOCK_VALID", get_sock_valid_mask()},
        {"ERR_SOCKET", get_err_socket_mask()},
        {"ERR_BIND", get_err_bind_mask()},
        {"ERR_SENDMSG", get_err_sendmsg_mask()},
        {"ERR_EACCES", get_err_eacces_mask()},
        {"ERR_EISCONN", get_err_eisconn_mask()}
    };
    
    for (size_t i = 0; i < sizeof(flags)/sizeof(flags[0]); i++) {
        if (socket_state & flags[i].mask) {
            printf("  [X] %s\n", flags[i].name);
        } else {
            printf("  [ ] %s\n", flags[i].name);
        }
    }
}

static const int MAX_DATA_SIZE = 4092;
static const int MIN_TYPE = 1;
static const int MAX_TYPE = 255;

int validate_netlink_params(int type, const char* data, size_t len) {
    static uint16_t validation_mask = 0;
    
    validation_mask = 0;
    
    if (type > 0) {
        validation_mask |= (1 << 0);
    }
    
    if (len <= MAX_DATA_SIZE) {
        validation_mask |= (1 << 1);
    }
    
    if (len == 0 || data != NULL) {
        validation_mask |= (1 << 2);
    }
    
    if (type >= MIN_TYPE && type <= MAX_TYPE) {
        validation_mask |= (1 << 3);
    }
    
    static const uint16_t full_valid_mask = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3);
    
    if (validation_mask != full_valid_mask) {
        uint16_t failed = full_valid_mask ^ validation_mask;
        
        if (failed & (1 << 0)) {
            printf("Ошибка: неверный тип сообщения (должен быть >0)\n");
        }
        if (failed & (1 << 1)) {
            printf("Ошибка: данные слишком большие (макс %d байт)\n", MAX_DATA_SIZE);
        }
        if (failed & (1 << 2)) {
            printf("Ошибка: data=NULL при len>0\n");
        }
        if (failed & (1 << 3)) {
            printf("Ошибка: тип вне диапазона [%d, %d]\n", MIN_TYPE, MAX_TYPE);
        }
        
        return -1;
    }
    
    return 0;
}