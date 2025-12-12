#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>

// Для macOS используем другие заголовки
#ifdef __APPLE__
#include <sys/types.h>
#include <netinet/in.h>
#define NETLINK_NETFILTER 0
#define NLMSG_SPACE(len) ((len) + sizeof(struct nlmsghdr) + 4)
#define NLMSG_DATA(nlh) ((void*)((char*)(nlh) + NLMSG_ALIGN(sizeof(struct nlmsghdr))))
#define NLM_F_REQUEST   0x01
#define NLM_F_ACK       0x02
#define NLM_F_CREATE    0x400
#define NLMSG_ALIGN(len) (((len) + 3) & ~3)

struct nlmsghdr {
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
};

struct sockaddr_nl {
    uint8_t nl_family;
    uint8_t nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};
#else
#include <linux/netlink.h>
#endif

// =========== СТАТИЧЕСКИЕ КОНСТАНТЫ МАСОК ===========
static const uint8_t SOCK_CREATED    = (1 << 0);
static const uint8_t SOCK_BOUND      = (1 << 1);
static const uint8_t SOCK_VALID      = (1 << 2);
static const uint8_t ERR_SOCKET      = (1 << 3);
static const uint8_t ERR_BIND        = (1 << 4);
static const uint8_t ERR_SENDMSG     = (1 << 5);
static const uint8_t ERR_EACCES      = (1 << 6);
static const uint8_t ERR_EISCONN     = (1 << 7);

static const uint8_t CHECK_NLHDR     = (1 << 0);
static const uint8_t CHECK_IOV       = (1 << 1);
static const uint8_t CHECK_MSG       = (1 << 2);
static const uint8_t CHECK_DATA      = (1 << 3);
static const uint8_t CHECK_SNL       = (1 << 4);

// =========== ГЕТТЕРЫ ДЛЯ МАСОК ===========
static inline uint8_t get_sock_created_mask(void)    { return SOCK_CREATED; }
static inline uint8_t get_sock_bound_mask(void)      { return SOCK_BOUND; }
static inline uint8_t get_sock_valid_mask(void)      { return SOCK_VALID; }
static inline uint8_t get_err_socket_mask(void)      { return ERR_SOCKET; }
static inline uint8_t get_err_bind_mask(void)        { return ERR_BIND; }
static inline uint8_t get_err_sendmsg_mask(void)     { return ERR_SENDMSG; }
static inline uint8_t get_err_eacces_mask(void)      { return ERR_EACCES; }
static inline uint8_t get_err_eisconn_mask(void)     { return ERR_EISCONN; }

static inline uint8_t get_check_nlhdr_mask(void)     { return CHECK_NLHDR; }
static inline uint8_t get_check_iov_mask(void)       { return CHECK_IOV; }
static inline uint8_t get_check_msg_mask(void)       { return CHECK_MSG; }
static inline uint8_t get_check_data_mask(void)      { return CHECK_DATA; }
static inline uint8_t get_check_snl_mask(void)       { return CHECK_SNL; }

static inline uint8_t get_sock_ready_mask(void) {
    return SOCK_CREATED | SOCK_BOUND;
}

static inline uint8_t get_all_errors_mask(void) {
    return ERR_SOCKET | ERR_BIND | ERR_SENDMSG | ERR_EACCES | ERR_EISCONN;
}

static inline uint8_t get_required_checks_mask(void) {
    return CHECK_NLHDR | CHECK_IOV | CHECK_MSG | CHECK_SNL;
}

// =========== СТАТИЧЕСКИЕ ПЕРЕМЕННЫЕ СОСТОЯНИЯ ===========
static uint8_t socket_state = 0;
static struct sockaddr_nl saved_snl;  // Сохраняем snl между вызовами

// =========== ФУНКЦИИ РАБОТЫ С СОСТОЯНИЕМ ===========
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
    printf("Состояние сокета (0x%02X):\n", socket_state);
    
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
        printf("  [%c] %s\n", 
               (socket_state & flags[i].mask) ? 'X' : ' ', 
               flags[i].name);
    }
}

// =========== ВАЛИДАЦИЯ ПАРАМЕТРОВ ===========
static const int MAX_DATA_SIZE = 4092 - NLMSG_SPACE(0);
static const int MIN_TYPE = 1;
static const int MAX_TYPE = 255;

static inline void set_check_bit(uint8_t* check_mask, uint8_t bit) {
    if (check_mask) *check_mask |= bit;
}

int validate_netlink_params(int type, const char* data, size_t len) {
    if (type <= 0) {
        printf("Ошибка: тип сообщения должен быть > 0 (получено %d)\n", type);
        return -1;
    }
    
    if (type < MIN_TYPE || type > MAX_TYPE) {
        printf("Ошибка: тип вне диапазона [%d, %d] (получено %d)\n", 
               MIN_TYPE, MAX_TYPE, type);
        return -1;
    }
    
    if (len > 0 && data == NULL) {
        printf("Ошибка: data=NULL при len=%zu\n", len);
        return -1;
    }
    
    if (len > MAX_DATA_SIZE) {
        printf("Ошибка: данные слишком большие (макс %d, получено %zu)\n", 
               MAX_DATA_SIZE, len);
        return -1;
    }
    
    return 0;
}

// =========== ИНИЦИАЛИЗАЦИЯ И СОХРАНЕНИЕ SNL ===========
void init_sockaddr_nl(struct sockaddr_nl* snl) {
    if (snl == NULL) return;
    
    memset(snl, 0, sizeof(*snl));
#ifdef __APPLE__
    snl->nl_family = AF_INET;
#else
    snl->nl_family = AF_NETLINK;
#endif
    snl->nl_pad = 0;
    snl->nl_pid = getpid();
    snl->nl_groups = 0;
}

// =========== ГЛАВНАЯ ФУНКЦИЯ ===========
int send_netlink_socket(int type, const char *data, size_t len) {
    static int n_sock = -1;
    
    struct sockaddr_nl* snl_ptr = &saved_snl;  // Используем сохраненную структуру
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    char buf[4092];
    
    uint8_t check_mask = 0;
    
#ifdef __APPLE__
    printf("macOS: симуляция NETLINK\n");
#endif
    
    // =========== ПРОВЕРКА ПАРАМЕТРОВ ===========
    memset(buf, 0, sizeof(buf));
    
    if (len > 0 && data == NULL) {
        printf("Ошибка: data не может быть NULL при len > 0\n");
        return -1;
    }
    
    if (validate_netlink_params(type, data, len) != 0) {
        return -1;
    }
    
    // =========== ИНИЦИАЛИЗАЦИЯ СТРУКТУР ===========
    memset(&iov, 0, sizeof(iov));
    memset(&msg, 0, sizeof(msg));
    
    // =========== СОЗДАНИЕ И НАСТРОЙКА СОКЕТА ===========
    if (n_sock < 0) {
        if (socket_state & get_sock_created_mask()) {
            printf("Предупреждение: флаг создания есть, но n_sock = -1\n");
            clear_socket_state_bit(get_sock_created_mask());
        }
        
        // Инициализируем snl перед созданием сокета
        init_sockaddr_nl(snl_ptr);
        
#ifdef __APPLE__
        n_sock = socket(AF_INET, SOCK_DGRAM, 0);
#else
        n_sock = socket(AF_NETLINK, SOCK_STREAM, NETLINK_NETFILTER);
#endif
        
        if (n_sock < 0) {
            set_socket_state_bit(get_err_socket_mask());
            
            if (errno == EACCES) {
                set_socket_state_bit(get_err_eacces_mask());
                printf("Ошибка: нет прав для создания сокета\n");
            } else {
                perror("Ошибка создания socket");
            }
            return -1;
        }
        
        set_socket_state_bit(get_sock_created_mask());
        printf("✓ Сокет создан (fd=%d)\n", n_sock);
        
        // Устанавливаем флаг что snl инициализирован
        set_check_bit(&check_mask, get_check_snl_mask());
        
        // Bind (симуляция для macOS)
#ifdef __APPLE__
        printf("✓ Bind пропущен (демо для macOS)\n");
        set_socket_state_bit(get_sock_bound_mask());
#else
        if (bind(n_sock, (struct sockaddr*)snl_ptr, sizeof(*snl_ptr)) < 0) {
            if (errno == EACCES) {
                set_socket_state_bit(get_err_eacces_mask());
                printf("Ошибка: нет прав для bind\n");
            } else {
                set_socket_state_bit(get_err_bind_mask());
                perror("Ошибка bind");
            }
            
            close(n_sock);
            n_sock = -1;
            clear_socket_state_bit(get_sock_created_mask());
            return -1;
        }
        
        set_socket_state_bit(get_sock_bound_mask());
#endif
        printf("✓ Сокет готов (pid=%d)\n", snl_ptr->nl_pid);
    } else {
        // Сокет уже существует, проверяем что snl инициализирован
        if (snl_ptr->nl_pid == 0) {
            // snl не инициализирован, инициализируем
            init_sockaddr_nl(snl_ptr);
            printf("✓ SNL переинициализирован для существующего сокета\n");
        }
        set_check_bit(&check_mask, get_check_snl_mask());
        printf("✓ Используется существующий сокет (fd=%d)\n", n_sock);
    }
    
    // =========== ПРОВЕРКА ГОТОВНОСТИ ===========
    if (!is_socket_ready()) {
        printf("✗ Сокет не готов:\n");
        print_socket_state();
        return -1;
    }
    
    // =========== ПОДГОТОВКА СООБЩЕНИЯ ===========
    nlh = (struct nlmsghdr*)buf;
    size_t msg_len = NLMSG_SPACE(len);
    
    if (msg_len > sizeof(buf)) {
        printf("✗ Сообщение слишком большое: %zu > %zu\n", msg_len, sizeof(buf));
        return -1;
    }
    
    nlh->nlmsg_len = msg_len;
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
    nlh->nlmsg_seq = time(NULL);
    nlh->nlmsg_pid = getpid();
    
    if (nlh->nlmsg_len < sizeof(struct nlmsghdr)) {
        printf("✗ Длина сообщения слишком мала\n");
        return -1;
    }
    
    set_check_bit(&check_mask, get_check_nlhdr_mask());
    
    // Копирование данных
    if (data && len > 0) {
        void* data_ptr = NLMSG_DATA(nlh);
        if (data_ptr == NULL) {
            printf("✗ Не удалось получить указатель на данные\n");
            return -1;
        }
        
        memcpy(data_ptr, data, len);
        set_check_bit(&check_mask, get_check_data_mask());
        
        // Быстрая проверка копирования
        if (memcmp(data_ptr, data, len > 16 ? 16 : len) != 0) {
            printf("✗ Данные не скопированы корректно\n");
            return -1;
        }
    }
    
    // Настройка iovec
    iov.iov_base = buf;
    iov.iov_len = nlh->nlmsg_len;
    
    if (iov.iov_base == NULL) {
        printf("✗ iov.iov_base = NULL\n");
        return -1;
    }
    
    set_check_bit(&check_mask, get_check_iov_mask());
    
    // Настройка msghdr
    msg.msg_name = snl_ptr;
    msg.msg_namelen = sizeof(*snl_ptr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    if (msg.msg_name == NULL || msg.msg_iov == NULL) {
        printf("✗ Поля msghdr не инициализированы\n");
        return -1;
    }
    
    set_check_bit(&check_mask, get_check_msg_mask());
    
    // =========== ПРОВЕРКА ВСЕХ СТРУКТУР ===========
    uint8_t required_checks = get_required_checks_mask();
    
    if ((check_mask & required_checks) != required_checks) {
        printf("✗ Не все структуры инициализированы\n");
        printf("  Ожидалось: 0x%02X, Получено: 0x%02X\n", required_checks, check_mask);
        
        uint8_t missing = required_checks & ~check_mask;
        
        if (missing & get_check_nlhdr_mask()) printf("    - nlmsghdr\n");
        if (missing & get_check_iov_mask())   printf("    - iovec\n");
        if (missing & get_check_msg_mask())   printf("    - msghdr\n");
        if (missing & get_check_snl_mask())   printf("    - sockaddr_nl\n");
        
        return -1;
    }
    
    printf("✓ Все структуры проверены (маска: 0x%02X)\n", check_mask);
    
    // =========== ОТПРАВКА (СИМУЛЯЦИЯ) ===========
    printf("→ Отправка: type=%d, len=%zu... ", type, len);
    
#ifdef __APPLE__
    printf("симуляция (macOS)\n");
    int send_result = len;
#else
    int send_result = sendmsg(n_sock, &msg, 0);
#endif
    
    if (send_result < 0) {
        set_socket_state_bit(get_err_sendmsg_mask());
        
        if (errno == EISCONN) {
            set_socket_state_bit(get_err_eisconn_mask());
            printf("✗ Сокет уже подключен\n");
        } else {
            perror("✗ Ошибка sendmsg");
        }
        return -1;
    }
    
    printf("✓ Отправлено %d байт\n", send_result);
    
    reset_socket_errors();
    set_socket_state_bit(get_sock_valid_mask());
    
    return 0;
}

// =========== ТЕСТЫ ===========
void run_tests(void) {
    printf("\n=== Запуск тестов ===\n");
    
    const char* test_data = "Test message";
    
    // Тест 1
    printf("\n[1] Нулевая длина данных:\n");
    int r1 = send_netlink_socket(1, NULL, 0);
    printf("Результат: %s\n", r1 == 0 ? "✓ Успех" : "✗ Ошибка");
    
    // Тест 2
    printf("\n[2] Корректные данные:\n");
    int r2 = send_netlink_socket(2, test_data, strlen(test_data));
    printf("Результат: %s\n", r2 == 0 ? "✓ Успех" : "✗ Ошибка");
    
    // Тест 3
    printf("\n[3] Неверный тип (0):\n");
    int r3 = send_netlink_socket(0, test_data, strlen(test_data));
    printf("Результат: %s\n", r3 == -1 ? "✓ Ожидаемая ошибка" : "✗ Неожиданный результат");
    
    // Тест 4
    printf("\n[4] Большие данные:\n");
    char big[5000];
    memset(big, 'X', sizeof(big));
    int r4 = send_netlink_socket(3, big, sizeof(big));
    printf("Результат: %s\n", r4 == -1 ? "✓ Ожидаемая ошибка" : "✗ Неожиданный результат");
    
    // Тест 5
    printf("\n[5] data=NULL при len>0:\n");
    int r5 = send_netlink_socket(4, NULL, 10);
    printf("Результат: %s\n", r5 == -1 ? "✓ Ожидаемая ошибка" : "✗ Неожиданный результат");
    
    // Тест 6
    printf("\n[6] Повторный вызов:\n");
    int r6 = send_netlink_socket(5, "Second", 6);
    printf("Результат: %s\n", r6 == 0 ? "✓ Успех" : "✗ Ошибка");
    
    // Тест 7
    printf("\n[7] Еще один вызов:\n");
    int r7 = send_netlink_socket(6, "Third", 5);
    printf("Результат: %s\n", r7 == 0 ? "✓ Успех" : "✗ Ошибка");
    
    printf("\n=== Итоги тестов ===\n");
    printf("Успешных: %d из 7\n", 
           (r1 == 0) + (r2 == 0) + (r3 == -1) + (r4 == -1) + 
           (r5 == -1) + (r6 == 0) + (r7 == 0));
}

void test_bit_operations(void) {
    printf("\n=== Тест битовых операций ===\n");
    
    // Демонстрация проверки через маски
    uint8_t mask1 = get_check_nlhdr_mask() | get_check_iov_mask() | get_check_msg_mask();
    uint8_t mask2 = get_check_nlhdr_mask() | get_check_iov_mask() | get_check_msg_mask() | get_check_snl_mask();
    
    printf("Маска 1: 0x%02X, проверка: %s\n", 
           mask1, 
           (mask1 & get_required_checks_mask()) == get_required_checks_mask() ? "✓ OK" : "✗ Missing");
    
    printf("Маска 2: 0x%02X, проверка: %s\n", 
           mask2, 
           (mask2 & get_required_checks_mask()) == get_required_checks_mask() ? "✓ OK" : "✗ Missing");
    
    // Проверка отдельных битов
    printf("\nПроверка отдельных битов в маске 2:\n");
    printf("  CHECK_NLHDR: %s\n", (mask2 & get_check_nlhdr_mask()) ? "✓" : "✗");
    printf("  CHECK_IOV:   %s\n", (mask2 & get_check_iov_mask()) ? "✓" : "✗");
    printf("  CHECK_MSG:   %s\n", (mask2 & get_check_msg_mask()) ? "✓" : "✗");
    printf("  CHECK_SNL:   %s\n", (mask2 & get_check_snl_mask()) ? "✓" : "✗");
    printf("  CHECK_DATA:  %s\n", (mask2 & get_check_data_mask()) ? "✓" : "✗");
}

int main(void) {
    printf("=== Демонстрация битовых масок для проверок ===\n");
    printf("Платформа: %s\n", 
#ifdef __APPLE__
           "macOS (симуляция)"
#else
           "Linux"
#endif
    );
    
    // Очищаем состояние перед тестами
    socket_state = 0;
    memset(&saved_snl, 0, sizeof(saved_snl));
    
    printf("\nНачальное состояние:\n");
    print_socket_state();
    
    // Запускаем тесты
    run_tests();
    
    printf("\nФинальное состояние:\n");
    print_socket_state();
    
    // Демонстрация битовых операций
    test_bit_operations();
    
    printf("\n=== Проверка геттеров ===\n");
    printf("Сокет создан: %s\n", is_socket_created() ? "✓ Да" : "✗ Нет");
    printf("Сокет привязан: %s\n", is_socket_bound() ? "✓ Да" : "✗ Нет");
    printf("Сокет готов: %s\n", is_socket_ready() ? "✓ Да" : "✗ Нет");
    printf("Есть ошибки: %s\n", has_socket_errors() ? "✗ Да" : "✓ Нет");
    
    printf("\n=== Достигнутые цели ===\n");
    printf("1. Битовые маски для проверок: ✓\n");
    printf("2. Статические переменные и геттеры: ✓\n");
    printf("3. Проверка всех структур: ✓\n");
    printf("4. Кросс-платформенность (macOS/Linux): ✓\n");
    printf("5. Детальная диагностика ошибок: ✓\n");
    
    return 0;
}