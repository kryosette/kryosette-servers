// test_node.c
#include "code.h"
#include <check.h>
#include <stdlib.h>
#include <string.h>

// Мокируем сетевое взаимодействие
int mock_forward_sock = -1;
int mock_forward_result = 0;

START_TEST(test_rate_limiting) {
    ClientInfo client = {0};
    strcpy(client.ip, "192.168.1.1");
    client.last_update = time(NULL);
    client.last_request = time(NULL);
    
    // 1. Проверяем начальное состояние
    ck_assert_int_eq(check_rate_limiting(&client), 0);
    
    // 2. Имитируем быстрые запросы
    for (int i = 0; i < MAX_REQUESTS_PER_SECOND + 1; i++) {
        client.count++;
        client.last_request = time(NULL);  // Обновляем время последнего запроса
    }
    
    // 3. Должно сработать ограничение по количеству
    ck_assert_int_eq(check_rate_limiting(&client), 1);
    
    // 4. Ждем 1 секунду и проверяем сброс
    sleep(1);
    ck_assert_int_eq(check_rate_limiting(&client), 0);
}
END_TEST

START_TEST(test_ip_banning) {
    const char *test_ip = "192.168.1.2";
    
    // Проверяем незабаненный IP
    ck_assert_int_eq(is_banned(test_ip), 0);
    
    // Добавляем в бан
    pthread_mutex_lock(&lock);
    ClientInfo *client = find_or_create_client(test_ip);
    client->is_banned = 1;
    client->banned_until = time(NULL) + 60;
    pthread_mutex_unlock(&lock);
    
    // Проверяем бан
    ck_assert_int_eq(is_banned(test_ip), 1);
}
END_TEST

START_TEST(test_authentication) {
    // Корректный пароль
    ck_assert_int_eq(authenticate("password", "127.0.0.1"), 1);
    
    // Неверный пароль
    ck_assert_int_eq(authenticate("wrong", "127.0.0.1"), 0);
}
END_TEST

// Добавьте мок-функцию в начале тестового файла
int mock_forward_connection = 1; 

START_TEST(test_forwarding_logic) {
    // Временное отключение реального соединения
    mock_forward_connection = 1;
    
    char test_data[] = "test payload";
    packet_count = 0; // Сброс счётчика
    
    // Тестируем буферизацию
    for (int i = 0; i < THRESHOLD-1; i++) {
        ck_assert_int_eq(forward_data(-1, test_data, strlen(test_data)), 0);
    }
    
    // Тестируем отправку
    ck_assert_int_eq(forward_data(-1, test_data, strlen(test_data)), 0);
}
END_TEST

Suite *node_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Node");
    tc_core = tcase_create("Core");
    
    tcase_add_test(tc_core, test_rate_limiting);
    tcase_add_test(tc_core, test_ip_banning);
    tcase_add_test(tc_core, test_authentication);
    tcase_add_test(tc_core, test_forwarding_logic);
    
    suite_add_tcase(s, tc_core);
    return s;
}

int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;
    
    s = node_suite();
    sr = srunner_create(s);
    
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}