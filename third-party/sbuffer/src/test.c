#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct SafeBuffer;

struct SafeBuffer *safe_buffer_create_string(size_t char_capacity);
struct SafeBuffer *safe_buffer_create_binary(size_t byte_capacity);
struct SafeBuffer *safe_buffer_create_int_array(size_t count);
struct SafeBuffer *safe_buffer_create_float_array(size_t count);
struct SafeBuffer *safe_buffer_create_struct(size_t element_size, size_t count);
struct SafeBuffer *safe_buffer_create(int type, size_t capacity);
void safe_buffer_destroy(struct SafeBuffer *buffer);
bool safe_buffer_validate(const struct SafeBuffer *buffer);
char* safe_buffer_get_string(struct SafeBuffer *buffer);
uint8_t* safe_buffer_get_binary(struct SafeBuffer *buffer);
int32_t* safe_buffer_get_int_array(struct SafeBuffer *buffer);
float* safe_buffer_get_float_array(struct SafeBuffer *buffer);
void* safe_buffer_get_generic(struct SafeBuffer *buffer);
bool safe_buffer_copy(struct SafeBuffer *dest, const struct SafeBuffer *src);
bool safe_buffer_append_string(struct SafeBuffer *buffer, const char *str);
bool safe_buffer_set_string(struct SafeBuffer *buffer, const char *str);
int safe_buffer_get_type(const struct SafeBuffer *buffer);
size_t safe_buffer_get_capacity(const struct SafeBuffer *buffer);
size_t safe_buffer_get_length(const struct SafeBuffer *buffer);
size_t safe_buffer_get_element_size(const struct SafeBuffer *buffer);

enum {
    BUFFER_TYPE_CHAR,
    BUFFER_TYPE_UINT8,
    BUFFER_TYPE_INT32,
    BUFFER_TYPE_FLOAT,
    BUFFER_TYPE_STRUCT
};

void test_create_string_buffer(void) {
    printf("Test 1: Creating string buffer... ");
    struct SafeBuffer *buf = safe_buffer_create_string(100);
    assert(buf != NULL);
    assert(safe_buffer_validate(buf) == true);
    assert(safe_buffer_get_type(buf) == BUFFER_TYPE_CHAR);
    assert(safe_buffer_get_capacity(buf) == 100);
    assert(safe_buffer_get_element_size(buf) == sizeof(char));
    char *str = safe_buffer_get_string(buf);
    assert(str != NULL);
    assert(str[0] == '\0');
    safe_buffer_destroy(buf);
    printf("OK\n");
}

void test_create_binary_buffer(void) {
    printf("Test 2: Creating binary buffer... ");
    struct SafeBuffer *buf = safe_buffer_create_binary(256);
    assert(buf != NULL);
    assert(safe_buffer_validate(buf) == true);
    assert(safe_buffer_get_type(buf) == BUFFER_TYPE_UINT8);
    assert(safe_buffer_get_capacity(buf) == 256);
    assert(safe_buffer_get_element_size(buf) == sizeof(uint8_t));
    uint8_t *data = safe_buffer_get_binary(buf);
    assert(data != NULL);
    for (size_t i = 0; i < 256; i++) {
        assert(data[i] == 0);
    }
    safe_buffer_destroy(buf);
    printf("OK\n");
}

void test_create_int_array(void) {
    printf("Test 3: Creating int array... ");
    struct SafeBuffer *buf = safe_buffer_create_int_array(50);
    assert(buf != NULL);
    assert(safe_buffer_validate(buf) == true);
    assert(safe_buffer_get_type(buf) == BUFFER_TYPE_INT32);
    assert(safe_buffer_get_capacity(buf) == 50);
    assert(safe_buffer_get_element_size(buf) == sizeof(int32_t));
    int32_t *ints = safe_buffer_get_int_array(buf);
    assert(ints != NULL);
    for (size_t i = 0; i < 50; i++) {
        ints[i] = (int32_t)(i * 10);
        assert(ints[i] == (int32_t)(i * 10));
    }
    safe_buffer_destroy(buf);
    printf("OK\n");
}

void test_create_float_array(void) {
    printf("Test 4: Creating float array... ");
    struct SafeBuffer *buf = safe_buffer_create_float_array(25);
    assert(buf != NULL);
    assert(safe_buffer_validate(buf) == true);
    assert(safe_buffer_get_type(buf) == BUFFER_TYPE_FLOAT);
    assert(safe_buffer_get_capacity(buf) == 25);
    assert(safe_buffer_get_element_size(buf) == sizeof(float));
    float *floats = safe_buffer_get_float_array(buf);
    assert(floats != NULL);
    for (size_t i = 0; i < 25; i++) {
        floats[i] = i * 1.5f;
        assert(floats[i] == i * 1.5f);
    }
    safe_buffer_destroy(buf);
    printf("OK\n");
}

void test_create_struct_buffer(void) {
    printf("Test 5: Creating struct buffer... ");
    struct Point {
        int x;
        int y;
        char label[20];
    };
    struct SafeBuffer *buf = safe_buffer_create_struct(sizeof(struct Point), 10);
    assert(buf != NULL);
    assert(safe_buffer_validate(buf) == true);
    assert(safe_buffer_get_type(buf) == BUFFER_TYPE_STRUCT);
    assert(safe_buffer_get_capacity(buf) == 10);
    assert(safe_buffer_get_element_size(buf) == sizeof(struct Point));
    struct Point *points = (struct Point*)safe_buffer_get_generic(buf);
    assert(points != NULL);
    for (size_t i = 0; i < 10; i++) {
        points[i].x = (int)i;
        points[i].y = (int)i * 2;
        snprintf(points[i].label, 20, "Point %zu", i);
        assert(points[i].x == (int)i);
        assert(points[i].y == (int)i * 2);
    }
    safe_buffer_destroy(buf);
    printf("OK\n");
}

void test_string_operations(void) {
    printf("Test 6: String operations... ");
    struct SafeBuffer *buf = safe_buffer_create_string(50);
    assert(buf != NULL);
    bool result = safe_buffer_set_string(buf, "Hello");
    assert(result == true);
    assert(safe_buffer_get_length(buf) == 5);
    char *str = safe_buffer_get_string(buf);
    assert(str != NULL);
    assert(strcmp(str, "Hello") == 0);
    result = safe_buffer_append_string(buf, " World");
    assert(result == true);
    assert(safe_buffer_get_length(buf) == 11);
    assert(strcmp(str, "Hello World") == 0);
    result = safe_buffer_append_string(buf, " This string is too long to fit in the buffer");
    assert(result == false);
    assert(safe_buffer_get_length(buf) == 11);
    assert(strcmp(str, "Hello World") == 0);
    safe_buffer_set_string(buf, NULL);
    assert(safe_buffer_get_length(buf) == 0);
    assert(str[0] == '\0');
    safe_buffer_destroy(buf);
    printf("OK\n");
}

void test_buffer_copy(void) {
    printf("Test 7: Buffer copy... ");
    
    // Создаем два строковых буфера (там есть length)
    struct SafeBuffer *src = safe_buffer_create_string(20);
    struct SafeBuffer *dest = safe_buffer_create_string(30);
    assert(src != NULL);
    assert(dest != NULL);
    
    // Устанавливаем строку в src
    bool result = safe_buffer_set_string(src, "Hello World");
    assert(result == true);
    
    // Копируем
    result = safe_buffer_copy(dest, src);
    assert(result == true);
    
    // Проверяем
    char *src_str = safe_buffer_get_string(src);
    char *dest_str = safe_buffer_get_string(dest);
    assert(strcmp(src_str, "Hello World") == 0);
    assert(strcmp(dest_str, "Hello World") == 0);
    
    safe_buffer_destroy(src);
    safe_buffer_destroy(dest);
    printf("OK\n");
}   
 
void test_buffer_validation(void) {
    printf("Test 8: Buffer validation... ");
    struct SafeBuffer *buf = safe_buffer_create_string(10);
    assert(buf != NULL);
    assert(safe_buffer_validate(buf) == true);
    assert(safe_buffer_get_type(buf) == BUFFER_TYPE_CHAR);
    assert(safe_buffer_get_capacity(buf) == 10);
    assert(safe_buffer_get_length(buf) == 0);
    assert(safe_buffer_get_element_size(buf) == sizeof(char));
    safe_buffer_destroy(buf);
    printf("OK\n");
}

void test_edge_cases(void) {
    printf("Test 9: Edge cases and errors... ");
    struct SafeBuffer *buf;
    buf = safe_buffer_create_string(0);
    assert(buf == NULL);
    buf = safe_buffer_create_string(1024 * 1024 + 1);
    assert(buf == NULL);
    buf = safe_buffer_create(BUFFER_TYPE_CHAR, 0);
    assert(buf == NULL);
    buf = safe_buffer_create(BUFFER_TYPE_CHAR, 1024 * 1024 + 1);
    assert(buf == NULL);
    buf = safe_buffer_create_struct(1, 1024 * 1024 + 1);
    assert(buf == NULL);
    buf = safe_buffer_create_struct(0, 10);
    assert(buf == NULL);
    buf = safe_buffer_create_string(10);
    assert(buf != NULL);
    char *str = safe_buffer_get_string(NULL);
    assert(str == NULL);
    uint8_t *bin = safe_buffer_get_binary(buf);
    assert(bin == NULL);
    int32_t *ints = safe_buffer_get_int_array(buf);
    assert(ints == NULL);
    bool result = safe_buffer_copy(NULL, NULL);
    assert(result == false);
    safe_buffer_destroy(NULL);
    safe_buffer_destroy(buf);
    printf("OK\n");
}

void test_type_safe_access(void) {
    printf("Test 10: Type-safe access... ");
    struct SafeBuffer *str_buf = safe_buffer_create_string(20);
    struct SafeBuffer *int_buf = safe_buffer_create_int_array(10);
    struct SafeBuffer *float_buf = safe_buffer_create_float_array(5);
    struct SafeBuffer *bin_buf = safe_buffer_create_binary(8);
    assert(str_buf != NULL);
    assert(int_buf != NULL);
    assert(float_buf != NULL);
    assert(bin_buf != NULL);
    char *str = safe_buffer_get_string(str_buf);
    int32_t *ints = safe_buffer_get_int_array(int_buf);
    float *floats = safe_buffer_get_float_array(float_buf);
    uint8_t *bin = safe_buffer_get_binary(bin_buf);
    assert(str != NULL);
    assert(ints != NULL);
    assert(floats != NULL);
    assert(bin != NULL);
    assert(safe_buffer_get_string(int_buf) == NULL);
    assert(safe_buffer_get_int_array(str_buf) == NULL);
    assert(safe_buffer_get_float_array(bin_buf) == NULL);
    assert(safe_buffer_get_binary(float_buf) == NULL);
    void *generic_str = safe_buffer_get_generic(str_buf);
    void *generic_int = safe_buffer_get_generic(int_buf);
    assert(generic_str == str);
    assert(generic_int == ints);
    safe_buffer_destroy(str_buf);
    safe_buffer_destroy(int_buf);
    safe_buffer_destroy(float_buf);
    safe_buffer_destroy(bin_buf);
    printf("OK\n");
}

int main() {
    printf("=== SafeBuffer Tests ===\n\n");
    test_create_string_buffer();
    test_create_binary_buffer();
    test_create_int_array();
    test_create_float_array();
    test_create_struct_buffer();
    test_string_operations();
    test_buffer_copy();
    test_buffer_validation();
    test_edge_cases();
    test_type_safe_access();
    printf("\n=== All tests passed! ===\n");
    return 0;
}