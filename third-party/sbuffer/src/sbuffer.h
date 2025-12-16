// sbuffer.h
#ifndef SBUFFER_H
#define SBUFFER_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    BUFFER_TYPE_CHAR,   // Для строк (нужен null-terminator)
    BUFFER_TYPE_UINT8,  // Для бинарных данных
    BUFFER_TYPE_INT32,  // Для целых чисел
    BUFFER_TYPE_FLOAT,  // Для чисел с плавающей точкой
    BUFFER_TYPE_STRUCT  // Для произвольных структур
} BufferType;

struct SafeBuffer;

#define SAFE_BUFFER_MAGIC 0x53424652UL

// Создание буферов
struct SafeBuffer *safe_buffer_create(BufferType type, size_t capacity);
struct SafeBuffer *safe_buffer_create_string(size_t char_capacity);
struct SafeBuffer *safe_buffer_create_binary(size_t byte_capacity);
struct SafeBuffer *safe_buffer_create_int_array(size_t count);
struct SafeBuffer *safe_buffer_create_float_array(size_t count);
struct SafeBuffer *safe_buffer_create_struct(size_t element_size, size_t count);

// Валидация
bool safe_buffer_validate(const struct SafeBuffer *buffer);

// Доступ к данным
char* safe_buffer_get_string(struct SafeBuffer *buffer);
uint8_t* safe_buffer_get_binary(struct SafeBuffer *buffer);
int32_t* safe_buffer_get_int_array(struct SafeBuffer *buffer);
float* safe_buffer_get_float_array(struct SafeBuffer *buffer);
void* safe_buffer_get_generic(struct SafeBuffer *buffer);

// Операции
bool safe_buffer_copy(struct SafeBuffer *dest, const struct SafeBuffer *src);
bool safe_buffer_append_string(struct SafeBuffer *buffer, const char *str);
bool safe_buffer_set_string(struct SafeBuffer *buffer, const char *str);

// Информация
BufferType safe_buffer_get_type(const struct SafeBuffer *buffer);
size_t safe_buffer_get_capacity(const struct SafeBuffer *buffer);
size_t safe_buffer_get_length(const struct SafeBuffer *buffer);
size_t safe_buffer_get_element_size(const struct SafeBuffer *buffer);

// Уничтожение
void safe_buffer_destroy(struct SafeBuffer *buffer);

#endif // SBUFFER_H