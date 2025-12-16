#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
    BUFFER_TYPE_CHAR,
    BUFFER_TYPE_UINT8,
    BUFFER_TYPE_INT32,
    BUFFER_TYPE_FLOAT,
    BUFFER_TYPE_STRUCT
} BufferType;

struct SafeBuffer {
    BufferType type;
    char *data;
    size_t capacity;
    size_t length;
    size_t element_size;
    unsigned long magic;
};

static const unsigned long SAFE_BUFFER_MAGIC_VALUE = 0x53424652UL;

bool safe_buffer_validate(const struct SafeBuffer *buffer) {
    if (!buffer) return false;
    if (buffer->magic != SAFE_BUFFER_MAGIC_VALUE) return false;
    if (buffer->capacity == 0) return false;
    if (buffer->element_size == 0 && buffer->type != BUFFER_TYPE_STRUCT) return false;
    if (!buffer->data) return false;
    if (buffer->element_size > 0 && buffer->capacity > SIZE_MAX / buffer->element_size) return false;
    switch (buffer->type) {
        case BUFFER_TYPE_CHAR:
        case BUFFER_TYPE_UINT8:
        case BUFFER_TYPE_INT32:
        case BUFFER_TYPE_FLOAT:
        case BUFFER_TYPE_STRUCT:
            break;
        default:
            return false;
    }
    return true;
}

struct SafeBuffer *safe_buffer_create(BufferType type, size_t capacity) {
    if (capacity == 0 || capacity > 1024 * 1024) return NULL;
    struct SafeBuffer *sbuffer = calloc(1, sizeof(*sbuffer));
    if (!sbuffer) return NULL;
    switch (type) {
        case BUFFER_TYPE_CHAR: sbuffer->element_size = sizeof(char); break;
        case BUFFER_TYPE_UINT8: sbuffer->element_size = sizeof(uint8_t); break;
        case BUFFER_TYPE_INT32: sbuffer->element_size = sizeof(int32_t); break;
        case BUFFER_TYPE_FLOAT: sbuffer->element_size = sizeof(float); break;
        case BUFFER_TYPE_STRUCT: sbuffer->element_size = 0; break;
        default: free(sbuffer); return NULL;
    }
    sbuffer->type = type;
    sbuffer->capacity = capacity;
    if (type == BUFFER_TYPE_CHAR) {
        sbuffer->data = calloc(1, (capacity + 1) * sbuffer->element_size);
        if (sbuffer->data) ((char*)sbuffer->data)[capacity] = '\0';
    } else {
        sbuffer->data = calloc(capacity, sbuffer->element_size);
    }
    if (!sbuffer->data) { free(sbuffer); return NULL; }
    sbuffer->magic = SAFE_BUFFER_MAGIC_VALUE;
    return sbuffer;
}

struct SafeBuffer* safe_buffer_create_string(size_t char_capacity) {
    return safe_buffer_create(BUFFER_TYPE_CHAR, char_capacity);
}

struct SafeBuffer* safe_buffer_create_binary(size_t byte_capacity) {
    return safe_buffer_create(BUFFER_TYPE_UINT8, byte_capacity);
}

struct SafeBuffer* safe_buffer_create_int_array(size_t count) {
    return safe_buffer_create(BUFFER_TYPE_INT32, count);
}

struct SafeBuffer* safe_buffer_create_struct(size_t element_size, size_t count) {
    if (element_size == 0 || count == 0 || count > (1024 * 1024) / element_size) return NULL;
    struct SafeBuffer *buffer = calloc(1, sizeof(*buffer));
    if (!buffer) return NULL;
    buffer->type = BUFFER_TYPE_STRUCT;
    buffer->element_size = element_size;
    buffer->capacity = count;
    buffer->data = calloc(count, element_size);
    if (!buffer->data) { free(buffer); return NULL; }
    buffer->magic = SAFE_BUFFER_MAGIC_VALUE;
    return buffer;
}

struct SafeBuffer* safe_buffer_create_float_array(size_t count) {
    return safe_buffer_create(BUFFER_TYPE_FLOAT, count);
}

char* safe_buffer_get_string(struct SafeBuffer *buffer) {
    if (!safe_buffer_validate(buffer) || buffer->type != BUFFER_TYPE_CHAR) return NULL;
    return (char*)buffer->data;
}

uint8_t* safe_buffer_get_binary(struct SafeBuffer *buffer) {
    if (!safe_buffer_validate(buffer) || buffer->type != BUFFER_TYPE_UINT8) return NULL;
    return (uint8_t*)buffer->data;
}

int32_t* safe_buffer_get_int_array(struct SafeBuffer *buffer) {
    if (!safe_buffer_validate(buffer) || buffer->type != BUFFER_TYPE_INT32) return NULL;
    return (int32_t*)buffer->data;
}

float* safe_buffer_get_float_array(struct SafeBuffer *buffer) {
    if (!safe_buffer_validate(buffer) || buffer->type != BUFFER_TYPE_FLOAT) return NULL;
    return (float*)buffer->data;
}

void* safe_buffer_get_generic(struct SafeBuffer *buffer) {
    if (!safe_buffer_validate(buffer)) return NULL;
    return buffer->data;
}

bool safe_buffer_copy(struct SafeBuffer *dest, const struct SafeBuffer *src) {
    if (!safe_buffer_validate(dest) || !safe_buffer_validate(src)) return false;
    if (dest->type != src->type) return false;
    if (dest->element_size != src->element_size) return false;
    size_t bytes_to_copy = src->length * src->element_size;
    if (bytes_to_copy > dest->capacity * dest->element_size) bytes_to_copy = dest->capacity * dest->element_size;
    memcpy(dest->data, src->data, bytes_to_copy);
    dest->length = bytes_to_copy / dest->element_size;
    if (dest->type == BUFFER_TYPE_CHAR) {
        size_t max_chars = dest->capacity;
        if (dest->length > max_chars) dest->length = max_chars;
        ((char*)dest->data)[dest->length] = '\0';
    }
    return true;
}

void safe_buffer_destroy(struct SafeBuffer *buffer) {
    if (!buffer) return;
    unsigned long saved_magic = buffer->magic;
    buffer->magic = 0xDEADBEEF;
    if (saved_magic == SAFE_BUFFER_MAGIC_VALUE && buffer->data) {
        size_t bytes_to_wipe = buffer->capacity * buffer->element_size;
        if (buffer->type == BUFFER_TYPE_CHAR) bytes_to_wipe += buffer->element_size;
        memset(buffer->data, 0, bytes_to_wipe);
        free(buffer->data);
        buffer->data = NULL;
    }
    memset(buffer, 0, sizeof(struct SafeBuffer));
    free(buffer);
}

bool safe_buffer_append_string(struct SafeBuffer *buffer, const char *str) {
    if (!safe_buffer_validate(buffer) || buffer->type != BUFFER_TYPE_CHAR || !str) return false;
    size_t str_len = strlen(str);
    if (buffer->length + str_len > buffer->capacity) return false;
    char *data = (char*)buffer->data;
    memcpy(data + buffer->length, str, str_len);
    buffer->length += str_len;
    data[buffer->length] = '\0';
    return true;
}

bool safe_buffer_set_string(struct SafeBuffer *buffer, const char *str) {
    if (!safe_buffer_validate(buffer) || buffer->type != BUFFER_TYPE_CHAR) return false;
    buffer->length = 0;
    if (str) return safe_buffer_append_string(buffer, str);
    ((char*)buffer->data)[0] = '\0';
    return true;
}

BufferType safe_buffer_get_type(const struct SafeBuffer *buffer) {
    if (!safe_buffer_validate(buffer)) return BUFFER_TYPE_STRUCT;
    return buffer->type;
}

size_t safe_buffer_get_capacity(const struct SafeBuffer *buffer) {
    if (!safe_buffer_validate(buffer)) return 0;
    return buffer->capacity;
}

size_t safe_buffer_get_length(const struct SafeBuffer *buffer) {
    if (!safe_buffer_validate(buffer)) return 0;
    return buffer->length;
}

size_t safe_buffer_get_element_size(const struct SafeBuffer *buffer) {
    if (!safe_buffer_validate(buffer)) return 0;
    return buffer->element_size;
}