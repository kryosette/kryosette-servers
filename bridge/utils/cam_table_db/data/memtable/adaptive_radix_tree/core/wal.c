#include "wal.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>

// Магическое число и версия формата
#define WAL_MAGIC 0x57414C31  // "WAL1"
#define WAL_VERSION 1

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint64_t created_at;
} wal_header_t;

typedef struct {
    uint64_t timestamp;
    char operation;
    uint32_t key_size;
    uint32_t value_size;
    // далее следуют key_data и value_data
} wal_record_header_t;
#pragma pack(pop)

wal_t* wal_init(const char* base_filename, size_t max_size) {
    wal_t* wal = malloc(sizeof(wal_t));
    if (!wal) return NULL;
    
    wal->filename = malloc(strlen(base_filename) + 16);
    if (!wal->filename) {
        free(wal);
        return NULL;
    }
    
    // Создаем имя файла с последовательным номером
    wal->sequence = 0;
    sprintf(wal->filename, "%s.%06lu.wal", base_filename, wal->sequence);
    wal->max_size = max_size;
    wal->current_size = 0;
    
    // Открываем файл с созданием если не существует
    wal->fd = open(wal->filename, O_CREAT | O_RDWR | O_APPEND, 0644);
    if (wal->fd == -1) {
        free(wal->filename);
        free(wal);
        return NULL;
    }
    
    // Если файл новый, пишем заголовок
    struct stat st;
    if (fstat(wal->fd, &st) == 0 && st.st_size == 0) {
        wal_header_t header = {
            .magic = WAL_MAGIC,
            .version = WAL_VERSION,
            .created_at = (uint64_t)time(NULL)
        };
        
        if (write(wal->fd, &header, sizeof(header)) != sizeof(header)) {
            close(wal->fd);
            free(wal->filename);
            free(wal);
            return NULL;
        }
        wal->current_size = sizeof(header);
    } else {
        wal->current_size = st.st_size;
    }
    
    return wal;
}

int wal_append(wal_t* wal, const char* key, size_t key_len, 
               const char* value, size_t value_len, char operation) {
    if (!wal || !key || key_len == 0) return -1;
    
    // Проверяем размер и делаем ротацию если нужно
    if (wal->current_size + sizeof(wal_record_header_t) + key_len + value_len > wal->max_size) {
        if (wal_rotate(wal) != 0) {
            return -1;
        }
    }
    
    wal_record_header_t header = {
        .timestamp = (uint64_t)time(NULL),
        .operation = operation,
        .key_size = (uint32_t)key_len,
        .value_size = (uint32_t)value_len
    };
    
    // Пишем заголовок записи
    if (write(wal->fd, &header, sizeof(header)) != sizeof(header)) {
        return -1;
    }
    
    // Пишем ключ
    if (write(wal->fd, key, key_len) != (ssize_t)key_len) {
        // Откатываем запись заголовка
        lseek(wal->fd, -sizeof(header), SEEK_CUR);
        return -1;
    }
    
    // Пишем значение если есть
    if (value_len > 0) {
        if (write(wal->fd, value, value_len) != (ssize_t)value_len) {
            // Откатываем запись
            lseek(wal->fd, -(sizeof(header) + key_len), SEEK_CUR);
            return -1;
        }
    }
    
    // Синхронизируем с диском для durability
    if (fsync(wal->fd) != 0) {
        return -1;
    }
    
    wal->current_size += sizeof(header) + key_len + value_len;
    return 0;
}

int wal_replay(wal_t* wal, wal_apply_func_t apply_func, void* user_data) {
    if (!wal || !apply_func) return -1;
    
    // Переходим в начало файла (после заголовка)
    lseek(wal->fd, sizeof(wal_header_t), SEEK_SET);
    
    wal_record_header_t header;
    ssize_t bytes_read;
    
    while ((bytes_read = read(wal->fd, &header, sizeof(header))) == sizeof(header)) {
        // Читаем ключ
        char* key = malloc(header.key_size);
        if (!key) return -1;
        
        if (read(wal->fd, key, header.key_size) != (ssize_t)header.key_size) {
            free(key);
            return -1;
        }
        
        // Читаем значение
        char* value = NULL;
        if (header.value_size > 0) {
            value = malloc(header.value_size);
            if (!value) {
                free(key);
                return -1;
            }
            
            if (read(wal->fd, value, header.value_size) != (ssize_t)header.value_size) {
                free(key);
                free(value);
                return -1;
            }
        }
        
        // Применяем операцию
        if (apply_func(header.operation, key, header.key_size, 
                      value, header.value_size, user_data) != 0) {
            free(key);
            if (value) free(value);
            return -1;
        }
        
        free(key);
        if (value) free(value);
    }
    
    return 0;
}

int wal_rotate(wal_t* wal) {
    if (!wal) return -1;
    
    close(wal->fd);
    
    // Увеличиваем sequence и создаем новое имя файла
    wal->sequence++;
    char new_filename[512];
    sprintf(new_filename, "%s.%06lu.wal", 
            wal->filename, wal->sequence);
    
    // Обновляем имя файла в структуре
    char* old_filename = wal->filename;
    wal->filename = malloc(strlen(new_filename) + 1);
    if (!wal->filename) {
        wal->filename = old_filename;
        return -1;
    }
    strcpy(wal->filename, new_filename);
    free(old_filename);
    
    // Создаем новый файл
    wal->fd = open(wal->filename, O_CREAT | O_RDWR | O_APPEND, 0644);
    if (wal->fd == -1) {
        return -1;
    }
    
    // Пишем заголовок
    wal_header_t header = {
        .magic = WAL_MAGIC,
        .version = WAL_VERSION,
        .created_at = (uint64_t)time(NULL)
    };
    
    if (write(wal->fd, &header, sizeof(header)) != sizeof(header)) {
        close(wal->fd);
        return -1;
    }
    
    wal->current_size = sizeof(header);
    return 0;
}

int wal_clear(wal_t* wal) {
    if (!wal) return -1;
    
    close(wal->fd);
    
    // Удаляем текущий файл
    if (unlink(wal->filename) != 0) {
        return -1;
    }
    
    // Создаем новый файл
    wal->fd = open(wal->filename, O_CREAT | O_RDWR | O_APPEND, 0644);
    if (wal->fd == -1) {
        return -1;
    }
    
    // Пишем заголовок
    wal_header_t header = {
        .magic = WAL_MAGIC,
        .version = WAL_VERSION,
        .created_at = (uint64_t)time(NULL)
    };
    
    if (write(wal->fd, &header, sizeof(header)) != sizeof(header)) {
        close(wal->fd);
        return -1;
    }
    
    wal->current_size = sizeof(header);
    return 0;
}

void wal_close(wal_t* wal) {
    if (!wal) return;
    
    if (wal->fd != -1) {
        close(wal->fd);
    }
    
    if (wal->filename) {
        free(wal->filename);
    }
    
    free(wal);
}

char* wal_find_latest(const char* base_filename) {
    // Простая реализация - ищем файл с наибольшим sequence number
    // В реальной системе нужно провершать magic number и целостность
    char pattern[512];
    sprintf(pattern, "%s.*.wal", base_filename);
    
    // Здесь должна быть логика поиска в директории
    // Для простоты возвращаем базовое имя
    char* filename = malloc(strlen(base_filename) + 16);
    if (!filename) return NULL;
    
    sprintf(filename, "%s.000000.wal", base_filename);
    return filename;
}

int wal_recover(const char* base_filename, wal_apply_func_t apply_func, void* user_data) {
    char* latest_wal = wal_find_latest(base_filename);
    if (!latest_wal) return -1;
    
    wal_t* wal = wal_init(base_filename, 64 * 1024 * 1024); // 64MB default
    if (!wal) {
        free(latest_wal);
        return -1;
    }
    
    int result = wal_replay(wal, apply_func, user_data);
    wal_close(wal);
    free(latest_wal);
    
    return result;
}
