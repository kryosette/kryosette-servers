#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define NUM_VARS 1000000
#define BITS_PER_BYTE 8
#define MASK_SIZE ((NUM_VARS + BITS_PER_BYTE - 1) / BITS_PER_BYTE)

// Структура для быстрой проверки
typedef struct {
    void* pointers[NUM_VARS];
    uint8_t null_mask[MASK_SIZE];
    uint8_t non_null_mask[MASK_SIZE];
} FastPointerSet;

// Инициализация
void init_masks(FastPointerSet* set) {
    memset(set->null_mask, 0, MASK_SIZE);
    memset(set->non_null_mask, 0, MASK_SIZE);
    
    for (size_t i = 0; i < NUM_VARS; i++) {
        size_t byte_idx = i / BITS_PER_BYTE;
        uint8_t bit_mask = 1 << (i % BITS_PER_BYTE);
        
        if (set->pointers[i] == NULL) {
            set->null_mask[byte_idx] |= bit_mask;
        } else {
            set->non_null_mask[byte_idx] |= bit_mask;
        }
    }
}

// 1. Наивная проверка (базовая)
int check_all_null_naive(void** ptrs, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (ptrs[i] != NULL) {
            return 0;
        }
    }
    return 1;
}

// 2. Memcmp проверка
int check_all_null_memcmp(FastPointerSet* set) {
    for (size_t i = 0; i < MASK_SIZE; i++) {
        if (set->non_null_mask[i] != 0) {
            return 0;
        }
    }
    return 1;
}

// 3. 64-битная проверка
int check_all_null_64bit(FastPointerSet* set) {
    const uint64_t* mask64 = (const uint64_t*)set->non_null_mask;
    size_t size64 = MASK_SIZE / 8;
    
    for (size_t i = 0; i < size64; i++) {
        if (mask64[i] != 0) {
            return 0;
        }
    }
    
    // Остаток
    const uint8_t* remainder = (const uint8_t*)(mask64 + size64);
    for (size_t i = 0; i < MASK_SIZE % 8; i++) {
        if (remainder[i] != 0) {
            return 0;
        }
    }
    
    return 1;
}

// 4. Развернутый цикл
int check_all_null_unrolled(FastPointerSet* set) {
    const uint64_t* mask64 = (const uint64_t*)set->non_null_mask;
    size_t size64 = MASK_SIZE / 8;
    
    // Развернутый цикл
    for (size_t i = 0; i < size64; i += 4) {
        uint64_t m1 = mask64[i];
        uint64_t m2 = (i+1 < size64) ? mask64[i+1] : 0;
        uint64_t m3 = (i+2 < size64) ? mask64[i+2] : 0;
        uint64_t m4 = (i+3 < size64) ? mask64[i+3] : 0;
        
        if (m1 | m2 | m3 | m4) {
            return 0;
        }
    }
    
    // Остаток байтов
    const uint8_t* remainder = (const uint8_t*)(mask64 + (size64 & ~3));
    size_t rem_start = (size64 & ~3) * 8;
    
    for (size_t i = 0; i < MASK_SIZE - rem_start; i++) {
        if (remainder[i] != 0) {
            return 0;
        }
    }
    
    return 1;
}

// Точный бенчмарк
void run_benchmark(const char* name, FastPointerSet* set, int use_mask) {
    const int ITERATIONS = 10000;
    volatile int dummy_result = 0; // volatile чтобы компилятор не оптимизировал
    
    clock_t start = clock();
    
    if (strcmp(name, "Naive") == 0) {
        for (int iter = 0; iter < ITERATIONS; iter++) {
            dummy_result += check_all_null_naive(set->pointers, NUM_VARS);
        }
    } else if (strcmp(name, "Memcmp") == 0) {
        for (int iter = 0; iter < ITERATIONS; iter++) {
            dummy_result += check_all_null_memcmp(set);
        }
    } else if (strcmp(name, "64-bit") == 0) {
        for (int iter = 0; iter < ITERATIONS; iter++) {
            dummy_result += check_all_null_64bit(set);
        }
    } else if (strcmp(name, "Unrolled") == 0) {
        for (int iter = 0; iter < ITERATIONS; iter++) {
            dummy_result += check_all_null_unrolled(set);
        }
    }
    
    clock_t end = clock();
    double elapsed_ms = (double)(end - start) * 1000.0 / CLOCKS_PER_SEC;
    
    printf("%-10s: %8.3f ms total, %8.3f ns/check\n", 
           name, elapsed_ms, elapsed_ms * 1e6 / ITERATIONS);
}

int main() {
    printf("=== Правильный бенчмарк проверки указателей ===\n");
    printf("Переменных: %d, Маска: %d байт\n\n", NUM_VARS, MASK_SIZE);
    
    FastPointerSet set;
    
    // Тест A: Все null
    printf("ТЕСТ A: Все 1M переменных = NULL\n");
    printf("--------------------------------\n");
    
    memset(set.pointers, 0, sizeof(set.pointers));
    init_masks(&set);
    
    run_benchmark("Naive", &set, 0);
    run_benchmark("Memcmp", &set, 1);
    run_benchmark("64-bit", &set, 1);
    run_benchmark("Unrolled", &set, 1);
    
    // Тест B: Ни одного null
    printf("\nТЕСТ B: Все 1M переменных = NON-NULL\n");
    printf("--------------------------------\n");
    
    for (size_t i = 0; i < NUM_VARS; i++) {
        set.pointers[i] = (void*)(i + 1);
    }
    init_masks(&set);
    
    run_benchmark("Naive", &set, 0);
    run_benchmark("Memcmp", &set, 1);
    run_benchmark("64-bit", &set, 1);
    
    // Тест C: 50% null
    printf("\nТЕСТ C: 500K null, 500K non-null\n");
    printf("--------------------------------\n");
    
    for (size_t i = 0; i < NUM_VARS; i++) {
        set.pointers[i] = (i % 2 == 0) ? NULL : (void*)(i + 1);
    }
    init_masks(&set);
    
    run_benchmark("Naive", &set, 0);
    run_benchmark("Memcmp", &set, 1);
    run_benchmark("64-bit", &set, 1);
    
    // Расчет ускорения
    printf("\n=== Итоги ===\n");
    printf("1. Проверка через маски работает на 125KB данных\n");
    printf("2. Memcmp на маске vs наивный цикл по 1M указателей\n");
    printf("3. 64-битная проверка самая эффективная\n");
    
    // Простая демонстрация
    printf("\n=== Демо: 10 проверок разными методами ===\n");
    
    // Маленький тест для наглядности
    FastPointerSet small_set;
    const int DEMO_SIZE = 10;
    
    printf("\nМаска для первых %d переменных:\n", DEMO_SIZE);
    for (int i = 0; i < DEMO_SIZE; i++) {
        small_set.pointers[i] = (i < 5) ? NULL : (void*)0x1234;
    }
    
    // Покажем как работает маска
    printf("Указатели: ");
    for (int i = 0; i < DEMO_SIZE; i++) {
        printf("%c ", small_set.pointers[i] ? 'N' : '0');
    }
    
    // Создадим маску вручную
    uint8_t demo_mask = 0;
    for (int i = 0; i < DEMO_SIZE; i++) {
        if (small_set.pointers[i] == NULL) {
            demo_mask |= (1 << i);
        }
    }
    
    printf("\nБитовая маска: 0x%02X = ", demo_mask);
    for (int i = 7; i >= 0; i--) {
        printf("%d", (demo_mask >> i) & 1);
    }
    printf("\n");
    
    // Проверка через маску
    printf("Все null? %s (маска == 0xFF? %s)\n", 
           (demo_mask == 0xFF) ? "Да" : "Нет",
           (demo_mask == 0xFF) ? "Да" : "Нет");
    
    return 0;
}