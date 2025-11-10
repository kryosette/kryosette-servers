#include "node16.h"
#include <stdlib.h>
#include <string.h>
#include "smemset.h"
#include <stdio.h>

inner_node node16_create()
{
    node16 *node = malloc(sizeof(node16));
    if (!node)
        return NULL;

    node->header.type = NODE16;
    atomic_store(&node->header.count, 0);
    node->header.prefix_len = 0;

    smemset(node->keys, 0, 16);
    for (int i = 0; i < 16; i++)
    {
        atomic_store(&node->children[i], NULL);
    }

    return (inner_node)node;
}

art_node *node16_find_child(node16 *node, uint8_t key_byte)
{
    if (!node)
        return NULL;

    int count = atomic_load(&node->header.count);

    // Binary search в отсортированном массиве
    int left = 0, right = count - 1;
    while (left <= right)
    {
        int mid = left + (right - left) / 2;
        if (node->keys[mid] == key_byte)
        {
            return atomic_load(&node->children[mid]);
        }
        else if (node->keys[mid] < key_byte)
        {
            left = mid + 1;
        }
        else
        {
            right = mid - 1;
        }
    }

    return NULL;
}

int node16_add_child(node16 *node, uint8_t key_byte, art_node *child)
{
    if (!node || !child)
        return -1;

    while (true)
    {
        int current_count = atomic_load(&node->header.count);

        if (current_count >= 16)
            return -2;

        // Binary search для проверки существования и поиска позиции
        int insert_pos = 0;
        int found = 0;

        for (int i = 0; i < current_count; i++)
        {
            if (node->keys[i] == key_byte)
            {
                return -3; // Key already exists
            }
            if (node->keys[i] < key_byte)
            {
                insert_pos = i + 1;
            }
        }

        // Используем MCAS для атомарной вставки
        MCAS_EHashDescriptor *desc = MCAS_ehash_create_descriptor(3, (uint64_t)node);

        // Операция 1: увеличение счетчика
        MCAS_ehash_set_operation(desc, 0,
                                 (_Atomic(uint64_t) *)&node->header.count,
                                 current_count, current_count + 1);

        // Операция 2: сдвиг элементов и вставка ключа
        MCAS_ehash_set_operation(desc, 1,
                                 (_Atomic(uint64_t) *)&node->keys[insert_pos],
                                 node->keys[insert_pos], key_byte);

        // Операция 3: установка указателя
        MCAS_ehash_set_operation(desc, 2,
                                 (_Atomic(uint64_t) *)&node->children[insert_pos],
                                 (uint64_t)atomic_load(&node->children[insert_pos]),
                                 (uint64_t)child);

        // Сдвигаем остальные элементы
        for (int i = current_count; i > insert_pos; i--)
        {
            node->keys[i] = node->keys[i - 1];
            art_node *old = atomic_exchange(&node->children[i],
                                            atomic_load(&node->children[i - 1]));
        }

        bool success = MCAS_ehash(desc);
        MCAS_ehash_free_descriptor(desc);

        if (success)
            return 0;
        // Retry if MCAS failed
    }
}

int node16_remove_child(node16 *node, uint8_t key_byte)
{
    if (!node)
        return -1;

    while (true)
    {
        int current_count = atomic_load(&node->header.count);
        if (current_count == 0)
            return -2;

        // Находим позицию для удаления
        int remove_pos = -1;
        for (int i = 0; i < current_count; i++)
        {
            if (node->keys[i] == key_byte)
            {
                remove_pos = i;
                break;
            }
        }
        if (remove_pos == -1)
            return -3;

        // MCAS для атомарного удаления
        MCAS_EHashDescriptor *desc = MCAS_ehash_create_descriptor(2, (uint64_t)node);

        MCAS_ehash_set_operation(desc, 0,
                                 (_Atomic(uint64_t) *)&node->header.count,
                                 current_count, current_count - 1);

        // Сдвигаем элементы
        for (int i = remove_pos; i < current_count - 1; i++)
        {
            node->keys[i] = node->keys[i + 1];
            atomic_store(&node->children[i], atomic_load(&node->children[i + 1]));
        }

        // Очищаем последний элемент
        node->keys[current_count - 1] = 0;
        MCAS_ehash_set_operation(desc, 1,
                                 (_Atomic(uint64_t) *)&node->children[current_count - 1],
                                 (uint64_t)atomic_load(&node->children[current_count - 1]),
                                 (uint64_t)NULL);

        bool success = MCAS_ehash(desc);
        MCAS_ehash_free_descriptor(desc);

        if (success)
            return 0;
    }
}

void node16_print(const node16 *node)
{
    if (!node)
    {
        printf("Node16: NULL\n");
        return;
    }

    printf("Node16: count=%d, prefix_len=%d\n",
           atomic_load(&node->header.count), node->header.prefix_len);
    printf("Keys: ");
    for (int i = 0; i < atomic_load(&node->header.count); i++)
    {
        printf("0x%02x ", node->keys[i]);
    }
    printf("\n");
}