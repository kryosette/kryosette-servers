#include "node48.h"
#include <stdlib.h>
#include <string.h>
#include "smemset.h"
#include <stdio.h>

inner_node node48_create()
{
    node48 *node = malloc(sizeof(node48));
    if (!node)
        return NULL;

    node->header.type = NODE48;
    atomic_store(&node->header.count, 0);
    node->header.prefix_len = 0;

    // Инициализируем keys как "невалидные" индексы
    smemset(node->keys, 48, 256); // 48 = invalid index (больше чем 47)

    for (int i = 0; i < 48; i++)
    {
        atomic_store(&node->children[i], NULL);
    }

    return (inner_node)node;
}

art_node *node48_find_child(node48 *node, uint8_t key_byte)
{
    if (!node)
        return NULL;

    uint8_t index = node->keys[key_byte];
    if (index < 48)
    { // Valid index
        return atomic_load(&node->children[index]);
    }
    return NULL;
}

int node48_add_child(node48 *node, uint8_t key_byte, art_node *child)
{
    if (!node || !child)
        return -1;

    while (true)
    {
        int current_count = atomic_load(&node->header.count);

        if (current_count >= 48)
            return -2;

        // Проверяем, существует ли уже ключ
        if (node->keys[key_byte] < 48)
        {
            return -3; // Key already exists
        }

        // Находим свободный слот в children
        int free_slot = -1;
        for (int i = 0; i < 48; i++)
        {
            if (atomic_load(&node->children[i]) == NULL)
            {
                free_slot = i;
                break;
            }
        }

        if (free_slot == -1)
            return -2; // No free slots

        // MCAS для атомарного добавления
        MCAS_EHashDescriptor *desc = MCAS_ehash_create_descriptor(3, (uint64_t)node);

        MCAS_ehash_set_operation(desc, 0,
                                 (_Atomic(uint64_t) *)&node->header.count,
                                 current_count, current_count + 1);

        MCAS_ehash_set_operation(desc, 1,
                                 (_Atomic(uint64_t) *)&node->keys[key_byte],
                                 node->keys[key_byte], free_slot);

        MCAS_ehash_set_operation(desc, 2,
                                 (_Atomic(uint64_t) *)&node->children[free_slot],
                                 (uint64_t)atomic_load(&node->children[free_slot]),
                                 (uint64_t)child);

        bool success = MCAS_ehash(desc);
        MCAS_ehash_free_descriptor(desc);

        if (success)
            return 0;
    }
}

int node48_remove_child(node48 *node, uint8_t key_byte)
{
    if (!node)
        return -1;

    while (true)
    {
        int current_count = atomic_load(&node->header.count);
        if (current_count == 0)
            return -2;

        uint8_t index = node->keys[key_byte];
        if (index >= 48)
            return -3; // Key not found

        // MCAS для атомарного удаления
        MCAS_EHashDescriptor *desc = MCAS_ehash_create_descriptor(3, (uint64_t)node);

        MCAS_ehash_set_operation(desc, 0,
                                 (_Atomic(uint64_t) *)&node->header.count,
                                 current_count, current_count - 1);

        MCAS_ehash_set_operation(desc, 1,
                                 (_Atomic(uint64_t) *)&node->keys[key_byte],
                                 index, 48); // 48 = invalid

        MCAS_ehash_set_operation(desc, 2,
                                 (_Atomic(uint64_t) *)&node->children[index],
                                 (uint64_t)atomic_load(&node->children[index]),
                                 (uint64_t)NULL);

        bool success = MCAS_ehash(desc);
        MCAS_ehash_free_descriptor(desc);

        if (success)
            return 0;
    }
}

void node48_print(const node48 *node)
{
    if (!node)
    {
        printf("Node48: NULL\n");
        return;
    }

    printf("Node48: count=%d, prefix_len=%d\n",
           atomic_load(&node->header.count), node->header.prefix_len);

    int key_count = 0;
    printf("Active keys: ");
    for (int i = 0; i < 256; i++)
    {
        if (node->keys[i] < 48)
        {
            printf("0x%02x->[%d] ", i, node->keys[i]);
            key_count++;
            if (key_count > 20)
            {
                printf("...");
                break;
            }
        }
    }
    printf("\n");
}