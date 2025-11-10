#include "node256.h"
#include <stdlib.h>
#include <string.h>
#include "smemset.h"
#include <stdio.h>

inner_node node256_create()
{
    node256 *node = malloc(sizeof(node256));
    if (!node)
        return NULL;

    node->header.type = NODE256;
    atomic_store(&node->header.count, 0);
    node->header.prefix_len = 0;

    for (int i = 0; i < 256; i++)
    {
        atomic_store(&node->children[i], NULL);
    }

    return (inner_node)node;
}

art_node *node256_find_child(node256 *node, uint8_t key_byte)
{
    if (!node)
        return NULL;
    return atomic_load(&node->children[key_byte]);
}

int node256_add_child(node256 *node, uint8_t key_byte, art_node *child)
{
    if (!node || !child)
        return -1;

    while (true)
    {
        int current_count = atomic_load(&node->header.count);

        // Проверяем, существует ли уже ключ
        if (atomic_load(&node->children[key_byte]) != NULL)
        {
            return -3; // Key already exists
        }

        // MCAS для атомарного добавления
        MCAS_EHashDescriptor *desc = MCAS_ehash_create_descriptor(2, (uint64_t)node);

        MCAS_ehash_set_operation(desc, 0,
                                 (_Atomic(uint64_t) *)&node->header.count,
                                 current_count, current_count + 1);

        MCAS_ehash_set_operation(desc, 1,
                                 (_Atomic(uint64_t) *)&node->children[key_byte],
                                 (uint64_t)atomic_load(&node->children[key_byte]),
                                 (uint64_t)child);

        bool success = MCAS_ehash(desc);
        MCAS_ehash_free_descriptor(desc);

        if (success)
            return 0;
    }
}

int node256_remove_child(node256 *node, uint8_t key_byte)
{
    if (!node)
        return -1;

    while (true)
    {
        int current_count = atomic_load(&node->header.count);
        if (current_count == 0)
            return -2;

        if (atomic_load(&node->children[key_byte]) == NULL)
        {
            return -3; // Key not found
        }

        // MCAS для атомарного удаления
        MCAS_EHashDescriptor *desc = MCAS_ehash_create_descriptor(2, (uint64_t)node);

        MCAS_ehash_set_operation(desc, 0,
                                 (_Atomic(uint64_t) *)&node->header.count,
                                 current_count, current_count - 1);

        MCAS_ehash_set_operation(desc, 1,
                                 (_Atomic(uint64_t) *)&node->children[key_byte],
                                 (uint64_t)atomic_load(&node->children[key_byte]),
                                 (uint64_t)NULL);

        bool success = MCAS_ehash(desc);
        MCAS_ehash_free_descriptor(desc);

        if (success)
            return 0;
    }
}

void node256_print(const node256 *node)
{
    if (!node)
    {
        printf("Node256: NULL\n");
        return;
    }

    printf("Node256: count=%d, prefix_len=%d\n",
           atomic_load(&node->header.count), node->header.prefix_len);

    int key_count = 0;
    printf("Active keys: ");
    for (int i = 0; i < 256; i++)
    {
        if (atomic_load(&node->children[i]) != NULL)
        {
            printf("0x%02x ", i);
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