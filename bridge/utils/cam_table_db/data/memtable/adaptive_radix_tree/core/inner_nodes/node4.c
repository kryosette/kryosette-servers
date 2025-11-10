#include "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/utils/cam_table_db/data/memtable/adaptive_radix_tree/core/inner_nodes/include/node4.h"
#include <stdlib.h>
#include <string.h>
#include "/mnt/c/Users/dmako/kryosette/kryosette-servers/third-party/smemset/include/smemset.h"
#include <stdio.h>
/*
ART is a prefix tree (radix tree) that:

    Stores keys in sorted order

    Uses adaptive nodes of different sizes

    Applies path compression to save memory

    Uses lazy expansion to reduce the height of the tree
*/
inner_node node4_create()
{
    node4 *node = malloc(sizeof(node4));
    if (!node)
    {
        return NULL;
    }

    node->header.type = NODE4;
    atomic_store(&node->header.count, 0);
    node->header.prefix_len = 0;
    smemset(node->keys, 0, 4);
    /*
    like:
    for (int i = 0; i < 4; i++) {
        node->children[i] = NULL;
    }
    */
    for (int i = 0; i < 4; i++)
    {
        atomic_store(&node->children[i], NULL);
    } // zeroing out
    return (inner_node)node;
}

// void node4_free(node4 *node)
// {
//     art_node_free_iterative((art_node *)node);
// }

art_node *node4_find_child(node4 *node, uint8_t key_byte)
{
    if (!node)
    {
        return NULL;
    }

    int count = atomic_load(&node->header.count);

    for (int i = 0; i < count; i++)
    {
        if (node->keys[i] == key_byte)
        {
            return atomic_load(&node->children[i]);
        }
    }

    return NULL;
}

/*
node4
     key       child pointer
 0  1  2   3   0 1 2 3
[0][2][3][255][][][][]
              ⭣ ⭣ ⭣ ⭣
              a b c d

Error Codes:

    0: Success

    -1: Invalid parameters (NULL pointer)

    -2: Capacity exceeded or empty node

    -3: Key already exists or not found
*/
int node4_add_child(node4 *node, uint8_t key_byte, art_node *child)
{
    if (!node || !child)
    {
        return -1;
    }

    while (true)
    {
        int current_count = atomic_load(&node->header.count);

        if (current_count >= 4)
        {
            return -2; // Нужно увеличить размер узла
        }

        for (int i = 0; i < current_count; i++)
        {
            if (node->keys[i] == key_byte)
            {
                return -3;
            }
        }

        int insert_pos = 0;
        while (insert_pos < current_count && node->keys[insert_pos] < key_byte)
        {
            insert_pos++;
        }

        MCAS_EHashDescriptor *desc = MCAS_ehash_create_descriptor(3, (uint64_t)node);

        MCAS_ehash_set_operation(desc, 0,
                                 (_Atomic(uint64_t) *)&node->header.count,
                                 current_count, current_count + 1);

        MCAS_ehash_set_operation(desc, 1,
                                 (_Atomic(uint64_t) *)&node->keys[insert_pos],
                                 node->keys[insert_pos], key_byte);

        MCAS_ehash_set_operation(desc, 2,
                                 (_Atomic(uint64_t) *)&node->children[insert_pos],
                                 (uint64_t)atomic_load(&node->children[insert_pos]),
                                 (uint64_t)child);

        bool success = MCAS_ehash(desc);
        MCAS_ehash_free_descriptor(desc);

        if (success)
        {
            return 0;
        }
    }
}

int node4_add_child(node4 *node, uint8_t key_byte, art_node *child)
{
    if (!node || !child)
    {
        return -1;
    }

    while (true)
    {
        int current_count = atomic_load(&node->header.count);

        if (current_count >= 4)
        {
            return -2;
        }

        for (int i = 0; i < current_count; i++)
        {
            if (node->keys[i] == key_byte)
            {
                return -3;
            }
        }

        int insert_pos = 0;
        while (insert_pos < current_count && node->keys[insert_pos] < key_byte)
        {
            insert_pos++;
        }

        if (!CAS(&node->header.count, current_count, current_count + 1))
        {
            continue;
        }

        for (int i = current_count; i > insert_pos; i--)
        {
            node->keys[i] = node->keys[i - 1];
            art_node *old_child = atomic_exchange(&node->children[i],
                                                  atomic_load(&node->children[i - 1]));
        }

        node->keys[insert_pos] = key_byte;
        atomic_store(&node->children[insert_pos], child);

        return 0;
    }
}

// inner_node node4_grow_to_16(node4 *node)
// {
//     if (!node)
//     {
//         return NULL;
//     }

//     node16 *new_node = malloc(sizeof(node16));
//     if (!new_node)
//     {
//         return NULL;
//     }

//     new_node->header.type = NODE16;
//     new_node->header.count = node->header.count;
//     new_node->header.prefix_len = node->header.prefix_len;

//     if (node->header.prefix_len > 0)
//     {
//         memcpy(new_node->prefix, node->prefix, node->header.prefix_len);
//     }

//     smemset(new_node->keys, 0, 16);
//     smemset(new_node->children, 0, 16 * sizeof(art_node *));

//     for (int i = 0; i < node->header.count; i++)
//     {
//         new_node->keys[i] = node->keys[i];
//         new_node->children[i] = node->children[i];
//     }

//     free(node);

//     return (inner_node)new_node;
// }

// Additional helper function for debugging
void node4_print(const node4 *node)
{
    if (!node)
    {
        printf("Node4: NULL\n");
        return;
    }

    printf("Node4: count=%d, prefix_len=%d\n", node->header.count, node->header.prefix_len);
    printf("Keys: ");
    for (int i = 0; i < node->header.count; i++)
    {
        printf("[%d]=0x%02x ", i, node->keys[i]);
    }
    printf("\n");

    printf("Children: ");
    for (int i = 0; i < node->header.count; i++)
    {
        printf("[%d]=%p ", i, (void *)node->children[i]);
    }
    printf("\n");
}