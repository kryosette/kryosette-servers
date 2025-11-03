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
    node->header.count = 0;
    node->header.prefix_len = 0;
    smemset(node->keys, 0, 4);
    /*
    like:
    for (int i = 0; i < 4; i++) {
        node->children[i] = NULL;
    }
    */
    smemset(node->children, 0, 4 * sizeof(art_node *)); // zeroing out
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

    for (int i = 0; i < node->header.count; i++)
    {
        if (node->keys[i] == key_byte)
        {
            return node->children[i];
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

    if (node->header.count >= 4)
    {
        return -2;
    }

    for (int i = 0; i < node->header.count; i++)
    {
        if (node->keys[i] == key_byte)
        {
            return -3;
        }
    }

    // Find insertion position to maintain sorted order
    int insert_pos = 0;
    while (insert_pos < node->header.count && node->keys[insert_pos] < key_byte)
    {
        insert_pos++;
    }

    // Shift existing elements to make space
    for (int i = node->header.count; i > insert_pos; i--)
    {
        node->keys[i] = node->keys[i - 1];
        node->children[i] = node->children[i - 1];
    }

    // Insert new key and child
    node->keys[insert_pos] = key_byte;
    node->children[insert_pos] = child;
    node->header.count++;

    return 0;
}

int node4_remove_child(node4 *node, uint8_t key_byte)
{
    if (!node)
    {
        return -1;
    }

    if (node->header.count == 0)
    {
        return -2;
    }

    // Find the key to remove
    int remove_pos = -1;
    for (int i = 0; i < node->header.count; i++)
    {
        if (node->keys[i] == key_byte)
        {
            remove_pos = i;
            break;
        }
    }

    if (remove_pos == -1)
    {
        return -3;
    }

    // Shift elements to fill the gap
    for (int i = remove_pos; i < node->header.count - 1; i++)
    {
        node->keys[i] = node->keys[i + 1];
        node->children[i] = node->children[i + 1];
    }

    // Clear the last element
    node->keys[node->header.count - 1] = 0;
    node->children[node->header.count - 1] = NULL;
    node->header.count--;

    return 0;
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