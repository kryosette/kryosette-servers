#pragma once

#include <stdint.h>
#include <stddef.h>

typedef struct inner_node_header
{
    uint8_t type;
    uint8_t count;
    uint8_t prefix_len;
    uint8_t reserved;
    uint32_t prefix[2];
} inner_node_header;

typedef enum
{
    NODE4 = 1,
    NODE16 = 2,
    NODE48 = 3,
    NODE256 = 4
} node_type;

typedef struct inner_node_header *inner_node;

typedef struct art_leaf art_leaf;

typedef void *art_node;

inner_node inner_node_create(uint8_t type);
void inner_node_free(inner_node node);
art_node *inner_node_find_child(inner_node node, uint8_t key_byte);
int inner_node_add_child(inner_node *node_ref, uint8_t key_byte, art_node child);
int inner_node_remove_child(inner_node node, uint8_t key_byte);