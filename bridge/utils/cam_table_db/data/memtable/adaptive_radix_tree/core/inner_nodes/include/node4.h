#pragma once

#include "inner_node_common.h"

#define LEAF_NODE 255

typedef struct node4
{
    inner_node_header header;
    uint8_t keys[4];
    art_node *children[4];
} node4;

typedef struct leaf_node
{
    inner_node_header header;
    char value[32];
} leaf_node;

inner_node node4_create();
void node4_free(node4 *node);
art_node *node4_find_child(node4 *node, uint8_t key_byte);
int node4_add_child(node4 *node, uint8_t key_byte, art_node *child);
int node4_remove_child(node4 *node, uint8_t key_byte);
inner_node node4_grow_to_16(node4 *node);