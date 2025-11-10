#pragma once

#include "inner_node_common.h"

typedef struct node48
{
    inner_node_header header;
    uint8_t keys[256]; // key_byte -> index in children
    _Atomic(art_node *) children[48];
} node48;

inner_node node48_create();
art_node *node48_find_child(node48 *node, uint8_t key_byte);
int node48_add_child(node48 *node, uint8_t key_byte, art_node *child);
int node48_remove_child(node48 *node, uint8_t key_byte);
inner_node node48_grow_to_256(node48 *node);
inner_node node48_shrink_to_16(node48 *node);
void node48_print(const node48 *node);