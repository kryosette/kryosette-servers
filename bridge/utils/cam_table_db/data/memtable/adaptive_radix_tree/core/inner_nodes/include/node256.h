#pragma once

#include "inner_node_common.h"

typedef struct node256
{
    inner_node_header header;
    _Atomic(art_node *) children[256];
} node256;

inner_node node256_create();
art_node *node256_find_child(node256 *node, uint8_t key_byte);
int node256_add_child(node256 *node, uint8_t key_byte, art_node *child);
int node256_remove_child(node256 *node, uint8_t key_byte);
inner_node node256_shrink_to_48(node256 *node);
void node256_print(const node256 *node);