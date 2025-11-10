#pragma once

#include "inner_node_common.h"

typedef struct node16
{
    inner_node_header header;
    uint8_t keys[16];
    _Atomic(art_node *) children[16];
} node16;

inner_node node16_create();
art_node *node16_find_child(node16 *node, uint8_t key_byte);
int node16_add_child(node16 *node, uint8_t key_byte, art_node *child);
int node16_remove_child(node16 *node, uint8_t key_byte);
inner_node node16_grow_to_48(node16 *node);
inner_node node16_shrink_to_4(node16 *node);
void node16_print(const node16 *node);