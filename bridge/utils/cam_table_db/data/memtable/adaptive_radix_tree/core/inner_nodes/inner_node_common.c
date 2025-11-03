#include "node4.h"
#include <stdlib.h>
#include <string.h>
#include "third-party\smemset\include\smemset.h"

void art_node_free(art_node node)
{
    if (!node)
        return;

    switch (node->type)
    {
    case NODE4:
        node4_free((node4 *)node);
        break;
    case NODE16:
        node16_free((node16 *)node);
        break;
    case NODE48:
        node48_free((node48 *)node);
        break;
    case NODE256:
        node256_free((node256 *)node);
        break;
    }
}

void art_node_free_iterative(art_node *start_node)
{
    if (!start_node)
        return;

    art_node **stack = malloc(1024 * sizeof(art_node *));
    int index = 0;

    stack[index++] = start_node;

    while (index > 0)
    {
        art_node *curr = stack[--index];

        if (is_leaf(curr))
        {
            leaf_free((art_leaf *)curr);
        }
        else
        {
            inner_node *inner = (inner_node *)curr;

            for (int i = 0; i < inner->header.count; i++)
            {
                if (inner->children[i] && index < 1024)
                {
                    stack[index++] = inner->children[i];
                }
            }

            free(inner);
        }
    }

    free(stack);
}
