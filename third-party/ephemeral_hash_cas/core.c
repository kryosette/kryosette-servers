#include "core.h"
#include <stdlib.h>

// ==================== Hash Generator Implementation ====================

void hash_generator_init(HashGenerator *gen, uint64_t seed)
{
    atomic_store(&gen->state, seed);
}

uint16_t hash_generator_next(HashGenerator *gen)
{
    uint64_t old_state = atomic_load(&gen->state);
    uint64_t new_state;
    uint16_t hash;

    do
    {
        // Xorshift64* PRNG
        new_state = old_state;
        new_state ^= new_state >> 12;
        new_state ^= new_state << 25;
        new_state ^= new_state >> 27;
        hash = (uint16_t)((new_state * 0x2545F4914F6CDD1DULL) >> 48);
    } while (!atomic_compare_exchange_strong(&gen->state, &old_state, new_state));

    return hash;
}

// ==================== Lock-Free Stack Implementation ====================

void ehash_stack_init(EHashStack *stack, uint64_t seed)
{
    atomic_store(&stack->head, 0);
    hash_generator_init(&stack->hash_gen, seed);
}

void ehash_stack_push(EHashStack *stack, EHashStackNode *node)
{
    EHashPtr old_head, new_head;

    do
    {
        old_head = EHash_load(&stack->head);
        node->next = (EHashStackNode *)ehash_get_ptr(old_head);
        new_head = make_ehash_ptr(node, hash_generator_next(&stack->hash_gen));
    } while (!EHash_CAS(&stack->head, old_head, new_head));
}

EHashStackNode *ehash_stack_pop(EHashStack *stack)
{
    EHashPtr old_head, new_head;
    EHashStackNode *node;

    do
    {
        old_head = EHash_load(&stack->head);
        node = (EHashStackNode *)ehash_get_ptr(old_head);
        if (node == NULL)
        {
            return NULL;
        }

        EHashStackNode *next_node = node->next;
        new_head = make_ehash_ptr(next_node, hash_generator_next(&stack->hash_gen));
    } while (!EHash_CAS(&stack->head, old_head, new_head));

    return node;
}

// ==================== Utility Functions ====================

uint64_t ehash_to_uint64(EHashPtr p)
{
    return ((uint64_t)p.hash << 48) | (p.ptr & 0xFFFFFFFFFFFF);
}

EHashPtr ehash_from_uint64(uint64_t val)
{
    return (EHashPtr){val & 0xFFFFFFFFFFFF, (uint16_t)((val >> 48) & 0xFFFF)};
}