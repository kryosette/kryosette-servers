#include "mcas.h"
#include "core.h"
#include <stdlib.h>
#include <stdio.h>

// ==================== CAS2 with Ephemeral Hash ====================

bool CAS2_ehash(int *addr1, int expected1, int new_val1,
                int *addr2, int expected2, int new_val2)
{
    CAS2_Descriptor *desc = malloc(sizeof(CAS2_Descriptor));
    desc->addr1 = addr1;
    desc->expected1 = expected1;
    desc->new_val1 = new_val1;
    desc->addr2 = addr2;
    desc->expected2 = expected2;
    desc->new_val2 = new_val2;
    atomic_store(&desc->status, 0);

    /* We are trying to atomically replace the value in addr1 with a pointer to our descriptor.
    If there was a number in the cell, we change it to an address (pointer).
    like:
    before:       after:
    a = 42      a = 0x5678   ← NUMBER replaced with ADDRESS!
    b = 100     b = 100
    */
    if (!CAS(addr1, expected1, (int)desc))
    {
        int curr = atomic_load((atomic_int *)addr1); // atomically reads the value of a variable
        if (curr == (int)desc)
        {
            // Another thread already installed our descriptor - help complete
            atomic_store(&desc->status, 1);

            // Complete second operation
            CAS(addr2, expected2, new_val2);

            free(desc);
            return true;
        }
        free(desc);
        return false;
    }

    // Descriptor successfully installed - perform second operation
    bool success = CAS(addr2, expected2, new_val2);

    // Update status and restore first location
    atomic_store(&desc->status, success ? 1 : 2);
    CAS(addr1, (int)desc, success ? new_val1 : expected1);

    free(desc);
    return success;
}

// ==================== CASN Implementation ====================

bool CASN(CASN_Descriptor *desc)
{
    atomic_store(&desc->status, 0); // pending

    // Process operations in pairs using CAS2
    for (int i = 0; i < desc->count; i += 2)
    {
        if (i + 1 < desc->count)
        {
            // Process pair with CAS2
            if (!CAS2_ehash(desc->operations[i].addr,
                            desc->operations[i].expected,
                            desc->operations[i].new_val,
                            desc->operations[i + 1].addr,
                            desc->operations[i + 1].expected,
                            desc->operations[i + 1].new_val))
            {
                atomic_store(&desc->status, 2); // failed
                return false;
            }
        }
        else
        {
            // Single operation - use CAS directly
            if (!CAS(desc->operations[i].addr,
                     desc->operations[i].expected,
                     desc->operations[i].new_val))
            {
                atomic_store(&desc->status, 2); // failed
                return false;
            }
        }
    }

    atomic_store(&desc->status, 1); // success
    return true;
}

bool MCAS(CASN_Descriptor *desc)
{
    return CASN(desc);
}

// ==================== Ephemeral Hash MCAS Implementation ====================

bool MCAS_ehash(MCAS_EHashDescriptor *desc)
{
    // Initialize status to pending
    atomic_store(&desc->status, 0);

    // Try to acquire all locations by replacing them with our descriptor pointer
    for (int i = 0; i < desc->count; i++)
    {
        MCAS_EHashOperation *op = &desc->operations[i];
        EHashPtr expected = ehash_from_uint64(op->expected);
        EHashPtr new_val = make_ehash_ptr(desc, hash_generator_next(&desc->hash_gen));

        while (true)
        {
            EHashPtr current = EHash_load(op->addr);

            // If we see our own descriptor, help complete the operation
            if (ehash_get_ptr(current) == desc)
            {
                break;
            }

            // If we see another descriptor, help complete it first
            if (ehash_get_ptr(current) != NULL && ehash_get_ptr(current) != (void *)op->expected)
            {
                MCAS_EHashDescriptor *other_desc = (MCAS_EHashDescriptor *)ehash_get_ptr(current);

                // Help complete the other operation
                if (atomic_load(&other_desc->status) == 0)
                {
                    for (int j = 0; j < other_desc->count; j++)
                    {
                        MCAS_EHashOperation *other_op = &other_desc->operations[j];
                        if (atomic_load(&other_desc->status) == 0)
                        {
                            EHash_CAS(other_op->addr,
                                      make_ehash_ptr(other_desc, current.hash),
                                      ehash_from_uint64(other_op->new_val));
                        }
                    }
                    atomic_store(&other_desc->status, 1);
                }
                continue;
            }

            // Try to install our descriptor
            if (EHash_CAS(op->addr, expected, new_val))
            {
                break;
            }

            // CAS failed, reload expected value
            expected = ehash_from_uint64(op->expected);
        }
    }

    // All locations acquired, now perform the actual updates
    bool success = true;
    for (int i = 0; i < desc->count; i++)
    {
        MCAS_EHashOperation *op = &desc->operations[i];

        // For the actual update, we need to be more careful
        // We'll use the fact that we own these locations now
        EHashPtr current = EHash_load(op->addr);
        if (ehash_get_ptr(current) != desc)
        {
            success = false;
            break;
        }

        EHashPtr new_val_ehash = ehash_from_uint64(op->new_val);
        if (!EHash_CAS(op->addr, current, new_val_ehash))
        {
            success = false;
            break;
        }
    }

    // Update status
    atomic_store(&desc->status, success ? 1 : 2);

    // Cleanup: restore original values on failure
    if (!success)
    {
        for (int i = 0; i < desc->count; i++)
        {
            MCAS_EHashOperation *op = &desc->operations[i];
            EHashPtr current = EHash_load(op->addr);
            if (ehash_get_ptr(current) == desc)
            {
                EHashPtr original = ehash_from_uint64(op->expected);
                EHash_CAS(op->addr, current, original);
            }
        }
    }

    return success;
}

// ==================== Utility Functions ====================

MCAS_EHashDescriptor *MCAS_ehash_create_descriptor(int count, uint64_t seed)
{
    MCAS_EHashDescriptor *desc = malloc(sizeof(MCAS_EHashDescriptor));
    desc->operations = malloc(sizeof(MCAS_EHashOperation) * count);
    desc->count = count;
    atomic_store(&desc->status, 0);
    hash_generator_init(&desc->hash_gen, seed);
    return desc;
}

void MCAS_ehash_free_descriptor(MCAS_EHashDescriptor *desc)
{
    if (desc)
    {
        free(desc->operations);
        free(desc);
    }
}

void MCAS_ehash_set_operation(MCAS_EHashDescriptor *desc, int index,
                              _Atomic(uint64_t) *addr, uint64_t expected, uint64_t new_val)
{
    if (index < desc->count)
    {
        desc->operations[index].addr = addr;
        desc->operations[index].expected = expected;
        desc->operations[index].new_val = new_val;
    }
}