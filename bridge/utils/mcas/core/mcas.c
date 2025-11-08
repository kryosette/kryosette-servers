#include "mcas.h"
#include "core.h"
#include <stdlib.h>
#include <stdio.h>

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