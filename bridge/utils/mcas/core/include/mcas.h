#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

// CAS1 - hardware primitive (wrapper)
static inline bool CAS(int *ptr, int expected, int new_val)
{
    return atomic_compare_exchange_strong((atomic_int *)ptr, &expected, new_val);
}

/* initialy: exist CAS2 (which acts on two arbitrary memory locations) *https://en.wikipedia.org/wiki/Double_compare-and-swap
work: DCAS takes two not necessarily **contiguous** memory locations and writes new values into them only if they match pre-supplied "expected" values;
as such, it is an extension of the much more popular compare-and-swap (CAS) operation.

**Contiguous Memory Allocation:**
[ Block 1 ][ Block 2 ][ Block 3 ][ Block 4 ]

**Non-Contiguous Memory Allocation:**
[ Block 1 ]     [ Block 3 ]
      [ Block 2 ]     [ Block 4 ]

build: CAS → CAS2 → CASN → MCAS

i - index
More precisely, MCAS is defined to operate on N distinct memory locations (ai), expected values (ei), and new values (ni): each ai is updated to
value ni if and only if each ai contains the expected value ei before the operation. (https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-579.pdf (30 page))
*/
typedef struct
{
    int *addr1;
    int expected1;
    int new_val1;
    int *addr2;
    int expected2;
    int new_val2;
    atomic_int status; // 0 - pending, 1 - success, 2 - failed
} CAS2_Descriptor;

// CAS2 - built from CAS1
bool CAS2_ehash(int *addr1, int expected1, int new_val1,
                int *addr2, int expected2, int new_val2);

typedef struct
{
    int *addr;
    int expected;
    int new_val;
} CAS_Operation;

typedef struct
{
    CAS_Operation *operations;
    int count;
    atomic_int status;
} CASN_Descriptor;

bool CASN(CASN_Descriptor *desc);

bool MCAS(CASN_Descriptor *desc);