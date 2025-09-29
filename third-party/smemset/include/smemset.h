#ifndef SMEMSET_H
#define SMEMSET_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    void *smemset(void *dstpp, int c, size_t len);

#ifdef REPLACE_STANDARD_MEMSET
#undef memset
#define memset smemset
#endif

#ifdef __cplusplus
}
#endif

#endif