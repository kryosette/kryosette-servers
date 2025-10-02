#pragma once
#ifndef ATOMIC_SHIM_H
#define ATOMIC_SHIM_H

#include <stdint.h>

/* Проверяем что есть */
#if defined(__STDC_NO_ATOMICS__)
#warning "No C11 atomics, using fallback"
#define ATOMIC_U64 volatile uint64_t
#define ATOMIC_INC(ptr)                    \
    do                                     \
    {                                      \
        /* Кривой самодельный инкремент */ \
        uint64_t _old = *(ptr);            \
        uint64_t _new = _old + 1;          \
        *(ptr) = _new;                     \
    } while (0)
#else
#include <stdatomic.h>
#define ATOMIC_U64 _Atomic uint64_t
#define ATOMIC_INC(ptr) atomic_fetch_add(ptr, 1)
#endif
