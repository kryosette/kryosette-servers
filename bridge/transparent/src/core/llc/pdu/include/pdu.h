#pragma once
#ifndef PDU_H
#define PDU_H

#include <cstdint>
#include <cstddef>

struct dsap_address
{
    bool is_group : 1;
    uint8_t address : 7;
};

struct ssap_address
{
    bool is_response : 1;
    uint8_t address : 7;
};

struct supervisory_type
{
    uint8_t pr : 2;
    uint8_t rej : 2;
    uint8_t rnr : 2;
};

union control_field
{
    uint16_t full_word;

    struct
    {
        uint8_t receive_sequence : 7;
        bool poll_final : 1;
        uint8_t send_sequence : 7;
        uint8_t format : 1;
    } information;

    struct
    {
        uint8_t modifier_bits : 2;
        uint8_t format : 2;
        uint8_t command_type : 4;
    } unnumbered;

    struct
    {
        uint8_t receive_sequence : 7;
        bool poll_final : 1;
        uint8_t reserved : 2;
        supervisory_type type;
        uint8_t format : 2;
    } supervisory;
};

struct info_field
{
    uint8_t *data;
    size_t length;
};

struct llc_pdu
{
    dsap_address dsap;
    ssap_address ssap;
    control_field control;
    info_field information;
};

#endif