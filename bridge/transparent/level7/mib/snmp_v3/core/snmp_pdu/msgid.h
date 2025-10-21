#pragma once
#ifndef SNMP_MSGID_H
#define SNMP_MSGID_H

#include <stdint.h>
#include <stdatomic.h>

uint32_t snmp_generate_msgid(void);

int snmp_msgid_is_replayed(uint32_t msgid);

#endif
