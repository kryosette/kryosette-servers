#include "msgid.h"

static _Atomic uint32_t msgid_counter = 0;

uint32_t snmp_generate_msgid(void) {
    // RFC: "MUST be chosen to avoid replay attacks"
    // RFC: "values do not need to be unpredictable"
    return atomic_fetch_add(&msgid_counter, 1) + 1;
}

int snmp_msgid_is_replayed(uint32_t msgid) {
    // TODO: реализовать кеш последних N msgID
    // Пока всегда возвращаем "не повтор"
    return 0;
}
