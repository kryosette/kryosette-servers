#include "stp.h"

struct stp_instance *stp;
struct mac_table_t *mac;

int bridge_id_compare(const struct bridge_id *a, const struct bridge_id *b) {
    if (a->priority != b->priority) {
        return a->priority - b->priority;
    }
    return memcmp(a->mac, b->mac, 6);
}

void init_bridge_id(struct bridge_id *bid, uint16_t priority, const uint8_t *mac) {
    bid->priority = priority;
    memcpy(bid->mac, mac, 6);
}

void stp_init(struct stp_instance *stp, uint8_t *mac) {
  if (stp == NULL) {
    return NULL;
  }
}
