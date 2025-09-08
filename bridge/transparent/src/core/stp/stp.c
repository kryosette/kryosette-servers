#include "stp.h"

struct stp_instance *stp;
struct mac_table_t *mac;

void stp_init(struct stp_instance *stp, uint8_t *mac) {
  if (stp == NULL) {
    return NULL;
  }
}
