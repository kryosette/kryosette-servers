#ifndef ISS_H
#define ISS_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>

typedef enum {
    MA_DATA_REQUEST,
    MA_DATA_INDICATION,
    MA_CONTROL_REQUEST,
    MA_CONTROL_INDICATION
} iss_primitive_t;

struct iss_data_unit {
    unsigned char *destination_addr;
    unsigned char *source_addr;
    uint16_t ethertype;
    unsigned char *data;
    size_t data_length;
    uint8_t priority;
    void *upper_layer_context;
};

typedef enum {
    SECURITY_POLICY_BYPASS,      // Пропуск без защиты
    SECURITY_POLICY_AUTHENTICATE, // Только аутентификация
    SECURITY_POLICY_ENCRYPT,      // Шифрование + аутентификация
    SECURITY_POLICY_DROP          // Блокировка
} security_policy_t;

struct security_context {
    security_policy_t policy;
    uint8_t *key;
    size_t key_length;
    uint32_t security_association_id;
    bool is_secure_iss;
};

struct iss_instance {
    char interface_name[IFNAMSIZ];
    struct security_context sec_ctx;
    bool is_enabled;
    uint32_t frame_counter;
    
    uint64_t protected_frames_out;
    uint64_t protected_frames_in;
    uint64_t dropped_frames;
    
    int (*original_ma_data_request)(struct iss_data_unit *sdu);
    int (*original_ma_data_indication)(struct iss_data_unit *sdu);
};


int iss_init(const char *interface_name, struct iss_instance **iss);
void iss_cleanup(struct iss_instance *iss);

int iss_ma_data_request(struct iss_instance *iss, struct iss_data_unit *sdu);
int iss_ma_data_indication(struct iss_instance *iss, struct iss_data_unit *sdu);
int iss_ma_control_request(struct iss_instance *iss, uint32_t control_code, void *param);
int iss_ma_control_indication(struct iss_instance *iss, uint32_t indication_code, void *param);

int iss_set_security_policy(struct iss_instance *iss, security_policy_t policy, 
                           const uint8_t *key, size_t key_len);
int iss_enable_security(struct iss_instance *iss);
int iss_disable_security(struct iss_instance *iss);

security_policy_t iss_classify_traffic(const struct iss_data_unit *sdu);
void iss_update_statistics(struct iss_instance *iss, bool is_outgoing, bool is_protected);

int iss_register_driver_callbacks(struct iss_instance *iss,
                                 int (*data_req)(struct iss_data_unit *),
                                 int (*data_ind)(struct iss_data_unit *));
#endif /* ISS_H */
