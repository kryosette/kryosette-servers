#pragma once
#ifndef SNMP_PDU_H
#define SNMP_PDU_H

#include <stdint.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==================== PDU Types ====================
#define SNMP_MSG_GET         0xA0
#define SNMP_MSG_GETNEXT     0xA1
#define SNMP_MSG_RESPONSE    0xA2
#define SNMP_MSG_SET         0xA3
#define SNMP_MSG_GETBULK     0xA5
#define SNMP_MSG_INFORM      0xA6
#define SNMP_MSG_TRAP2       0xA7
#define SNMP_MSG_REPORT      0xA8

// ==================== ASN.1 Types ====================
#define ASN_BOOLEAN          0x01
#define ASN_INTEGER          0x02
#define ASN_BIT_STR          0x03
#define ASN_OCTET_STR        0x04
#define ASN_NULL             0x05
#define ASN_OBJECT_ID        0x06
#define ASN_SEQUENCE         0x30
#define ASN_IPADDRESS        (0x00 | 0x40)
#define ASN_COUNTER          (0x01 | 0x40)
#define ASN_GAUGE            (0x02 | 0x40)
#define ASN_TIMETICKS        (0x03 | 0x40)
#define ASN_OPAQUE           (0x04 | 0x40)
#define ASN_COUNTER64        (0x06 | 0x40)

// ==================== Error Codes ====================
#define SNMP_ERR_NOERROR              0
#define SNMP_ERR_TOOBIG               1
#define SNMP_ERR_NOSUCHNAME           2
#define SNMP_ERR_BADVALUE             3
#define SNMP_ERR_READONLY             4
#define SNMP_ERR_GENERR               5
#define SNMP_ERR_NOACCESS             6
#define SNMP_ERR_WRONGTYPE            7
#define SNMP_ERR_WRONGLENGTH          8
#define SNMP_ERR_WRONGENCODING        9
#define SNMP_ERR_WRONGVALUE           10
#define SNMP_ERR_NOCREATION           11
#define SNMP_ERR_INCONSISTENTVALUE    12
#define SNMP_ERR_RESOURCEUNAVAILABLE  13
#define SNMP_ERR_COMMITFAILED         14
#define SNMP_ERR_UNDOFAILED           15
#define SNMP_ERR_AUTHORIZATION        16
#define SNMP_ERR_NOTWRITABLE          17
#define SNMP_ERR_INCONSISTENTNAME     18

// ==================== Structures ====================
typedef uint32_t oid;

struct variable_list {
    oid *name;
    size_t name_length;
    u_char type;
    union {
        int32_t integer;
        u_char *string;
        oid *objid;
        uint8_t ipaddress[4];
        uint32_t counter;
        uint32_t gauge;
        uint32_t timeticks;
        uint64_t counter64;
        void *arbitrary;
    } val;
    size_t val_len;
    struct variable_list *next_variable;
    void *data;
    size_t data_len;
};

typedef struct snmp_pdu {
    // Basic PDU fields
    int command;
    uint32_t reqid;
    uint32_t errstat;
    uint32_t errindex;
    struct variable_list *variables;
    
    // SNMPv3 specific fields
    u_char *contextEngineID;
    size_t contextEngineIDLen;
    char *contextName;
    
    // Message ID for correlation
    int32_t msgID;
    int msgMaxSize;
    u_char msgFlags;
    int securityModel;
    
    // Timing
    struct timeval timestamp;
    uint32_t engineBoots;
    uint32_t engineTime;
    
    // Internal use
    void *transport_data;
    size_t transport_data_len;
} snmp_pdu_t;

// ==================== Function Prototypes ====================

// PDU creation and destruction
snmp_pdu_t *snmp_pdu_create(int pdu_type);
void snmp_pdu_free(snmp_pdu_t *pdu);
snmp_pdu_t *snmp_pdu_clone(const snmp_pdu_t *src);

// Variable management
int snmp_pdu_add_var(snmp_pdu_t *pdu, const oid *objid, size_t objid_len,
                     u_char type, const void *value, size_t value_len);
int snmp_pdu_add_null_var(snmp_pdu_t *pdu, const oid *objid, size_t objid_len);
struct variable_list *snmp_pdu_get_variables(const snmp_pdu_t *pdu);
int snmp_pdu_get_variable_count(const snmp_pdu_t *pdu);
void snmp_pdu_remove_variable(snmp_pdu_t *pdu, struct variable_list *var);

// Context management (SNMPv3)
int snmp_pdu_set_context(snmp_pdu_t *pdu, const u_char *contextEngineID,
                        size_t engineIDLen, const char *contextName);
int snmp_pdu_get_context(const snmp_pdu_t *pdu, u_char **contextEngineID,
                        size_t *engineIDLen, char **contextName);

// Encoding/decoding
int snmp_pdu_encode(const snmp_pdu_t *pdu, u_char *buffer, size_t *buf_len);
snmp_pdu_t *snmp_pdu_decode(const u_char *data, size_t data_len);
int snmp_pdu_decode_scoped(const u_char *data, size_t data_len, snmp_pdu_t *pdu);
int snmp_pdu_encode_scoped(const snmp_pdu_t *pdu, u_char *buffer, size_t *buf_len);

// Utility functions
uint32_t snmp_generate_reqid(void);
const char *snmp_pdu_type_to_string(int pdu_type);
const char *snmp_error_to_string(int error_code);
int snmp_pdu_validate(const snmp_pdu_t *pdu);

// Bulk operations (GetBulk)
void snmp_pdu_set_bulk_parameters(snmp_pdu_t *pdu, int non_repeaters, int max_repetitions);
int snmp_pdu_get_bulk_parameters(const snmp_pdu_t *pdu, int *non_repeaters, int *max_repetitions);

// Debug functions
void snmp_pdu_dump(const snmp_pdu_t *pdu);
void snmp_pdu_hex_dump(const u_char *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif // SNMP_PDU_H
