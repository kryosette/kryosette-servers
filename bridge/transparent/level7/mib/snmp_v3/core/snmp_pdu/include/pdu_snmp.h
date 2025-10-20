#pragma once
#ifndef SNMP_PDU_H
#define SNMP_PDU_H

#include <stdint.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // ==================== Error Codes ====================
    extern const uint8_t SNMP_ERR_NOERROR = 0;
    extern const uint8_t SNMP_ERR_TOOBIG = 1;
    extern const uint8_t SNMP_ERR_NOSUCHNAME = 2;
    extern const uint8_t SNMP_ERR_BADVALUE = 3;
    extern const uint8_t SNMP_ERR_READONLY = 4;
    extern const uint8_t SNMP_ERR_GENERR = 5;
    extern const uint8_t SNMP_ERR_NOACCESS = 6;
    extern const uint8_t SNMP_ERR_WRONGTYPE = 7;
    extern const uint8_t SNMP_ERR_WRONGLENGTH = 8;
    extern const uint8_t SNMP_ERR_WRONGENCODING = 9;
    extern const uint8_t SNMP_ERR_WRONGVALUE = 10;
    extern const uint8_t SNMP_ERR_NOCREATION = 11;
    extern const uint8_t SNMP_ERR_INCONSISTENTVALUE = 12;
    extern const uint8_t SNMP_ERR_RESOURCEUNAVAILABLE = 13;
    extern const uint8_t SNMP_ERR_COMMITFAILED = 14;
    extern const uint8_t SNMP_ERR_UNDOFAILED = 15;
    extern const uint8_t SNMP_ERR_AUTHORIZATION = 16;
    extern const uint8_t SNMP_ERR_NOTWRITABLE = 17;
    extern const uint8_t SNMP_ERR_INCONSISTENTNAME = 18;

    // ==================== PDU Types ====================
    extern const uint8_t SNMP_MSG_GET = 0xA0;
    extern const uint8_t SNMP_MSG_GETNEXT = 0xA1;
    extern const uint8_t SNMP_MSG_RESPONSE = 0xA2;
    extern const uint8_t SNMP_MSG_SET = 0xA3;
    extern const uint8_t SNMP_MSG_GETBULK = 0xA5;
    extern const uint8_t SNMP_MSG_INFORM = 0xA6;
    extern const uint8_t SNMP_MSG_TRAP2 = 0xA7;
    extern const uint8_t SNMP_MSG_REPORT = 0xA8;

    // ==================== ASN.1 Types ====================
    extern const uint8_t ASN_BOOLEAN = 0x01;
    extern const uint8_t ASN_INTEGER = 0x02;
    extern const uint8_t ASN_BIT_STR = 0x03;
    extern const uint8_t ASN_OCTET_STR = 0x04;
    extern const uint8_t ASN_NULL = 0x05;
    extern const uint8_t ASN_OBJECT_ID = 0x06;
    extern const uint8_t ASN_SEQUENCE = 0x30;

    // Application types
    extern const uint8_t ASN_APPLICATION_MASK = 0x40;
    extern const uint8_t ASN_IPADDRESS = 0x00 | ASN_APPLICATION_MASK;
    extern const uint8_t ASN_COUNTER = 0x01 | ASN_APPLICATION_MASK;
    extern const uint8_t ASN_GAUGE = 0x02 | ASN_APPLICATION_MASK;
    extern const uint8_t ASN_TIMETICKS = 0x03 | ASN_APPLICATION_MASK;
    extern const uint8_t ASN_OPAQUE = 0x04 | ASN_APPLICATION_MASK;
    extern const uint8_t ASN_COUNTER64 = 0x06 | ASN_APPLICATION_MASK;

    // ==================== Structures ====================
    typedef uint32_t oid;

    struct variable_list
    {
        oid *name;
        size_t name_length;
        u_char type;
        union
        {
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

    typedef struct snmp_pdu
    {
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

    typedef struct snmp_pdu
    {
        snmp_pdu_type_t command;
        uint32_t reqid;
        uint32_t errstat;
        uint32_t errindex;
        struct variable_list *variables;

        u_char *contextEngineID;
        size_t contextEngineIDLen;
        char *contextName;

    } snmp_pdu_t;

    snmp_pdu_t *snmp_pdu_create(snmp_pdu_type_t pdu_type);
    void snmp_pdu_free(snmp_pdu_t *pdu);
    int snmp_pdu_add_var(snmp_pdu_t *pdu, const oid *objid, size_t objid_len,
                         u_char type, const void *value, size_t value_len);

    int snmp_pdu_encode_basic(const snmp_pdu_t *pdu, u_char *buffer, size_t *buf_len);
    snmp_pdu_t *snmp_pdu_decode_basic(const u_char *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif // SNMP_PDU_H