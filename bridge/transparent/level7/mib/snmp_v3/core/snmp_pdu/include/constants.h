#pragma once
#ifndef SNMP_CONSTANTS_H
#define SNMP_CONSTANTS_H

#include <stdint.h>

/**
 * @file snmp_constants.h
 * @brief Comprehensive SNMP protocol constants definition header
 *
 * This header provides a complete set of constants for SNMP (Simple Network Management Protocol)
 * operations, including error codes, PDU types, and ASN.1 data types. The implementation uses
 * function-based accessors to ensure type safety and potential runtime flexibility.
 */

#ifdef __cplusplus
extern "C"
{
#endif

    // ==================== Error Codes ====================
    /**
     * @brief SNMP error status constants group
     *
     * These functions return standard SNMP error codes as defined in RFC 3416.
     * Each error code represents a specific condition encountered during SNMP operations.
     */

    uint8_t get_snmp_err_noerror(void);             ///< Operation completed successfully
    uint8_t get_snmp_err_toobig(void);              ///< Response message would be too large to transmit
    uint8_t get_snmp_err_nosuchname(void);          ///< Requested object name does not exist
    uint8_t get_snmp_err_badvalue(void);            ///< Invalid value in SET operation
    uint8_t get_snmp_err_readonly(void);            ///< Attempt to modify read-only object
    uint8_t get_snmp_err_generr(void);              ///< General failure during operation
    uint8_t get_snmp_err_noaccess(void);            ///< Access denied to requested object
    uint8_t get_snmp_err_wrongtype(void);           ///< Data type mismatch in SET operation
    uint8_t get_snmp_err_wronglength(void);         ///< Invalid length for the data type
    uint8_t get_snmp_err_wrongencoding(void);       ///< Invalid ASN.1 encoding in the value
    uint8_t get_snmp_err_wrongvalue(void);          ///< Value out of range or otherwise invalid
    uint8_t get_snmp_err_nocreation(void);          ///< Object creation not allowed
    uint8_t get_snmp_err_inconsistentvalue(void);   ///< Value inconsistent with other managed objects
    uint8_t get_snmp_err_resourceunavailable(void); ///< Required resources temporarily unavailable
    uint8_t get_snmp_err_commitfailed(void);        ///< Configuration commit operation failed
    uint8_t get_snmp_err_undofailed(void);          ///< Configuration undo operation failed
    uint8_t get_snmp_err_authorization(void);       ///< Authorization error for the operation
    uint8_t get_snmp_err_notwritable(void);         ///< Object exists but is not writable
    uint8_t get_snmp_err_inconsistentname(void);    ///< Object name inconsistent with creation requirements

    // ==================== PDU Types ====================
    /**
     * @brief SNMP Protocol Data Unit (PDU) type constants
     *
     * These functions return the message types used in SNMP protocol exchanges.
     * Each PDU type serves a specific purpose in the SNMP communication model.
     */

    uint8_t get_snmp_msg_get(void);      ///< Retrieve the value of specified objects (SNMP Get)
    uint8_t get_snmp_msg_getnext(void);  ///< Retrieve next object in MIB tree (SNMP GetNext)
    uint8_t get_snmp_msg_response(void); ///< Response to Get, GetNext, Set, or GetBulk requests
    uint8_t get_snmp_msg_set(void);      ///< Modify the value of specified objects (SNMP Set)
    uint8_t get_snmp_msg_getbulk(void);  ///< Efficiently retrieve large amounts of data (SNMP GetBulk)
    uint8_t get_snmp_msg_inform(void);   ///< Acknowledged notification between managers
    uint8_t get_snmp_msg_trap2(void);    ///< Unacknowledged notification (SNMPv2 Trap)
    uint8_t get_snmp_msg_report(void);   ///< Error reporting in SNMPv3

    // ==================== ASN.1 Types ====================
    /**
     * @brief ASN.1 (Abstract Syntax Notation One) type constants
     *
     * These functions return BER (Basic Encoding Rules) type identifiers used
     * to encode SNMP data according to ASN.1 standards.
     */

    uint8_t get_asn_boolean(void);   ///< Boolean truth value (TRUE/FALSE)
    uint8_t get_asn_integer(void);   ///< Signed integer value
    uint8_t get_asn_bit_str(void);   ///< Bit string (sequence of bits)
    uint8_t get_asn_octet_str(void); ///< Octet string (binary data)
    uint8_t get_asn_null(void);      ///< Null placeholder value
    uint8_t get_asn_object_id(void); ///< Object Identifier (OID) for MIB objects
    uint8_t get_asn_sequence(void);  ///< Ordered collection of ASN.1 types

    /**
     * @brief Application-specific ASN.1 types
     *
     * These types are specific to SNMP application context and extend the
     * basic ASN.1 type system for network management purposes.
     */

    uint8_t get_asn_application_mask(void); ///< Bitmask to identify application-specific types
    uint8_t get_asn_ipaddress(void);        ///< IPv4 address (32-bit)
    uint8_t get_asn_counter(void);          ///< Non-negative integer that increments (wraps)
    uint8_t get_asn_gauge(void);            ///< Non-negative integer that can increase/decrease
    uint8_t get_asn_timeticks(void);        ///< Time in hundredths of seconds since epoch
    uint8_t get_asn_opaque(void);           ///< Arbitrary data encoded as octet string
    uint8_t get_asn_counter64(void);        ///< 64-bit counter for high-capacity interfaces

#ifdef __cplusplus
}
#endif

#endif // SNMP_CONSTANTS_H