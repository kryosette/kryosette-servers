#include "constants.h"

/**
 * @file snmp_constants.c
 * @brief SNMP protocol constants implementation
 *
 * This file provides the concrete implementation of all SNMP-related constants
 * and their corresponding accessor functions. The implementation follows the
 * SNMP protocol specifications as defined in relevant RFCs.
 */

// ==================== Error Codes ====================
/**
 * @brief SNMP error status constants implementation
 *
 * These constants represent the standard SNMP error codes as specified in
 * RFC 3416. Each error code corresponds to a specific error condition that
 * can occur during SNMP protocol operations.
 *
 * @note Error codes range from 0 to 18 as per SNMP specification
 */
static const uint8_t SNMP_ERR_NOERROR = 0;              ///< No error occurred - operation successful
static const uint8_t SNMP_ERR_TOOBIG = 1;               ///< Response message exceeds maximum size limit
static const uint8_t SNMP_ERR_NOSUCHNAME = 2;           ///< Requested object identifier not found in MIB
static const uint8_t SNMP_ERR_BADVALUE = 3;             ///< Invalid value provided in SET operation
static const uint8_t SNMP_ERR_READONLY = 4;             ///< Attempt to write to a read-only object
static const uint8_t SNMP_ERR_GENERR = 5;               ///< General or unspecified error condition
static const uint8_t SNMP_ERR_NOACCESS = 6;             ///< Access denied due to security restrictions
static const uint8_t SNMP_ERR_WRONGTYPE = 7;            ///< Data type mismatch for the target object
static const uint8_t SNMP_ERR_WRONGLENGTH = 8;          ///< Value length invalid for the data type
static const uint8_t SNMP_ERR_WRONGENCODING = 9;        ///< Invalid ASN.1 encoding in the provided value
static const uint8_t SNMP_ERR_WRONGVALUE = 10;          ///< Value outside acceptable range or constraints
static const uint8_t SNMP_ERR_NOCREATION = 11;          ///< Object instance creation not permitted
static const uint8_t SNMP_ERR_INCONSISTENTVALUE = 12;   ///< Value inconsistent with system state
static const uint8_t SNMP_ERR_RESOURCEUNAVAILABLE = 13; ///< Required system resources not available
static const uint8_t SNMP_ERR_COMMITFAILED = 14;        ///< Configuration commit operation failed
static const uint8_t SNMP_ERR_UNDOFAILED = 15;          ///< Configuration rollback operation failed
static const uint8_t SNMP_ERR_AUTHORIZATION = 16;       ///< Operation not authorized for this context
static const uint8_t SNMP_ERR_NOTWRITABLE = 17;         ///< Object exists but cannot be modified
static const uint8_t SNMP_ERR_INCONSISTENTNAME = 18;    ///< Object name violates creation requirements

// ==================== PDU Types ====================
/**
 * @brief SNMP Protocol Data Unit type constants implementation
 *
 * These constants define the various message types used in SNMP protocol
 * communications. The values correspond to ASN.1 context-specific tags
 * for SNMP PDUs.
 *
 * @note PDU types use the range 0xA0-0xA8 as per SNMP protocol specification
 */
static const uint8_t SNMP_MSG_GET = 0xA0;      ///< Retrieve exact object values (SNMP GetRequest)
static const uint8_t SNMP_MSG_GETNEXT = 0xA1;  ///< Retrieve next sequential object (SNMP GetNextRequest)
static const uint8_t SNMP_MSG_RESPONSE = 0xA2; ///< Response to any request PDU (SNMP Response)
static const uint8_t SNMP_MSG_SET = 0xA3;      ///< Modify object values (SNMP SetRequest)
static const uint8_t SNMP_MSG_GETBULK = 0xA5;  ///< Efficient bulk data retrieval (SNMP GetBulkRequest)
static const uint8_t SNMP_MSG_INFORM = 0xA6;   ///< Acknowledged manager-to-manager notification
static const uint8_t SNMP_MSG_TRAP2 = 0xA7;    ///< Unacknowledged agent notification (SNMPv2-Trap)
static const uint8_t SNMP_MSG_REPORT = 0xA8;   ///< SNMPv3 error reporting mechanism

// ==================== ASN.1 Types ====================
/**
 * @brief Basic ASN.1 type constants implementation
 *
 * These constants represent the fundamental ASN.1 data types used in
 * SNMP protocol encoding. They correspond to BER (Basic Encoding Rules)
 * type identifiers for primitive data types.
 *
 * @note These are universal class tags as defined in ASN.1 standards
 */
static const uint8_t ASN_BOOLEAN = 0x01;   ///< Boolean type (TRUE/FALSE) - universal tag 1
static const uint8_t ASN_INTEGER = 0x02;   ///< Signed integer type - universal tag 2
static const uint8_t ASN_BIT_STR = 0x03;   ///< Bit string type - universal tag 3
static const uint8_t ASN_OCTET_STR = 0x04; ///< Octet string (binary data) - universal tag 4
static const uint8_t ASN_NULL = 0x05;      ///< Null placeholder - universal tag 5
static const uint8_t ASN_OBJECT_ID = 0x06; ///< Object Identifier - universal tag 6
static const uint8_t ASN_SEQUENCE = 0x30;  ///< Constructed sequence - universal tag 16 (0x30)

/**
 * @brief SNMP application-specific ASN.1 type constants
 *
 * These constants define application-specific data types used exclusively
 * in SNMP protocol. They are constructed by combining the application
 * class mask (0x40) with specific type identifiers.
 *
 * @note Application-specific types use class bit 0x40 as per ASN.1
 */
static const uint8_t ASN_APPLICATION_MASK = 0x40;                 ///< Bitmask to identify application class types
static const uint8_t ASN_IPADDRESS = 0x00 | ASN_APPLICATION_MASK; ///< IPv4 address (4-octet string)
static const uint8_t ASN_COUNTER = 0x01 | ASN_APPLICATION_MASK;   ///< 32-bit non-negative counter
static const uint8_t ASN_GAUGE = 0x02 | ASN_APPLICATION_MASK;     ///< 32-bit non-negative integer
static const uint8_t ASN_TIMETICKS = 0x03 | ASN_APPLICATION_MASK; ///< Time in hundredths of seconds
static const uint8_t ASN_OPAQUE = 0x04 | ASN_APPLICATION_MASK;    ///< Extended data type support
static const uint8_t ASN_COUNTER64 = 0x06 | ASN_APPLICATION_MASK; ///< 64-bit non-negative counter

// ==================== Error Codes Getters ====================
/**
 * @brief Error code accessor functions implementation
 *
 * These functions provide read-only access to the SNMP error code constants.
 * Using functions instead of direct constant access allows for potential
 * runtime configuration or validation while maintaining a consistent interface.
 */
uint8_t get_snmp_err_noerror(void) { return SNMP_ERR_NOERROR; }
uint8_t get_snmp_err_toobig(void) { return SNMP_ERR_TOOBIG; }
uint8_t get_snmp_err_nosuchname(void) { return SNMP_ERR_NOSUCHNAME; }
uint8_t get_snmp_err_badvalue(void) { return SNMP_ERR_BADVALUE; }
uint8_t get_snmp_err_readonly(void) { return SNMP_ERR_READONLY; }
uint8_t get_snmp_err_generr(void) { return SNMP_ERR_GENERR; }
uint8_t get_snmp_err_noaccess(void) { return SNMP_ERR_NOACCESS; }
uint8_t get_snmp_err_wrongtype(void) { return SNMP_ERR_WRONGTYPE; }
uint8_t get_snmp_err_wronglength(void) { return SNMP_ERR_WRONGLENGTH; }
uint8_t get_snmp_err_wrongencoding(void) { return SNMP_ERR_WRONGENCODING; }
uint8_t get_snmp_err_wrongvalue(void) { return SNMP_ERR_WRONGVALUE; }
uint8_t get_snmp_err_nocreation(void) { return SNMP_ERR_NOCREATION; }
uint8_t get_snmp_err_inconsistentvalue(void) { return SNMP_ERR_INCONSISTENTVALUE; }
uint8_t get_snmp_err_resourceunavailable(void) { return SNMP_ERR_RESOURCEUNAVAILABLE; }
uint8_t get_snmp_err_commitfailed(void) { return SNMP_ERR_COMMITFAILED; }
uint8_t get_snmp_err_undofailed(void) { return SNMP_ERR_UNDOFAILED; }
uint8_t get_snmp_err_authorization(void) { return SNMP_ERR_AUTHORIZATION; }
uint8_t get_snmp_err_notwritable(void) { return SNMP_ERR_NOTWRITABLE; }
uint8_t get_snmp_err_inconsistentname(void) { return SNMP_ERR_INCONSISTENTNAME; }

// ==================== PDU Types Getters ====================
/**
 * @brief PDU type accessor functions implementation
 *
 * These functions provide access to SNMP Protocol Data Unit type constants.
 * The function-based interface ensures consistent access patterns across
 * different constant categories in the library.
 */
uint8_t get_snmp_msg_get(void) { return SNMP_MSG_GET; }
uint8_t get_snmp_msg_getnext(void) { return SNMP_MSG_GETNEXT; }
uint8_t get_snmp_msg_response(void) { return SNMP_MSG_RESPONSE; }
uint8_t get_snmp_msg_set(void) { return SNMP_MSG_SET; }
uint8_t get_snmp_msg_getbulk(void) { return SNMP_MSG_GETBULK; }
uint8_t get_snmp_msg_inform(void) { return SNMP_MSG_INFORM; }
uint8_t get_snmp_msg_trap2(void) { return SNMP_MSG_TRAP2; }
uint8_t get_snmp_msg_report(void) { return SNMP_MSG_REPORT; }

// ==================== ASN.1 Types Getters ====================
/**
 * @brief Basic ASN.1 type accessor functions implementation
 *
 * These functions provide access to fundamental ASN.1 data type constants
 * used in SNMP message encoding and decoding operations.
 */
uint8_t get_asn_boolean(void) { return ASN_BOOLEAN; }
uint8_t get_asn_integer(void) { return ASN_INTEGER; }
uint8_t get_asn_bit_str(void) { return ASN_BIT_STR; }
uint8_t get_asn_octet_str(void) { return ASN_OCTET_STR; }
uint8_t get_asn_null(void) { return ASN_NULL; }
uint8_t get_asn_object_id(void) { return ASN_OBJECT_ID; }
uint8_t get_asn_sequence(void) { return ASN_SEQUENCE; }

// ==================== Application Types Getters ====================
/**
 * @brief Application-specific ASN.1 type accessor functions implementation
 *
 * These functions provide access to SNMP-specific application class types
 * that extend the basic ASN.1 type system for network management purposes.
 */
uint8_t get_asn_application_mask(void) { return ASN_APPLICATION_MASK; }
uint8_t get_asn_ipaddress(void) { return ASN_IPADDRESS; }
uint8_t get_asn_counter(void) { return ASN_COUNTER; }
uint8_t get_asn_gauge(void) { return ASN_GAUGE; }
uint8_t get_asn_timeticks(void) { return ASN_TIMETICKS; }
uint8_t get_asn_opaque(void) { return ASN_OPAQUE; }
uint8_t get_asn_counter64(void) { return ASN_COUNTER64; }