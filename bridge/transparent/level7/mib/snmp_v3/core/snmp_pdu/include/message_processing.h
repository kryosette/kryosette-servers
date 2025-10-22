#pragma once
#ifndef SNMP_MP_H
#define SNMP_MP_H

#include "pdu_snmp.h"

/**
 * @file snmp_mp.h
 * @brief SNMP Message Processing (MP) module interface
 *
 * This header defines the Message Processing interface for SNMP operations
 * as specified in RFC 3411. The module handles preparation and processing
 * of SNMP messages across different message processing models.
 */

/**
 * @brief Message Processing operation result codes
 *
 * These enumeration values represent the possible outcomes of message
 * processing operations, indicating success or specific failure conditions
 * that may occur during message parsing and validation.
 */
typedef enum
{
    MP_PROCESS_SUCCESS = 0,    ///< Message processed successfully without errors
    MP_PROCESS_ERROR_VERSION,  ///< Unsupported or invalid SNMP version
    MP_PROCESS_ERROR_SECURITY, ///< Security model processing failure
    MP_PROCESS_ERROR_DECODING  ///< ASN.1 decoding or message format error
} mp_process_result_t;

/**
 * @brief Prepare data elements from incoming SNMP message
 *
 * This function implements the abstract service primitive for processing
 * incoming SNMP messages as defined in RFC 3411. It extracts and validates
 * all components of an SNMP message and prepares them for further processing
 * by the SNMP engine.
 *
 * @param transportDomain The transport domain (e.g., "udp", "tcp")
 * @param transportAddress The transport-level address of the message source
 * @param wholeMsg The complete received SNMP message bytes
 * @param wholeMsgLength Length of the complete message in bytes
 * @param messageProcessingModel Output: Message processing model identified
 * @param securityModel Output: Security model used in the message
 * @param securityName Output: Security principal identifier
 * @param securityLevel Output: Security level requested/used
 * @param contextEngineID Output: Context engine ID for scoping
 * @param contextEngineIDLen Output: Length of context engine ID
 * @param contextName Output: Context name for scoping
 * @param pduVersion Output: PDU version indicator
 * @param PDU Output: Parsed Protocol Data Unit structure
 * @param pduType Output: Type of PDU extracted from message
 * @param sendPduHandle Output: Handle for correlating responses
 * @param maxSizeResponseScopedPDU Output: Maximum response size allowed
 * @param statusInformation Output: Additional status or error information
 * @param stateReference Output: Reference to internal processing state
 *
 * @return mp_process_result_t Processing result code indicating success or specific error
 *
 * @note This function corresponds to the prepareDataElements abstract service
 *       interface defined in RFC 3411 section 4.2.1
 */
mp_process_result_t prepareDataElements(
    const char *transportDomain,
    const char *transportAddress,
    const u_char *wholeMsg,
    size_t wholeMsgLength,
    snmp_mp_model_t *messageProcessingModel,
    snmp_security_model_t *securityModel,
    char **securityName,
    snmp_security_level_t *securityLevel,
    u_char **contextEngineID,
    size_t *contextEngineIDLen,
    char **contextName,
    int *pduVersion,
    snmp_pdu_t **PDU,
    snmp_pdu_type_t *pduType,
    void **sendPduHandle,
    size_t *maxSizeResponseScopedPDU,
    char **statusInformation,
    void **stateReference);

/**
 * @brief Prepare response message for transmission
 *
 * This function constructs an SNMP response message from the provided
 * PDU and security parameters. It handles the complete message assembly
 * including security wrapping and proper encoding according to the
 * specified message processing model.
 *
 * @param messageProcessingModel Message processing model to use
 * @param securityModel Security model to apply
 * @param securityName Security principal for response
 * @param securityLevel Security level for response
 * @param contextEngineID Context engine ID for scoping
 * @param contextEngineIDLen Length of context engine ID
 * @param contextName Context name for scoping
 * @param pduVersion PDU version indicator
 * @param PDU Protocol Data Unit to send in response
 * @param maxSizeResponseScopedPDU Maximum size constraint for response
 * @param stateReference State reference from original request
 * @param wholeMsg Output: Complete prepared response message
 * @param wholeMsgLength Output: Length of prepared response message
 *
 * @return mp_process_result_t Processing result code indicating success or specific error
 *
 * @note This function corresponds to the prepareResponseMessage abstract service
 *       interface defined in RFC 3411 for outgoing message preparation
 */
mp_process_result_t prepareResponseMessage(
    snmp_mp_model_t messageProcessingModel,
    snmp_security_model_t securityModel,
    char *securityName,
    snmp_security_level_t securityLevel,
    u_char *contextEngineID,
    size_t contextEngineIDLen,
    char *contextName,
    int pduVersion,
    snmp_pdu_t *PDU,
    size_t maxSizeResponseScopedPDU,
    void *stateReference,
    u_char **wholeMsg,
    size_t *wholeMsgLength);

#endif