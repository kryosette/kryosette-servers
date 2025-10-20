#pragma once
#ifndef SNMP_MP_H
#define SNMP_MP_H

#include "pdu_snmp.h"

typedef enum
{
    MP_PROCESS_SUCCESS = 0,
    MP_PROCESS_ERROR_VERSION,
    MP_PROCESS_ERROR_SECURITY,
    MP_PROCESS_ERROR_DECODING
} mp_process_result_t;

// Abstract service primitive from RFC 3411
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

// For send message
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