#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "pdu_snmp.h"

snmp_pdu_t *snmp_pdu_create(snmp_pdu_type_t pdu_type) {
    snmp_pdu_t *pdu = calloc(1, sizeof(snmp_pdu_t));
    if (pdu == NULL) {
        return NULL;
    }
    
    pdu->command = pdu_type;
    pdu->reqid = 0;
    pdu->errstat = 0;
    pdu->errindex = 0;
    pdu->variables = NULL;
    
    pdu->contextEngineID = NULL;
    pdu->contextEngineIDLen = 0;
    pdu->contextName = NULL;
    
    pdu->msgID = 0;
    pdu->msgMaxSize = 0;
    pdu->msgFlags = 0;
    pdu->securityModel = 0;
    
    pdu->timestamp.tv_sec = 0;
    pdu->timestamp.tv_usec = 0;
    pdu->engineBoots = 0;
    pdu->engineTime = 0;
    
    pdu->transport_data = NULL;
    pdu->transport_data_len = 0;
    
    return pdu;
}

static void snmp_free_variable(struct variable_list *var) {
    if (!var) return;
    
    if (var->name) {
        free(var->name);
    }
    
    switch (var->type) {
        case ASN_OCTET_STR:
        case ASN_BIT_STR:
        case ASN_OPAQUE:
            if (var->val.string) {
                free(var->val.string);
            }
            break;
            
        case ASN_OBJECT_ID:
            if (var->val.objid) {
                free(var->val.objid);
            }
            break;
            
        case ASN_IPADDRESS:
            if (var->val.string && var->val_len == 4) {
                free(var->val.string);
            }
            break;
            
        case ASN_INTEGER:
        case ASN_COUNTER:
        case ASN_GAUGE:
        case ASN_TIMETICKS:
        case ASN_COUNTER64:
        case ASN_NULL:
        case ASN_BOOLEAN:
            break;
            
        default:
            if (var->val.string) {
                free(var->val.string);
            }
            break;
    }
    
    snmp_free_variable(var->next_variable);
    
    free(var);
}

void snmp_pdu_free(snmp_pdu_t *pdu) {
    if (!pdu) return;
    
    if (pdu->contextEngineID) {
        free(pdu->contextEngineID);
        pdu->contextEngineID = NULL;
        pdu->contextEngineIDLen = 0;
    }
    
    if (pdu->contextName) {
        free(pdu->contextName);
        pdu->contextName = NULL;
    }
    
    if (pdu->transport_data) {
        free(pdu->transport_data);
        pdu->transport_data = NULL;
        pdu->transport_data_len = 0;
    }
    
    if (pdu->variables) {
        snmp_free_variable(pdu->variables);
        pdu->variables = NULL;
    }
    
    free(pdu);
}

void snmp_pdu_reset(snmp_pdu_t *pdu) {
    if (!pdu) return;
    
    if (pdu->contextEngineID) {
        free(pdu->contextEngineID);
        pdu->contextEngineID = NULL;
        pdu->contextEngineIDLen = 0;
    }
    
    if (pdu->contextName) {
        free(pdu->contextName);
        pdu->contextName = NULL;
    }
    
    if (pdu->transport_data) {
        free(pdu->transport_data);
        pdu->transport_data = NULL;
        pdu->transport_data_len = 0;
    }
    
    if (pdu->variables) {
        snmp_free_variable(pdu->variables);
        pdu->variables = NULL;
    }
    
    pdu->command = 0;
    pdu->reqid = 0;
    pdu->errstat = 0;
    pdu->errindex = 0;
    pdu->msgID = 0;
    pdu->msgMaxSize = 0;
    pdu->msgFlags = 0;
    pdu->securityModel = 0;
    pdu->timestamp.tv_sec = 0;
    pdu->timestamp.tv_usec = 0;
    pdu->engineBoots = 0;
    pdu->engineTime = 0;
}



