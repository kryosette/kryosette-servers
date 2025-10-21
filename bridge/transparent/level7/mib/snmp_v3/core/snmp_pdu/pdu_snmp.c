#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "pdu_snmp.h"

snmp_pdu_t *snmp_pdu_create(snmp_pdu_type_t pdu_type) {
    snmp_pdu_t *pdu = calloc(sizeof(snmp_pdu_t));
    if (pdu == NULL || pdu == 0) {
        return NULL;
    }
    
    pdu->command = command;
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

